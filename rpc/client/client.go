package clientrpc

import (
	"errors"
	"github.com/qwid-org/qwid-node/logger"
	"github.com/qwid-org/qwid-node/tcpip"
	"net/rpc"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const (
	initialBackoff = 1 * time.Second  // NP-M6
	maxBackoff     = 30 * time.Second // NP-M6
)

// nextBackoff doubles cur, capped at maxBackoff. Pure/deterministic. NP-M6.
func nextBackoff(cur time.Duration) time.Duration {
	next := cur * 2
	if next > maxBackoff {
		return maxBackoff
	}
	return next
}

var InRPC = make(chan []byte)
var OutRPC = make(chan []byte)
var muRPC = sync.Mutex{}

// reqMu serializes a full request/response pair for callers that use Call().
// WH-C6: request/response are already paired correctly by the single ConnectRPC
// goroutine over unbuffered channels (a second InRPC send cannot complete until
// the previous reply has been consumed), so there is no cross-caller response
// mixup. Call() makes that atomicity explicit and is the preferred API; the
// remaining limitation is that all RPC is serialized over one connection (a slow
// call delays others) — removing that needs connection pooling / correlation IDs.
var reqMu = sync.Mutex{}

// Concurrent calls (S7-02). net/rpc correlates replies by sequence number and
// the node's server runs each call in its own goroutine, so Call shares one
// connection without serializing: a slow request no longer stalls every other
// user of the website, and none waits longer than callTimeout. The channel
// pair (InRPC/OutRPC) stays for the GUI and tools that drive it directly.
var (
	directMu    sync.RWMutex
	direct      *rpc.Client
	directAddr  string
	redialing   atomic.Bool
	callTimeout = 30 * time.Second
)

func connectDirect(addr string) error {
	c, err := rpc.Dial("tcp", addr)
	if err != nil {
		return err
	}
	directMu.Lock()
	old := direct
	direct, directAddr = c, addr
	directMu.Unlock()
	if old != nil {
		old.Close()
	}
	return nil
}

func disconnectDirect() {
	directMu.Lock()
	old := direct
	direct = nil
	directMu.Unlock()
	if old != nil {
		old.Close()
	}
}

// redialDirect replaces a broken connection in the background, once at a time.
func redialDirect() {
	if !redialing.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer redialing.Store(false)
		directMu.RLock()
		addr := directAddr
		directMu.RUnlock()
		backoff := initialBackoff
		for connectDirect(addr) != nil {
			time.Sleep(backoff)
			backoff = nextBackoff(backoff)
		}
	}()
}

// Call performs one request/response, bounded by callTimeout. Without a
// direct connection it falls back to the serialized channel pair.
func Call(msg []byte) []byte {
	directMu.RLock()
	c := direct
	directMu.RUnlock()
	if c == nil {
		reqMu.Lock()
		defer reqMu.Unlock()
		InRPC <- msg
		return <-OutRPC
	}
	var reply []byte
	call := c.Go("Listener.Send", msg, &reply, make(chan *rpc.Call, 1))
	timer := time.NewTimer(callTimeout)
	defer timer.Stop()
	select {
	case done := <-call.Done:
		if done.Error != nil {
			logger.GetLogger().Printf("RPC call failed: %v", done.Error)
			if done.Error == rpc.ErrShutdown {
				redialDirect()
			}
			return []byte("Timeout")
		}
		return reply
	case <-timer.C:
		logger.GetLogger().Printf("RPC call timed out after %v", callTimeout)
		return []byte("Timeout")
	}
}

func ConnectRPC(ip string) {
	address := ip + ":" + strconv.Itoa(tcpip.Ports[tcpip.RPCTopic])
	var client *rpc.Client
	var err error
	backoff := initialBackoff
	for {
		client, err = rpc.Dial("tcp", address)
		if err == nil {
			break
		}
		logger.GetLogger().Printf("Failed to connect to RPC server at %s: %v. Retrying in %v...", address, err, backoff)
		time.Sleep(backoff)
		backoff = nextBackoff(backoff) // NP-M6: exponential backoff
	}

	// The concurrent path used by Call gets its own connection.
	if err := connectDirect(address); err != nil {
		logger.GetLogger().Printf("concurrent RPC connection failed: %v; Call falls back to the shared channel", err)
	}

	// WH-C6: block on InRPC instead of polling with a 100ms sleep, which added
	// latency to every RPC and burned a wakeup 10x/second while idle.
	for {
		line := <-InRPC
		muRPC.Lock()
		var reply []byte // NP-M7: net/rpc gob sizes the reply slice itself; no fixed pre-alloc
		err = client.Call("Listener.Send", line, &reply)
		if err != nil {
			logger.GetLogger().Printf("RPC call failed: %v. Reconnecting...", err)
			OutRPC <- []byte("Timeout")
			reconnectBackoff := initialBackoff
			for {
				client, err = rpc.Dial("tcp", address)
				if err == nil {
					break
				}
				logger.GetLogger().Printf("Failed to reconnect to RPC server at %s: %v. Retrying in %v...", address, err, reconnectBackoff)
				time.Sleep(reconnectBackoff)
				reconnectBackoff = nextBackoff(reconnectBackoff) // NP-M6
			}
		} else {
			OutRPC <- reply
		}
		muRPC.Unlock()
	}
}

// TransactionAccepted turns the node's reply to TRAN into an error unless the
// node actually accepted the transaction (S7-05): callers used to ignore the
// reply and tell the user "success" for a rejected transaction.
func TransactionAccepted(reply []byte) error {
	if string(reply) == "transaction sent" {
		return nil
	}
	if len(reply) == 0 {
		return errors.New("node gave no answer")
	}
	return errors.New(string(reply))
}

// SubmitTransaction sends a signed TRAN request and reports whether the node
// accepted it.
func SubmitTransaction(signedMsg []byte) error {
	return TransactionAccepted(Call(signedMsg))
}

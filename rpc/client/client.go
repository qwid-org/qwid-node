package clientrpc

import (
	"github.com/qwid-org/qwid-node/logger"
	"github.com/qwid-org/qwid-node/tcpip"
	"net/rpc"
	"strconv"
	"sync"
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

// Call performs one request/response over the shared RPC connection atomically.
func Call(msg []byte) []byte {
	reqMu.Lock()
	defer reqMu.Unlock()
	InRPC <- msg
	return <-OutRPC
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

package clientrpc

import (
	"github.com/wonabru/qwid-node/logger"
	"github.com/wonabru/qwid-node/tcpip"
	"net/rpc"
	"strconv"
	"sync"
	"time"
)

const (
	retryInterval = 5 * time.Second
	bufferSize    = 1024 * 1024
)

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
	for {
		client, err = rpc.Dial("tcp", address)
		if err == nil {
			break
		}
		logger.GetLogger().Printf("Failed to connect to RPC server at %s: %v. Retrying in %v...", address, err, retryInterval)
		time.Sleep(retryInterval)
	}

	// WH-C6: block on InRPC instead of polling with a 100ms sleep, which added
	// latency to every RPC and burned a wakeup 10x/second while idle.
	for {
		line := <-InRPC
		muRPC.Lock()
		reply := make([]byte, bufferSize)
		err = client.Call("Listener.Send", line, &reply)
		if err != nil {
			logger.GetLogger().Printf("RPC call failed: %v. Reconnecting...", err)
			OutRPC <- []byte("Timeout")
			for {
				client, err = rpc.Dial("tcp", address)
				if err == nil {
					break
				}
				logger.GetLogger().Printf("Failed to reconnect to RPC server at %s: %v. Retrying in %v...", address, err, retryInterval)
				time.Sleep(retryInterval)
			}
		} else {
			OutRPC <- reply
		}
		muRPC.Unlock()
	}
}

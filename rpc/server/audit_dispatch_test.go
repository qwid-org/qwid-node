package serverrpc

import (
	"sync"
	"testing"

	"github.com/qwid-org/qwid-node/blocks"
	"github.com/qwid-org/qwid-node/common"
)

// Audit 2026-11-12 F-RPC-01: a panic in one RPC handler must not take the
// node down, and listing tokens must not race a token registration.
func TestHandlerPanicBecomesAnErrorReply(t *testing.T) {
	var reply []byte
	safeDispatch("TEST", &reply, func() { panic("boom") })
	if len(reply) == 0 {
		t.Fatal("a panicking handler left no reply")
	}
}

func TestTokenListingDoesNotRaceRegistration(t *testing.T) {
	blocks.InitStateDB()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			var a common.Address
			a.ByteValue[0], a.ByteValue[1] = byte(i), 0x77
			blocks.StateMutex.Lock()
			blocks.State.RegisterNewToken(a, "T", "T", 8)
			blocks.StateMutex.Unlock()
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			var reply []byte
			handleLTKN(nil, &reply)
		}
	}()
	wg.Wait()
}

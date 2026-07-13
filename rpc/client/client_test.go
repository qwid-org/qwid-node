package clientrpc

import (
	"sync"
	"testing"
)

// TestCallPairsResponsesUnderConcurrency proves Call() serializes a full
// request/response pair, so concurrent callers never receive each other's reply.
func TestCallPairsResponsesUnderConcurrency(t *testing.T) {
	stop := make(chan struct{})
	go func() { // stub ConnectRPC: echo each request back as its reply
		for {
			select {
			case m := <-InRPC:
				OutRPC <- m
			case <-stop:
				return
			}
		}
	}()
	defer close(stop)

	const N = 50
	var wg sync.WaitGroup
	mismatch := make([]bool, N)
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			reply := Call([]byte{byte(i)})
			if len(reply) != 1 || reply[0] != byte(i) {
				mismatch[i] = true
			}
		}(i)
	}
	wg.Wait()
	for i, m := range mismatch {
		if m {
			t.Fatalf("Call %d received a mismatched reply", i)
		}
	}
}

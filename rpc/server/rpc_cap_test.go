package serverrpc

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/qwid-org/qwid-node/common"
)

func TestRPCSlotAcquireReleaseBounded(t *testing.T) {
	atomic.StoreInt64(&rpcConnCount, 0)
	defer atomic.StoreInt64(&rpcConnCount, 0)

	for i := 0; i < common.MaxConcurrentRPCConnections; i++ {
		if !tryAcquireRPCSlot() {
			t.Fatalf("acquire %d/%d should succeed", i+1, common.MaxConcurrentRPCConnections)
		}
	}
	if tryAcquireRPCSlot() {
		t.Fatal("acquire beyond cap must fail")
	}
	// A rejected acquire must roll back — the counter stays exactly at the cap.
	if c := atomic.LoadInt64(&rpcConnCount); c != int64(common.MaxConcurrentRPCConnections) {
		t.Fatalf("rpcConnCount = %d, want %d (rejected acquire must roll back)", c, common.MaxConcurrentRPCConnections)
	}
	releaseRPCSlot()
	if !tryAcquireRPCSlot() {
		t.Fatal("acquire after release should succeed")
	}
}

// TestRPCSlotConcurrentNeverExceedsCap runs many racing acquire/release pairs and
// asserts the number of simultaneously-HELD (successful) slots never exceeds the
// cap, and the counter returns to 0 with no leak. Run under -race.
func TestRPCSlotConcurrentNeverExceedsCap(t *testing.T) {
	atomic.StoreInt64(&rpcConnCount, 0)
	defer atomic.StoreInt64(&rpcConnCount, 0)

	var live int64 // successfully-held slots
	var maxLive int64
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < 500; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if tryAcquireRPCSlot() {
				n := atomic.AddInt64(&live, 1)
				mu.Lock()
				if n > maxLive {
					maxLive = n
				}
				mu.Unlock()
				atomic.AddInt64(&live, -1)
				releaseRPCSlot()
			}
		}()
	}
	wg.Wait()
	if maxLive > int64(common.MaxConcurrentRPCConnections) {
		t.Fatalf("held %d slots simultaneously, cap is %d", maxLive, common.MaxConcurrentRPCConnections)
	}
	if c := atomic.LoadInt64(&rpcConnCount); c != 0 {
		t.Fatalf("rpcConnCount leaked: got %d, want 0", c)
	}
}

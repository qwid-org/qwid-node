package transactionServices

import (
	"testing"
	"time"
)

// A full pool persists for as long as the chain needs to drain it, so the
// message announcing it must not be emitted once per gossip message. At 500 TPS
// that turned a steady-state condition into hundreds of synchronous log writes
// per second inside the receive path, which is the same path sync and nonce
// traffic use — so the logging, not the pool, was what stopped block
// production.
func TestPoolFullLogIsThrottled(t *testing.T) {
	poolFullMutex.Lock()
	poolFullDrops, poolFullLastLog = 0, time.Time{}
	poolFullMutex.Unlock()

	// The first drop reports immediately: an operator must see the condition
	// start without waiting out the period.
	if n := notePoolFullDrop(); n != 1 {
		t.Fatalf("first drop reported %d, expected it to report immediately as 1", n)
	}

	// Everything inside the period is counted, not logged.
	const burst = 5000
	for i := 0; i < burst; i++ {
		if n := notePoolFullDrop(); n != 0 {
			t.Fatalf("drop %d logged inside the quiet period (reported %d)", i, n)
		}
	}

	// When the period elapses, the suppressed volume is reported rather than
	// discarded — "dropped 5000" and "dropped 3" are different situations.
	poolFullMutex.Lock()
	poolFullLastLog = time.Now().Add(-2 * poolFullLogPeriod)
	poolFullMutex.Unlock()

	if n := notePoolFullDrop(); n != burst+1 {
		t.Fatalf("after the period the report was %d, expected the %d suppressed drops plus this one", n, burst)
	}

	// The counter resets, so the next period reports its own volume only.
	poolFullMutex.Lock()
	poolFullLastLog = time.Now().Add(-2 * poolFullLogPeriod)
	poolFullMutex.Unlock()
	if n := notePoolFullDrop(); n != 1 {
		t.Fatalf("the suppressed count carried over: reported %d, expected 1", n)
	}
}

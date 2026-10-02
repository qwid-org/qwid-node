package syncServices

import (
	"testing"
	"time"
)

// S2-06: a ~60-byte gh orders up to 21 full blocks read and sent. Serving is
// budgeted per transport source.
func TestHeaderServingIsBudgetedPerSource(t *testing.T) {
	resetHeaderServeBudget()
	defer resetHeaderServeBudget()
	src, other := [4]byte{203, 0, 113, 10}, [4]byte{203, 0, 113, 11}
	now := time.Unix(1_700_000_000, 0)

	served := int64(0)
	for allowHeaderServe(src, 21, now) {
		served += 21
		if served > 10*headerServeBurst {
			t.Fatal("budget never ran out")
		}
	}
	if served > headerServeBurst {
		t.Fatalf("served %d blocks in a burst, budget %d", served, headerServeBurst)
	}
	if !allowHeaderServe(other, 21, now) {
		t.Fatal("another source must have its own budget")
	}
	if !allowHeaderServe(src, 21, now.Add(time.Second)) {
		t.Fatal("the budget must refill over time")
	}
}

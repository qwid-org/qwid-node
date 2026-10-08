package syncServices

import "testing"

// Audit 2026-10-07 F3-01: the routine header request must not use up the
// fork-resolution request's slot - that starved fork recovery forever.
func TestForkHeaderRequestHasItsOwnLimiter(t *testing.T) {
	addr := [4]byte{198, 51, 100, 77}
	if !allowHeaderRequest(addr) {
		t.Fatal("first routine request refused")
	}
	if !allowForkHeaderRequest(addr) {
		t.Fatal("the fork request was refused because a routine request was just sent")
	}
	if allowForkHeaderRequest(addr) {
		t.Fatal("fork requests are not rate-limited at all")
	}
}

// Audit 2026-10-07 F3-03: the answer to a fork request lies below our tip and
// must be recognised as such, or the "shorter other chain" check drops it and
// the fork point is never found. When a routine and a fork request both
// cover a batch, the fork one is consumed.
func TestTakeHeaderRequestReportsForkRequests(t *testing.T) {
	addr := [4]byte{198, 51, 100, 78}
	defer func() {
		pendingHeaderRequestsMutex.Lock()
		delete(pendingHeaderRequests, addr)
		pendingHeaderRequestsMutex.Unlock()
	}()

	recordHeaderRequest(addr, 50, 70)
	if ok, fork := takeHeaderRequest(addr, 50, 70); !ok || fork {
		t.Fatalf("routine answer: ok=%v fork=%v, want true false", ok, fork)
	}

	recordHeaderRequest(addr, 40, 70)
	recordForkHeaderRequest(addr, 40, 60)
	if ok, fork := takeHeaderRequest(addr, 40, 60); !ok || !fork {
		t.Fatalf("fork answer: ok=%v fork=%v, want true true", ok, fork)
	}
	// The routine request is still outstanding.
	if ok, fork := takeHeaderRequest(addr, 45, 70); !ok || fork {
		t.Fatalf("remaining routine request: ok=%v fork=%v, want true false", ok, fork)
	}
	if ok, _ := takeHeaderRequest(addr, 40, 60); ok {
		t.Fatal("a consumed request answered a second batch")
	}
}

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

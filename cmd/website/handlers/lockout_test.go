package handlers

import (
	"testing"
	"time"
)

// TestAccountLockout verifies WH-M11: an account locks after maxFailedLogins
// failures and unlocks after a successful login clears the counter.
func TestAccountLockout(t *testing.T) {
	rl := &rateLimiter{entries: make(map[string][]time.Time)}
	user := "alice"

	if rl.isLockedOut(user) {
		t.Fatal("account locked before any failures")
	}
	for i := 0; i < maxFailedLogins; i++ {
		rl.recordFailure(user)
	}
	if !rl.isLockedOut(user) {
		t.Fatalf("account not locked after %d failures", maxFailedLogins)
	}
	rl.clearFailures(user)
	if rl.isLockedOut(user) {
		t.Fatal("account still locked after clearFailures")
	}
}

package handlers

import (
	"testing"
	"time"
)

// TestQWID28_LoadWalletThrottle verifies the LoadWallet brute-force throttle:
// attempts within the window are capped, a successful load resets the counter,
// and attempts age out of the window (QWID-2026-28).
func TestQWID28_LoadWalletThrottle(t *testing.T) {
	loadWalletThrottleReset()
	t.Cleanup(loadWalletThrottleReset)

	base := time.Unix(1_700_000_000, 0)

	// The first loadWalletMaxAttempts are allowed; the next is refused.
	for i := 0; i < loadWalletMaxAttempts; i++ {
		if !loadWalletThrottleAllow(base) {
			t.Fatalf("attempt %d within the cap should be allowed", i)
		}
	}
	if loadWalletThrottleAllow(base) {
		t.Fatal("attempt beyond the cap must be refused")
	}

	// A successful load clears the counter, so the user can act again.
	loadWalletThrottleReset()
	if !loadWalletThrottleAllow(base) {
		t.Fatal("after a reset the next attempt should be allowed")
	}

	// Attempts older than the window age out: fill the cap, then jump past the
	// window and confirm attempts are allowed again.
	loadWalletThrottleReset()
	for i := 0; i < loadWalletMaxAttempts; i++ {
		loadWalletThrottleAllow(base)
	}
	if loadWalletThrottleAllow(base) {
		t.Fatal("cap should be reached at the same instant")
	}
	later := base.Add(loadWalletWindow + time.Second)
	if !loadWalletThrottleAllow(later) {
		t.Fatal("attempts older than the window must age out, allowing a new attempt")
	}
}

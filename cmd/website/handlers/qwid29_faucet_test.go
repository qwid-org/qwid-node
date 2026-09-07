package handlers

import (
	"os"
	"path/filepath"
	"testing"
)

// TestQWID29_FaucetLifetimeBudgetIsEnforced verifies the persisted lifetime
// budget caps total welcome payouts regardless of rate, that refunds return
// budget, and that the total survives a reload (a restart cannot reset it).
func TestQWID29_FaucetLifetimeBudgetIsEnforced(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("FAUCET_LIFETIME_BUDGET_QWD", "10000") // room for exactly two 5000 payouts

	saved := Faucet
	t.Cleanup(func() { Faucet = saved })

	if err := InitFaucetLedger(dir); err != nil {
		t.Fatalf("init: %v", err)
	}

	// Two payouts fit the 10000 budget; the third must be refused.
	if !Faucet.reserve(welcomeAmountQWD) {
		t.Fatal("first reserve should succeed")
	}
	if !Faucet.reserve(welcomeAmountQWD) {
		t.Fatal("second reserve should succeed")
	}
	if Faucet.reserve(welcomeAmountQWD) {
		t.Fatal("third reserve must be refused (budget exhausted)")
	}

	// A refund frees budget for exactly one more.
	Faucet.refund(welcomeAmountQWD)
	if !Faucet.reserve(welcomeAmountQWD) {
		t.Fatal("reserve after refund should succeed")
	}
	if Faucet.reserve(welcomeAmountQWD) {
		t.Fatal("budget should be exhausted again")
	}

	// The persisted total must survive a reload — a website restart cannot reset
	// the lifetime budget.
	if _, err := os.Stat(filepath.Join(dir, "faucet.json")); err != nil {
		t.Fatalf("faucet state not persisted: %v", err)
	}
	Faucet = nil
	if err := InitFaucetLedger(dir); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if Faucet.reserve(welcomeAmountQWD) {
		t.Fatal("after reload the budget must still be exhausted")
	}
}

// TestQWID29_ReserveRefusesWhenPersistFails confirms a reserve that cannot
// persist hands out nothing (no unmetered funds on a write failure).
func TestQWID29_ReserveRefusesWhenPersistFails(t *testing.T) {
	dir := t.TempDir()
	saved := Faucet
	t.Cleanup(func() { Faucet = saved })
	if err := InitFaucetLedger(dir); err != nil {
		t.Fatalf("init: %v", err)
	}
	// Make the state file path unwritable by replacing the directory entry with a
	// path whose parent does not exist.
	Faucet.filePath = filepath.Join(dir, "no-such-subdir", "faucet.json")
	if Faucet.reserve(welcomeAmountQWD) {
		t.Fatal("reserve must fail when the total cannot be persisted")
	}
}

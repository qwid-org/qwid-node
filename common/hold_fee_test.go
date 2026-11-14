package common

import "testing"

// Audit 2026-11-13 (F-POOL-01): the fee for holding a pending-pool slot is
// HeldTxFeePerWeek for MaxTransactionDelay blocks, pro rata, rounded up.
func TestHoldFee(t *testing.T) {
	if HoldFee(0) != 0 || HoldFee(-5) != 0 {
		t.Fatal("no hold, no fee")
	}
	if HoldFee(MaxTransactionDelay) != HeldTxFeePerWeek {
		t.Fatalf("a week costs %d, want %d", HoldFee(MaxTransactionDelay), HeldTxFeePerWeek)
	}
	if HoldFee(MaxTransactionDelay/10) != HeldTxFeePerWeek/10 {
		t.Fatalf("a tenth of a week costs %d", HoldFee(MaxTransactionDelay/10))
	}
	if HoldFee(1) < 1 || HoldFee(1) != (HeldTxFeePerWeek+MaxTransactionDelay-1)/MaxTransactionDelay {
		t.Fatalf("one block costs %d, want the rounded-up share", HoldFee(1))
	}
}

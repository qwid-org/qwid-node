package transactionsPool

import (
	"testing"

	"github.com/qwid-org/qwid-node/common"
)

// TestPendingSpendTracksAddAndRemove verifies the per-sender pending-spend
// accounting that admission uses: it grows by fee+amount on add and shrinks on
// remove (DDoS incident 2026-09-08).
func TestPendingSpendTracksAddAndRemove(t *testing.T) {
	pool := NewTransactionPool(common.MaxTransactionInPool, 0)
	sAddr := common.EmptyAddress()
	sender := sAddr.GetBytes()

	// specTx(m, 5): GasPrice 5 * GasUsage 1 = fee 5, Amount 1 => cost 6.
	const cost = int64(6)
	if got := pool.PendingSpend(sender); got != 0 {
		t.Fatalf("initial PendingSpend = %d, want 0", got)
	}
	tx1 := specTx(1, 5)
	tx2 := specTx(2, 5)
	pool.AddTransaction(tx1, tx1.Hash)
	pool.AddTransaction(tx2, tx2.Hash)
	if got := pool.PendingSpend(sender); got != 2*cost {
		t.Fatalf("after two adds PendingSpend = %d, want %d", got, 2*cost)
	}
	pool.RemoveTransactionByHash(tx1.Hash.GetBytes())
	if got := pool.PendingSpend(sender); got != cost {
		t.Fatalf("after one remove PendingSpend = %d, want %d", got, cost)
	}
	pool.RemoveTransactionByHash(tx2.Hash.GetBytes())
	if got := pool.PendingSpend(sender); got != 0 {
		t.Fatalf("after removing all PendingSpend = %d, want 0", got)
	}
}

// TestCumulativeAdmissionCapsUnderfundedSender reproduces the incident: a sender
// with a small balance floods many individually-affordable transactions. The
// cumulative gate (pending+cost <= balance) — the exact check the admission path
// applies — must admit only as many as the balance covers, not all of them.
func TestCumulativeAdmissionCapsUnderfundedSender(t *testing.T) {
	pool := NewTransactionPool(common.MaxTransactionInPool, 0)
	sAddr := common.EmptyAddress()
	sender := sAddr.GetBytes()

	const cost = int64(6)   // fee 5 + amount 1
	const balance = int64(11) // like the 11 QWD account in the incident

	admitted := 0
	for i := 0; i < 50; i++ {
		tx := specTx(byte(100+i), 5)
		if pool.PendingSpend(sender)+cost > balance {
			continue // admission would reject
		}
		if pool.AddTransaction(tx, tx.Hash) {
			admitted++
		}
	}
	// balance 11, cost 6: only the first fits (6<=11); the second would be 12>11.
	if admitted != 1 {
		t.Fatalf("admitted %d transactions from an 11-balance sender, want 1 (flood must be capped)", admitted)
	}
	if got := pool.PendingSpend(sender); got != cost {
		t.Fatalf("PendingSpend = %d, want %d", got, cost)
	}
}

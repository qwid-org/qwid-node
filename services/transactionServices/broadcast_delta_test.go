package transactionServices

import (
	"testing"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
)

// mkTx builds a Transaction whose GetHash() returns a hash tagged by b.
func mkTx(b byte) transactionsDefinition.Transaction {
	var h common.Hash
	h[0] = b
	return transactionsDefinition.Transaction{Hash: h}
}

func hashSet(bs ...byte) map[common.Hash]struct{} {
	s := make(map[common.Hash]struct{})
	for _, b := range bs {
		var h common.Hash
		h[0] = b
		s[h] = struct{}{}
	}
	return s
}

func TestSelectNewTransactions(t *testing.T) {
	txs := []transactionsDefinition.Transaction{mkTx(1), mkTx(2), mkTx(3)}

	// empty seen -> all are new
	got := selectNewTransactions(txs, hashSet())
	if len(got) != 3 {
		t.Fatalf("empty seen: got %d new, want 3", len(got))
	}
	// all seen -> none new
	got = selectNewTransactions(txs, hashSet(1, 2, 3))
	if len(got) != 0 {
		t.Fatalf("all seen: got %d new, want 0", len(got))
	}
	// partial -> only the complement, order preserved
	got = selectNewTransactions(txs, hashSet(2))
	tx1, tx3 := mkTx(1), mkTx(3)
	if len(got) != 2 || got[0].GetHash() != tx1.GetHash() || got[1].GetHash() != tx3.GetHash() {
		t.Fatalf("partial seen: got %v, want [tx1 tx3]", got)
	}
}

func TestPruneSeen(t *testing.T) {
	// seen has 1,2,3,4; current pool has only 2,3 -> prune 1 and 4.
	seen := hashSet(1, 2, 3, 4)
	pruneSeen(seen, []transactionsDefinition.Transaction{mkTx(2), mkTx(3)})
	if len(seen) != 2 {
		t.Fatalf("after prune: %d entries, want 2", len(seen))
	}
	tx1, tx2, tx3 := mkTx(1), mkTx(2), mkTx(3)
	if _, ok := seen[tx2.GetHash()]; !ok {
		t.Fatal("hash 2 should be kept")
	}
	if _, ok := seen[tx3.GetHash()]; !ok {
		t.Fatal("hash 3 should be kept")
	}
	if _, ok := seen[tx1.GetHash()]; ok {
		t.Fatal("hash 1 (mined/dropped) should be pruned")
	}

	// pruning against an empty pool clears everything.
	seen2 := hashSet(1, 2)
	pruneSeen(seen2, nil)
	if len(seen2) != 0 {
		t.Fatalf("prune vs empty pool: %d entries, want 0", len(seen2))
	}
}

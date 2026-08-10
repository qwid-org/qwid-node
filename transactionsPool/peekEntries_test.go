package transactionsPool

import (
	"testing"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
)

// PeekTransactions filters by the pool's priority, and what "priority" means
// differs per pool: gas price for the main pool, maturity height for escrow,
// and a key derived from the multi-signature hash for multisig. Read-only
// callers such as the PEND RPC need every entry regardless, plus the priority
// itself so escrow can be shown with the height it settles at. PeekEntries
// provides that without touching PeekTransactions, which consensus depends on.

// poolTestTx mirrors buildEscrowTx in escrowPersistence_test.go: height 100,
// so a transaction with delay d matures at 100+d.
func poolTestTx(t *testing.T, nonce int64, delay int64) transactionsDefinition.Transaction {
	t.Helper()
	sigBytes := make([]byte, common.SignatureLength(false)+1)
	sig, _ := common.GetSignatureFromBytes(sigBytes, common.EmptyAddress())
	tx := transactionsDefinition.Transaction{
		TxParam: transactionsDefinition.TxParam{
			ChainID:     common.GetChainID(),
			Sender:      common.EmptyAddress(),
			SendingTime: nonce,
			Nonce:       nonce,
		},
		TxData: transactionsDefinition.TxData{
			Recipient:               common.EmptyAddress(),
			Amount:                  1000,
			OptData:                 []byte{byte(nonce)},
			EscrowTransactionsDelay: delay,
		},
		Height:    100,
		GasPrice:  1,
		GasUsage:  1,
		Signature: sig,
	}
	if err := tx.CalcHashAndSet(); err != nil {
		t.Fatalf("CalcHashAndSet: %v", err)
	}
	return tx
}

func TestPeekEntriesReturnsEscrowMaturityHeight(t *testing.T) {
	pool := NewTransactionPool(10, 1)
	tx := poolTestTx(t, 1, 36)
	if !pool.AddTransaction(tx, tx.GetHash()) {
		t.Fatal("AddTransaction refused the transaction")
	}

	entries := pool.PeekEntries(10)

	if len(entries) != 1 {
		t.Fatalf("PeekEntries returned %d entries, want 1", len(entries))
	}
	// Height 100 + delay 36; this is what the UI must show as "settles at".
	if entries[0].Priority != 136 {
		t.Errorf("Priority = %d, want 136 (height + escrow delay)", entries[0].Priority)
	}
}

// The bug this is really about: handlePEND asked the multisig pool for
// entries with height math.MaxInt64, but that pool matches priority by
// equality against a hash-derived key, so the query could never match and
// pending multi-signature transactions were invisible in the wallet.
func TestPeekEntriesReturnsMultisigWhichPeekTransactionsCannot(t *testing.T) {
	pool := NewTransactionPool(10, 2)
	tx := poolTestTx(t, 2, 0)
	if !pool.AddTransaction(tx, tx.GetHash()) {
		t.Fatal("AddTransaction refused the transaction")
	}

	const maxInt64 = int64(^uint64(0) >> 1)
	if got := pool.PeekTransactions(10, maxInt64); len(got) != 0 {
		t.Fatalf("PeekTransactions unexpectedly matched %d multisig txs — "+
			"the premise of this test is wrong", len(got))
	}

	if entries := pool.PeekEntries(10); len(entries) != 1 {
		t.Fatalf("PeekEntries returned %d entries, want 1", len(entries))
	}
}

// Escrow settlement peeks with the current height and must keep ignoring
// transactions that have not matured. PeekEntries must not have changed that.
func TestPeekTransactionsStillGatesEscrowByMaturity(t *testing.T) {
	pool := NewTransactionPool(10, 1)
	tx := poolTestTx(t, 3, 36) // matures at 136
	if !pool.AddTransaction(tx, tx.GetHash()) {
		t.Fatal("AddTransaction refused the transaction")
	}

	if got := pool.PeekTransactions(10, 135); len(got) != 0 {
		t.Errorf("transaction settled one block early: got %d", len(got))
	}
	if got := pool.PeekTransactions(10, 136); len(got) != 1 {
		t.Errorf("matured transaction not returned at its maturity height: got %d", len(got))
	}
}

func TestPeekEntriesRespectsLimit(t *testing.T) {
	pool := NewTransactionPool(10, 1)
	for i := int64(1); i <= 4; i++ {
		tx := poolTestTx(t, i, i)
		if !pool.AddTransaction(tx, tx.GetHash()) {
			t.Fatalf("AddTransaction refused transaction %d", i)
		}
	}

	if entries := pool.PeekEntries(2); len(entries) != 2 {
		t.Errorf("PeekEntries(2) returned %d entries, want 2", len(entries))
	}
	if entries := pool.PeekEntries(100); len(entries) != 4 {
		t.Errorf("PeekEntries(100) returned %d entries, want all 4", len(entries))
	}
}

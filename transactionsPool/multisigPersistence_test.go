package transactionsPool

import (
	"testing"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
)

func allowSyntheticMultiSignSignatures(t *testing.T) {
	t.Helper()
	saved := verifyPersistedMultiSign
	verifyPersistedMultiSign = func(*transactionsDefinition.Transaction) bool { return true }
	t.Cleanup(func() { verifyPersistedMultiSign = saved })
}

func withFreshMultiSignPool(t *testing.T) {
	t.Helper()
	saved := PoolTxMultiSign
	PoolTxMultiSign = NewTransactionPool(common.MaxTransactionInPool, 2)
	t.Cleanup(func() { PoolTxMultiSign = saved })
}

// multiSignTestTx builds a pool-worthy tx; mainHash zero => a main multisig tx,
// otherwise a confirmation of mainHash.
func multiSignTestTx(t *testing.T, nonce int64, mainHash common.Hash) transactionsDefinition.Transaction {
	t.Helper()
	tx := poolTestTx(t, nonce, 0)
	tx.TxParam.MultiSignTx = mainHash
	if err := tx.CalcHashAndSet(); err != nil {
		t.Fatalf("CalcHashAndSet: %v", err)
	}
	return tx
}

// TestMultiSignPoolSurvivesRestart: the pool is consensus state built from
// applied blocks; without persistence a restart between the main tx's block
// and a confirmation block made the confirmation block unappliable forever.
func TestMultiSignPoolSurvivesRestart(t *testing.T) {
	cleanup := withInMemoryDB(t)
	defer cleanup()
	allowSyntheticMultiSignSignatures(t)
	withFreshMultiSignPool(t)

	main := multiSignTestTx(t, 1, common.EmptyHash())
	conf := multiSignTestTx(t, 2, main.GetHash())

	if !AddMultiSignTransaction(main) || !AddMultiSignTransaction(conf) {
		t.Fatal("AddMultiSignTransaction odrzucił transakcję")
	}

	// "Restart": fresh in-memory pool, reload from DB.
	withFreshMultiSignPool(t)
	if err := LoadMultiSignPoolFromDB(); err != nil {
		t.Fatalf("LoadMultiSignPoolFromDB: %v", err)
	}

	if !PoolTxMultiSign.HasTransaction(main.GetHash().GetBytes()) {
		t.Fatal("main tx nie przetrwał restartu")
	}
	if !PoolTxMultiSign.HasTransaction(conf.GetHash().GetBytes()) {
		t.Fatal("potwierdzenie nie przetrwało restartu")
	}
	// The grouping key must be rebuilt too: PeekTransactions selects by the
	// main hash's int64 prefix, which is how ProcessTransactionsMultiSign
	// finds the group.
	group := PoolTxMultiSign.PeekTransactions(common.MaxTransactionInPool,
		common.GetInt64FromByte(main.GetHash().GetBytes()))
	if len(group) != 2 {
		t.Fatalf("grupa multisig po restarcie ma %d wpisów, oczekiwano 2 (main + potwierdzenie)", len(group))
	}
}

// TestRemoveMultiSignTransactionDropsPersistedCopy: settlement and expiry must
// remove the DB mirror, or a restart would resurrect settled transfers.
func TestRemoveMultiSignTransactionDropsPersistedCopy(t *testing.T) {
	cleanup := withInMemoryDB(t)
	defer cleanup()
	allowSyntheticMultiSignSignatures(t)
	withFreshMultiSignPool(t)

	main := multiSignTestTx(t, 3, common.EmptyHash())
	if !AddMultiSignTransaction(main) {
		t.Fatal("AddMultiSignTransaction odrzucił transakcję")
	}
	RemoveMultiSignTransaction(main.GetHash().GetBytes())

	withFreshMultiSignPool(t)
	if err := LoadMultiSignPoolFromDB(); err != nil {
		t.Fatalf("LoadMultiSignPoolFromDB: %v", err)
	}
	if PoolTxMultiSign.HasTransaction(main.GetHash().GetBytes()) {
		t.Fatal("usunięta transakcja wróciła z bazy po restarcie")
	}
}

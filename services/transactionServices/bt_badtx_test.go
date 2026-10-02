package transactionServices

import (
	"testing"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
)

// S2-07: answering a bt with a once-rejected transaction must not promote it
// to the confirmed prefix, which elsewhere means "already in the chain" and
// would keep it out of every future block.
func TestBtServesBadTransactionWithoutConfirmingIt(t *testing.T) {
	withBxTestDB(t)
	tx := keylessTx(t, 0x41)
	if err := tx.StoreToDBPoolTx(common.BadTransactionDBPrefix[:]); err != nil {
		t.Fatal(err)
	}
	got, ok := loadForBt(tx.Hash.GetBytes(), func(transactionsDefinition.Transaction) bool { return true })
	if !ok || got.Hash != tx.Hash {
		t.Fatal("a valid bad-tx entry must still be served")
	}
	if transactionsDefinition.CheckFromDBPoolTx(common.TransactionDBPrefix[:], tx.Hash.GetBytes()) {
		t.Fatal("serving a bad transaction marked it confirmed")
	}
	if _, ok := loadForBt(tx.Hash.GetBytes(), func(transactionsDefinition.Transaction) bool { return false }); ok {
		t.Fatal("a bad transaction that fails verification must not be served")
	}
}

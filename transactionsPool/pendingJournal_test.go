package transactionsPool

import (
	"testing"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/database"
	"github.com/qwid-org/qwid-node/logger"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
)

func inEscrow(tx transactionsDefinition.Transaction) (pool, db bool) {
	pool = PoolTxEscrow.TransactionExists(tx.GetHash().GetBytes())
	// A raw read: LoadFromDBPoolTx refuses a held entry, whose Height differs
	// from the signed body.
	b, err := database.MainDB.Get(append(common.EscrowPoolDBPrefix[:], tx.GetHash().GetBytes()...))
	return pool, err == nil && len(b) > 0
}

// Audit 2026-10-07 F3-07: a rewind brings the escrow pool back to the target
// height - settlements above it come back, entries added above it go - and a
// re-applied block first undoes what a cut-short apply of it left behind.
func TestRewindRestoresTheEscrowPool(t *testing.T) {
	logger.InitLogger()
	defer withInMemoryDB(t)()
	a, b, c := buildEscrowTx(1), buildEscrowTx(2), buildEscrowTx(3)
	t.Cleanup(func() {
		for _, tx := range []transactionsDefinition.Transaction{a, b, c} {
			PoolTxEscrow.RemoveTransactionByHash(tx.GetHash().GetBytes())
		}
	})
	check := func(when string, tx transactionsDefinition.Transaction, want bool) {
		t.Helper()
		if p, d := inEscrow(tx); p != want || d != want {
			t.Fatalf("%s: tx %d in pool=%v db=%v, want %v", when, tx.TxParam.Nonce, p, d, want)
		}
	}

	BeginPendingPoolJournal(10) // block 10 holds a
	AddEscrowTransaction(a)
	EndPendingPoolJournal()
	BeginPendingPoolJournal(11) // block 11 settles a and holds b
	RemoveEscrowTransaction(a.GetHash().GetBytes())
	AddEscrowTransaction(b)
	EndPendingPoolJournal()
	check("after block 11", a, false)
	check("after block 11", b, true)

	BeginPendingPoolJournal(12) // block 12 holds c, then the node crashes
	AddEscrowTransaction(c)
	BeginPendingPoolJournal(12) // block 12 applied again
	check("re-applying block 12", c, false)
	EndPendingPoolJournal()

	UndoPendingPoolsAbove(10)
	check("rewound to 10", a, true)
	check("rewound to 10", b, false)
	UndoPendingPoolsAbove(9)
	check("rewound to 9", a, false)
	UndoPendingPoolsAbove(9) // nothing left to undo
	check("rewound to 9 twice", a, false)
}

// Audit 2026-10-07 F3-08: an escrow entry whose Height block application reset
// to its inclusion block survives a restart. It used to fail the loader's
// hash check and be deleted. Without its signed original it is kept but not
// loaded.
func TestHeldEscrowSurvivesRestart(t *testing.T) {
	logger.InitLogger()
	defer withInMemoryDB(t)()
	allowSyntheticEscrowSignatures(t)
	signed := buildEscrowTx(7)
	t.Cleanup(func() { PoolTxEscrow.RemoveTransactionByHash(signed.GetHash().GetBytes()) })
	if err := signed.StoreToDBPoolTx(common.TransactionDBPrefix[:]); err != nil {
		t.Fatal(err)
	}
	held := signed
	held.Height = 250 // what ProcessTransaction does on inclusion
	AddEscrowTransaction(held)
	PoolTxEscrow.RemoveTransactionByHash(held.GetHash().GetBytes()) // restart: memory is gone

	if err := LoadEscrowPoolFromDB(); err != nil {
		t.Fatal(err)
	}
	got, ok := PoolTxEscrow.GetTransactionByHash(held.GetHash().GetBytes())
	if !ok || got.Height != 250 {
		t.Fatalf("held escrow after restart: present=%v height=%d, want present at 250", ok, got.Height)
	}

	// Without the signed original: kept in the DB, not loaded.
	PoolTxEscrow.RemoveTransactionByHash(held.GetHash().GetBytes())
	if err := transactionsDefinition.RemoveTransactionFromDBbyHash(common.TransactionDBPrefix[:], signed.GetHash().GetBytes()); err != nil {
		t.Fatal(err)
	}
	if err := LoadEscrowPoolFromDB(); err != nil {
		t.Fatal(err)
	}
	if PoolTxEscrow.TransactionExists(held.GetHash().GetBytes()) {
		t.Fatal("an entry without its signed original was loaded")
	}
	if _, db := inEscrow(held); !db {
		t.Fatal("an entry without its signed original was deleted")
	}
}

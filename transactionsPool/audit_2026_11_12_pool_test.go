package transactionsPool

import (
	"testing"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
)

// Audit 2026-11-12 F-POOL-02: the escrow and multisig pools hold transfers
// that blocks have already put on the chain. Whether one of them is there must
// not depend on what this node banned or which scheme it runs after a restart.

func TestHeldPoolsIgnoreLocalBans(t *testing.T) {
	logger.InitLogger()
	for _, kind := range []uint8{1, 2} {
		p := NewTransactionPool(common.MaxTransactionInPool, kind)
		tx := buildEscrowTx(70 + kind)
		for i := 0; i <= common.MaxNumberOfTxBans+5; i++ {
			p.BanTransactionByHash(tx.GetHash().GetBytes())
		}
		if !p.AddTransaction(tx, tx.GetHash()) || !p.HasTransaction(tx.GetHash().GetBytes()) {
			t.Fatalf("pool type %d refused a transfer a block holds because this node had banned its hash", kind)
		}
	}
	// the main pool keeps its bans: that is admission, not chain state
	p := NewTransactionPool(common.MaxTransactionInPool, 0)
	tx := buildEscrowTx(79)
	for i := 0; i <= common.MaxNumberOfTxBans+5; i++ {
		p.BanTransactionByHash(tx.GetHash().GetBytes())
	}
	if p.AddTransaction(tx, tx.GetHash()) {
		t.Fatal("the main pool admitted a banned transaction")
	}
}

func TestPersistedHeldEntryOnTheChainLoadsWhateverTheScheme(t *testing.T) {
	logger.InitLogger()
	cleanup := withInMemoryDB(t)
	defer cleanup()
	PoolTxEscrow = NewTransactionPool(common.MaxTransactionInPool, 1)
	PoolTxMultiSign = NewTransactionPool(common.MaxTransactionInPool, 2)

	onChain := buildEscrowTx(81) // its all-zero signature verifies under no scheme
	if err := onChain.StoreToDBPoolTx(common.TransactionDBPrefix[:]); err != nil {
		t.Fatal(err)
	}
	notOnChain := buildEscrowTx(82)
	for _, tx := range []transactionsDefinition.Transaction{onChain, notOnChain} {
		if err := tx.StoreToDBPoolTx(common.EscrowPoolDBPrefix[:]); err != nil {
			t.Fatal(err)
		}
		if err := tx.StoreToDBPoolTx(common.MultiSignPoolDBPrefix[:]); err != nil {
			t.Fatal(err)
		}
	}
	if err := LoadEscrowPoolFromDB(); err != nil {
		t.Fatal(err)
	}
	if err := LoadMultiSignPoolFromDB(); err != nil {
		t.Fatal(err)
	}
	if !PoolTxEscrow.HasTransaction(onChain.GetHash().GetBytes()) || !PoolTxMultiSign.HasTransaction(onChain.GetHash().GetBytes()) {
		t.Fatal("a held transfer that is on the chain was not reloaded because its signature does not verify under the node's current scheme")
	}
	if PoolTxEscrow.HasTransaction(notOnChain.GetHash().GetBytes()) || PoolTxMultiSign.HasTransaction(notOnChain.GetHash().GetBytes()) {
		t.Fatal("an entry no block ever carried was loaded")
	}
	if !transactionsDefinition.CheckFromDBPoolTx(common.EscrowPoolDBPrefix[:], notOnChain.GetHash().GetBytes()) {
		t.Fatal("the unexplained entry was deleted instead of kept aside")
	}
}

// F-POOL-01: the pools report how much room is left, so the block check can
// refuse a transfer that would not fit instead of losing it at apply time.
func TestHeldPoolReportsFreeSlots(t *testing.T) {
	logger.InitLogger()
	p := NewTransactionPool(2, 1)
	if p.FreeSlots() != 2 {
		t.Fatalf("free = %d, want 2", p.FreeSlots())
	}
	a, b, c := buildEscrowTx(91), buildEscrowTx(92), buildEscrowTx(93)
	p.AddTransaction(a, a.GetHash())
	p.AddTransaction(b, b.GetHash())
	if p.FreeSlots() != 0 {
		t.Fatalf("free = %d, want 0", p.FreeSlots())
	}
	if p.AddTransaction(c, c.GetHash()) {
		t.Fatal("a full held pool accepted another entry")
	}
}

package blocks

// QWID-2026-37: escrow settlement must not be stranded by a failed block
// application. Settlement now runs at the END of ProcessBlockTransfers, after
// every failable step, so a per-transaction failure rolls the block back
// BEFORE any escrow is settled — leaving the matured escrow pending and
// re-appliable, instead of removed while the block itself failed.

import (
	"testing"

	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
	"github.com/qwid-org/qwid-node/transactionsPool"
)

func TestQWID37_FailedBlockDoesNotSettleEscrow(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	withBalanceTestDB(t)
	initTestAccounts()
	transactionsPool.PoolTxEscrow = transactionsPool.NewTransactionPool(common.MaxTransactionInPool, 1)

	sender, recipient := testAddress(37), testAddress(38)
	const start, amount, delay = int64(1_000_000_000), int64(100_000_000), int64(20)
	account.Accounts.AllAccounts[sender.ByteValue] = account.Account{
		Address: sender.ByteValue, Balance: start, TransactionDelay: delay,
	}
	// Include the escrow at height 100 so it matures at 120.
	esc := transferTx(t, sender, recipient, amount, common.EmptyHash(), 37)
	if err := ProcessTransaction(esc, 100, 1000); err != nil {
		t.Fatalf("including escrow: %v", err)
	}
	if !transactionsPool.PoolTxEscrow.HasTransaction(esc.Hash.GetBytes()) {
		t.Fatal("escrow was not pooled")
	}
	maturity := int64(100) + delay
	recipientBefore := balanceOf(t, recipient)

	// A block at maturity whose transaction list references a hash that is not
	// in the pool DB: the per-tx loop fails and ProcessBlockTransfers returns
	// before it can reach the escrow settlement at the end.
	var missing common.Hash
	missing[0] = 0xEE
	bl := buildMinimalBlock()
	bl.BaseBlock.BaseHeader.Height = maturity
	bl.TransactionsHashes = []common.Hash{missing}

	if err := ProcessBlockTransfers(bl, 0, nil); err == nil {
		t.Fatal("a block with an unresolvable transaction was applied successfully")
	}
	// The matured escrow must still be pending, and no money may have moved.
	if !transactionsPool.PoolTxEscrow.HasTransaction(esc.Hash.GetBytes()) {
		t.Fatal("a failed block settled and removed the matured escrow — it is now lost while the " +
			"block itself failed, a permanent balance divergence (QWID-2026-37)")
	}
	if got := balanceOf(t, recipient); got != recipientBefore {
		t.Fatalf("recipient balance moved (%d -> %d) during a failed block (QWID-2026-37)", recipientBefore, got)
	}
}

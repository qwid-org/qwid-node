package blocks

import (
	"testing"

	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
	"github.com/qwid-org/qwid-node/transactionsPool"
)

// ProcessTransactionsEscrow walks every pooled escrow transaction that the pool
// offers for this height and settles the ones whose delay has elapsed. On an
// immature one it used to `return`, abandoning the rest of the batch — the
// exact mistake the AC-M7 comment four lines above it fixed for the
// delegated-account branch, left in place here.
//
// The escrow pool is a max-heap (basePool.go: Less is `>`), so it hands out the
// HIGHEST priority first — and for escrow the priority is the height the entry
// was pooled at. The most recently pooled transaction therefore comes first,
// and that is precisely the one least likely to have matured. An immature entry
// in front of a mature one is the common case, not a corner case, and it made
// the mature transfer miss its settlement block. It settles in some later
// block, so nothing is lost, but a transfer can be held past the delay its
// owner was promised for as long as newer entries keep arriving.
func TestEscrowSettlesLaterEntriesAfterAnImmatureOne(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	withBalanceTestDB(t)
	initTestAccounts()
	transactionsPool.PoolTxEscrow = transactionsPool.NewTransactionPool(common.MaxTransactionInPool, 1)

	slowSender, slowRecipient := testAddress(20), testAddress(21)
	dueSender, dueRecipient := testAddress(22), testAddress(23)
	const start, amount = int64(1_000_000_000), int64(100_000_000)

	account.Accounts.AllAccounts[slowSender.ByteValue] = account.Account{
		Address: slowSender.ByteValue, Balance: start, TransactionDelay: 100,
	}
	account.Accounts.AllAccounts[dueSender.ByteValue] = account.Account{
		Address: dueSender.ByteValue, Balance: start, TransactionDelay: 20,
	}

	// Pooled first, at the lower height, and due at 100+20 = 120.
	dueTx := transferTx(t, dueSender, dueRecipient, amount, common.EmptyHash(), 22)
	if err := ProcessTransaction(dueTx, 100, 1000); err != nil {
		t.Fatalf("ProcessTransaction(due): %v", err)
	}
	// Pooled later, at the higher height, so the max-heap serves it FIRST, and
	// it is nowhere near due: 110 + 100 = 210.
	slowTx := transferTx(t, slowSender, slowRecipient, amount, common.EmptyHash(), 20)
	if err := ProcessTransaction(slowTx, 110, 1100); err != nil {
		t.Fatalf("ProcessTransaction(slow): %v", err)
	}

	_ = ProcessTransactionsEscrow(120, nil)

	if got := balanceOf(t, dueRecipient); got != amount {
		t.Errorf("a matured transfer did not settle: recipient = %d, want %d — "+
			"an earlier immature entry aborted the batch", got, amount)
	}
	if got := balanceOf(t, slowRecipient); got != 0 {
		t.Errorf("the immature transfer settled early: recipient = %d, want 0", got)
	}
}

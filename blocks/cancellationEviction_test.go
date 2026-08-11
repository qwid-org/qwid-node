package blocks

import (
	"testing"

	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
	"github.com/qwid-org/qwid-node/transactionsPool"
)

// A cancellation whose escrow target has matured can never become valid again:
// validateEscrowCancellation rejects it once height reaches the maturity point,
// and height only ever increases. CheckBlockTransfers then fails the whole
// block, the producer logs and returns, and the transaction stays in the pool —
// so the next block is assembled from the same set and fails identically. The
// chain stops producing blocks permanently. Observed on mainnet-candidate at
// block 139793: "invalid escrow cancellation: escrow transaction has already
// matured", repeating every block interval.

func cancellationFixture(t *testing.T, targetHeight, delay int64) (transactionsDefinition.Transaction, common.Address) {
	t.Helper()
	initTestAccounts()
	transactionsPool.PoolTxEscrow = transactionsPool.NewTransactionPool(common.MaxTransactionInPool, 1)
	transactionsPool.PoolsTx = transactionsPool.NewTransactionPool(common.MaxTransactionInPool, 0)

	var owner common.Address
	owner.ByteValue[0] = 1
	account.Accounts.AllAccounts[owner.ByteValue] = account.Account{
		Address:          owner.ByteValue,
		Balance:          1_000_000,
		TransactionDelay: delay,
	}

	var targetHash common.Hash
	targetBytes := make([]byte, common.HashLength)
	targetBytes[0] = 99
	targetHash.Set(targetBytes)
	target := transactionsDefinition.Transaction{
		TxParam: transactionsDefinition.TxParam{Sender: owner},
		Hash:    targetHash,
		Height:  targetHeight,
	}
	if !transactionsPool.PoolTxEscrow.AddTransaction(target, targetHash) {
		t.Fatal("failed to add escrow target")
	}

	var cancelHash common.Hash
	cancelBytes := make([]byte, common.HashLength)
	cancelBytes[0] = 77
	cancelHash.Set(cancelBytes)
	cancel := transactionsDefinition.Transaction{
		TxParam: transactionsDefinition.TxParam{Sender: owner},
		TxData: transactionsDefinition.TxData{
			Recipient: owner,
			OptData:   transactionsDefinition.CancellationOptData(targetHash),
		},
		Hash: cancelHash,
	}
	if !transactionsPool.PoolsTx.AddTransaction(cancel, cancelHash) {
		t.Fatal("failed to add cancellation to the main pool")
	}
	return cancel, owner
}

func TestFilterUnbuildableKeepsValidOne(t *testing.T) {
	cancel, _ := cancellationFixture(t, 100, 20) // matures at 120

	kept := FilterUnbuildableTransactions([]transactionsDefinition.Transaction{cancel}, 119)

	if len(kept) != 1 {
		t.Fatalf("a cancellation one block before maturity was dropped: got %d", len(kept))
	}
	if !transactionsPool.PoolsTx.HasTransaction(cancel.Hash.GetBytes()) {
		t.Error("a still-valid cancellation was evicted from the pool")
	}
}

func TestFilterUnbuildableEvictsMaturedOne(t *testing.T) {
	cancel, _ := cancellationFixture(t, 100, 20) // matures at 120

	kept := FilterUnbuildableTransactions([]transactionsDefinition.Transaction{cancel}, 120)

	if len(kept) != 0 {
		t.Fatalf("a matured cancellation was still offered to the block: got %d", len(kept))
	}
	// It can never pass again, so leaving it in the pool would re-poison every
	// subsequent block — that is exactly the stall this guards against.
	if transactionsPool.PoolsTx.HasTransaction(cancel.Hash.GetBytes()) {
		t.Error("a permanently invalid cancellation was left in the pool")
	}
}

// A cancellation whose target is not in the escrow pool yet is a different
// case: the target's block may simply not have been processed here yet, so the
// transaction must be held back from this block WITHOUT being destroyed.
func TestFilterUnbuildableKeepsUnknownTargetInPool(t *testing.T) {
	cancel, _ := cancellationFixture(t, 100, 20)
	transactionsPool.PoolTxEscrow = transactionsPool.NewTransactionPool(common.MaxTransactionInPool, 1)

	kept := FilterUnbuildableTransactions([]transactionsDefinition.Transaction{cancel}, 110)

	if len(kept) != 0 {
		t.Fatalf("an unverifiable cancellation was offered to the block: got %d", len(kept))
	}
	if !transactionsPool.PoolsTx.HasTransaction(cancel.Hash.GetBytes()) {
		t.Error("a cancellation whose target may still arrive was evicted")
	}
}

// Ordinary transactions must pass through untouched.
func TestFilterUnbuildableIgnoresNonCancellations(t *testing.T) {
	_, owner := cancellationFixture(t, 100, 20)

	plain := transactionsDefinition.Transaction{
		TxParam: transactionsDefinition.TxParam{Sender: owner},
		TxData:  transactionsDefinition.TxData{Recipient: owner, Amount: 5},
	}

	kept := FilterUnbuildableTransactions([]transactionsDefinition.Transaction{plain}, 500)

	if len(kept) != 1 {
		t.Fatalf("a plain transaction was dropped: got %d", len(kept))
	}
}

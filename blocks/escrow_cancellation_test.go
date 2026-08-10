package blocks

import (
	"testing"

	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
	"github.com/qwid-org/qwid-node/transactionsPool"
)

func TestValidateEscrowCancellation(t *testing.T) {
	initTestAccounts()
	transactionsPool.PoolTxEscrow = transactionsPool.NewTransactionPool(common.MaxTransactionInPool, 1)

	var owner common.Address
	owner.ByteValue[0] = 1
	account.Accounts.AllAccounts[owner.ByteValue] = account.Account{
		Address:          owner.ByteValue,
		Balance:          1_000_000,
		TransactionDelay: 20,
	}

	var targetHash common.Hash
	targetBytes := make([]byte, common.HashLength)
	targetBytes[0] = 99
	targetHash.Set(targetBytes)
	target := transactionsDefinition.Transaction{
		TxParam: transactionsDefinition.TxParam{Sender: owner},
		Hash:    targetHash,
		Height:  100,
	}
	if !transactionsPool.PoolTxEscrow.AddTransaction(target, targetHash) {
		t.Fatal("failed to add escrow target")
	}

	cancel := transactionsDefinition.Transaction{
		TxParam: transactionsDefinition.TxParam{Sender: owner},
		TxData: transactionsDefinition.TxData{
			Recipient: owner,
			OptData:   transactionsDefinition.CancellationOptData(targetHash),
		},
	}
	if _, err := validateEscrowCancellation(cancel, 119); err != nil {
		t.Fatalf("valid cancellation rejected: %v", err)
	}
	if _, err := validateEscrowCancellation(cancel, 120); err == nil {
		t.Fatal("cancellation at maturity height accepted")
	}

	var stranger common.Address
	stranger.ByteValue[0] = 2
	cancel.TxParam.Sender = stranger
	cancel.TxData.Recipient = stranger
	if _, err := validateEscrowCancellation(cancel, 119); err == nil {
		t.Fatal("non-owner cancellation accepted")
	}
}

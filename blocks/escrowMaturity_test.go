package blocks

import (
	"testing"

	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
)

// Two different delays exist and only one governs settlement.
//
//	tx.TxData.EscrowTransactionsDelay — carried only by a ModifyEscrow
//	  configuration transaction, which sets the account's delay. An ordinary
//	  transfer out of an escrow account has it at zero.
//	account.TransactionDelay — what ProcessTransactionsEscrow actually gates on
//	  (processTransaction.go), and what validateEscrowCancellation measures the
//	  cancellation window with.
//
// The escrow pool orders entries by tx.Height + tx.TxData.EscrowTransactionsDelay,
// which for a real transfer is just tx.Height. Reading that as "settles at" —
// as the PEND RPC briefly did — reports a height already in the past.

func TestEscrowMaturityHeightUsesAccountDelay(t *testing.T) {
	initTestAccounts()

	var owner common.Address
	owner.ByteValue[0] = 1
	account.Accounts.AllAccounts[owner.ByteValue] = account.Account{
		Address:          owner.ByteValue,
		Balance:          1_000_000,
		TransactionDelay: 20,
	}

	// An ordinary transfer out of the escrow account: no delay field on it.
	tx := transactionsDefinition.Transaction{
		TxParam: transactionsDefinition.TxParam{Sender: owner},
		TxData:  transactionsDefinition.TxData{Recipient: owner, Amount: 100},
		Height:  100,
	}

	got := EscrowMaturityHeight(tx)

	if got != 120 {
		t.Fatalf("EscrowMaturityHeight = %d, want 120 (height 100 + account delay 20)", got)
	}
	if got == tx.Height+tx.TxData.EscrowTransactionsDelay {
		t.Error("maturity was computed from the transaction's delay field, " +
			"which is zero on a transfer and would report a past height")
	}
}

func TestEscrowMaturityHeightZeroForUnknownAccount(t *testing.T) {
	initTestAccounts()

	var stranger common.Address
	stranger.ByteValue[0] = 9
	tx := transactionsDefinition.Transaction{
		TxParam: transactionsDefinition.TxParam{Sender: stranger},
		Height:  100,
	}

	// Nothing sensible to report rather than a misleading number; the RPC
	// omits the field when this is zero.
	if got := EscrowMaturityHeight(tx); got != 0 {
		t.Fatalf("EscrowMaturityHeight = %d, want 0 for an unknown account", got)
	}
}

func TestEscrowMaturityHeightZeroForNonEscrowAccount(t *testing.T) {
	initTestAccounts()

	var plain common.Address
	plain.ByteValue[0] = 2
	account.Accounts.AllAccounts[plain.ByteValue] = account.Account{
		Address:          plain.ByteValue,
		Balance:          500,
		TransactionDelay: 0,
	}
	tx := transactionsDefinition.Transaction{
		TxParam: transactionsDefinition.TxParam{Sender: plain},
		Height:  100,
	}

	if got := EscrowMaturityHeight(tx); got != 0 {
		t.Fatalf("EscrowMaturityHeight = %d, want 0 when the account has no delay", got)
	}
}

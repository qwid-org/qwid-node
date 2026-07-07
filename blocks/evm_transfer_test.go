package blocks

import (
	"math/big"
	"testing"

	"github.com/wonabru/qwid-node/account"
	"github.com/wonabru/qwid-node/common"
	"github.com/wonabru/qwid-node/logger"
	"github.com/wonabru/qwid-node/transactionsDefinition"
)

func initNativeAccountsBlocks() {
	account.AccountsRWMutex.Lock()
	account.Accounts.AllAccounts = make(map[[common.AddressLength]byte]account.Account)
	account.AccountsRWMutex.Unlock()
}

func TestEvmTransferMovesValueAndCanTransfer(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	initNativeAccountsBlocks()
	InitStateDB()

	var from, to common.Address
	from.ByteValue[0] = 0x50
	to.ByteValue[0] = 0x51
	account.SetBalance(from.ByteValue, 1000)

	if !evmCanTransfer(&State, from, big.NewInt(400)) {
		t.Fatal("CanTransfer should allow 400 from balance 1000")
	}
	if evmCanTransfer(&State, from, big.NewInt(1001)) {
		t.Fatal("CanTransfer should reject 1001 from balance 1000")
	}
	evmTransfer(&State, from, to, big.NewInt(400))
	if account.GetBalance(from.ByteValue) != 600 || account.GetBalance(to.ByteValue) != 400 {
		t.Fatalf("transfer wrong: from=%d to=%d", account.GetBalance(from.ByteValue), account.GetBalance(to.ByteValue))
	}
}

func TestIsContractCallTxPredicate(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	var recipient common.Address
	recipient.ByteValue[0] = 0x60
	recipient.ByteValue[19] = 0x01 // non-zero trailing byte => fails the delegated-account byte-pattern check

	mk := func(opt []byte) transactionsDefinition.Transaction {
		var tx transactionsDefinition.Transaction
		tx.TxData.OptData = opt
		tx.TxData.Recipient = recipient
		return tx
	}
	plain := account.Account{}                 // normal account
	multi := account.Account{MultiSignNumber: 2}

	// OptData present, normal account, non-delegated recipient => contract call.
	if !isContractCallTx(mk([]byte{0x01}), plain, 100) {
		t.Fatal("expected contract-call tx to be detected")
	}
	// No OptData => not a contract call.
	if isContractCallTx(mk(nil), plain, 100) {
		t.Fatal("empty OptData must not be a contract call")
	}
	// Multisign sender => EVM does not run => NOT a contract call (native moves value).
	if isContractCallTx(mk([]byte{0x01}), multi, 100) {
		t.Fatal("multisign-account tx must not be treated as EVM-owned")
	}
	// Escrow-delayed sender => EVM does not run => NOT a contract call.
	escrow := account.Account{TransactionDelay: 50}
	txEscrow := mk([]byte{0x01})
	txEscrow.Height = 100 // height+delay(150) > current(100) => delayed
	if isContractCallTx(txEscrow, escrow, 100) {
		t.Fatal("escrow-delayed tx must not be treated as EVM-owned")
	}
	// Delegated-account recipient => NOT a contract call (native settlement).
	delegatedRecipient := common.GetDelegatedAccountAddress(5)
	txDelegated := transactionsDefinition.Transaction{}
	txDelegated.TxData.OptData = []byte{0x01}
	txDelegated.TxData.Recipient = delegatedRecipient
	if isContractCallTx(txDelegated, plain, 100) {
		t.Fatal("delegated-account recipient must not be treated as contract call")
	}
}

func TestContractTxValueNotDoubleMoved(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	initNativeAccountsBlocks()
	InitStateDB()

	var sender, contract common.Address
	sender.ByteValue[0] = 0x70
	contract.ByteValue[0] = 0x71
	contract.ByteValue[19] = 0x01 // non-zero trailing byte => not a delegated-account address
	account.SetBalance(sender.ByteValue, 1000)

	// Simulate the EVM entry Transfer for a contract-call tx (msg.value=200).
	evmTransfer(&State, sender, contract, big.NewInt(200))
	// The native guard must classify this as a contract-call tx (predicate true),
	// so ProcessTransaction would skip the native amount move — no second move.
	var tx transactionsDefinition.Transaction
	tx.TxData.OptData = []byte{0x01}
	tx.TxData.Recipient = contract
	if !isContractCallTx(tx, account.Account{}, 100) {
		t.Fatal("contract tx not detected; native path would double-move value")
	}
	if account.GetBalance(sender.ByteValue) != 800 || account.GetBalance(contract.ByteValue) != 200 {
		t.Fatalf("value moved once only expected: sender=%d contract=%d",
			account.GetBalance(sender.ByteValue), account.GetBalance(contract.ByteValue))
	}
}

func TestValueTransferRevertedOnFailure(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	initNativeAccountsBlocks()
	InitStateDB()

	var from, to common.Address
	from.ByteValue[0] = 0x80
	to.ByteValue[0] = 0x81
	account.SetBalance(from.ByteValue, 1000)

	snap := State.Snapshot()
	evmTransfer(&State, from, to, big.NewInt(300)) // as the EVM does after Snapshot()
	// Simulate the call failing: EVM reverts to the snapshot.
	State.RevertToSnapshot(snap)

	if account.GetBalance(from.ByteValue) != 1000 || account.GetBalance(to.ByteValue) != 0 {
		t.Fatalf("value not restored on revert: from=%d to=%d",
			account.GetBalance(from.ByteValue), account.GetBalance(to.ByteValue))
	}
}

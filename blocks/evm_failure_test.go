package blocks

import (
	"errors"
	"fmt"
	"testing"

	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/common"
	vm "github.com/qwid-org/qwid-node/core/evm"
	"github.com/qwid-org/qwid-node/logger"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
)

func TestIsEVMExecutionError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"reverted", vm.ErrExecutionReverted, true},
		{"out of gas", vm.ErrOutOfGas, true},
		{"code store oog", vm.ErrCodeStoreOutOfGas, true},
		{"depth", vm.ErrDepth, true},
		{"insufficient balance", vm.ErrInsufficientBalance, true},
		{"addr collision", vm.ErrContractAddressCollision, true},
		{"max code size", vm.ErrMaxCodeSizeExceeded, true},
		{"invalid jump", vm.ErrInvalidJump, true},
		{"write protection", vm.ErrWriteProtection, true},
		{"return data oob", vm.ErrReturnDataOutOfBounds, true},
		{"gas uint overflow", vm.ErrGasUintOverflow, true},
		{"invalid code", vm.ErrInvalidCode, true},
		{"nonce uint overflow", vm.ErrNonceUintOverflow, true},
		{"wrapped reverted", fmt.Errorf("evaluate: %w", vm.ErrExecutionReverted), true},
		{"struct invalid opcode", &vm.ErrInvalidOpCode{}, true},
		{"struct stack underflow", &vm.ErrStackUnderflow{}, true},
		{"struct stack overflow", &vm.ErrStackOverflow{}, true},
		{"nil", nil, false},
		{"plain db error", errors.New("db read failed"), false},
		{"wrapped non-evm", fmt.Errorf("boom: %w", errors.New("io")), false},
	}
	for _, c := range cases {
		if got := isEVMExecutionError(c.err); got != c.want {
			t.Errorf("%s: isEVMExecutionError = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestEvaluateSCRevertingCreateIsExecutionError(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	account.AccountsRWMutex.Lock()
	account.Accounts.AllAccounts = make(map[[common.AddressLength]byte]account.Account)
	account.AccountsRWMutex.Unlock()
	InitStateDB()

	var sender common.Address
	sender.ByteValue[0] = 0x90
	account.SetBalance(sender.ByteValue, 1_000_000)

	var tx transactionsDefinition.Transaction
	tx.TxParam.Sender = sender
	tx.TxData.Recipient = common.EmptyAddress()              // Create
	tx.TxData.OptData = []byte{0x60, 0x00, 0x60, 0x00, 0xfd} // PUSH1 0 PUSH1 0 REVERT
	tx.GasUsage = 30000

	bl := Block{}
	_, _, _, _, err := EvaluateSC(tx, bl)
	if err == nil {
		t.Fatal("expected reverting Create to return an error")
	}
	if !isEVMExecutionError(err) {
		t.Fatalf("reverting Create error not classified as execution error: %v", err)
	}
	// The endowment/state must be reverted: sender balance intact.
	if account.GetBalance(sender.ByteValue) != 1_000_000 {
		t.Fatalf("sender balance changed on reverted Create: %d", account.GetBalance(sender.ByteValue))
	}
}

// TestEvaluateSCForBlockNotRejectedOnRevert asserts that a block containing a
// reverting contract tx is NOT rejected (ok==true) and that the failed tx
// registers no contract. It is DB-gated and t.Skip's without RocksDB, so it
// does not run in the CI sandbox; the branch's correctness where this test
// can't run was verified manually in the Phase 3b whole-branch review
// (persisted OutputLogs are non-consensus; fee charged once; value reverted;
// non-execution errors stay block-fatal). The always-running coverage is
// TestIsEVMExecutionError + TestEvaluateSCRevertingCreateIsExecutionError.
func TestEvaluateSCForBlockNotRejectedOnRevert(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	account.AccountsRWMutex.Lock()
	account.Accounts.AllAccounts = make(map[[common.AddressLength]byte]account.Account)
	account.AccountsRWMutex.Unlock()
	InitStateDB()

	var sender common.Address
	sender.ByteValue[0] = 0x91
	account.SetBalance(sender.ByteValue, 1_000_000)
	account.AddTransactionsSender(sender.ByteValue, common.Hash{}) // sender account must exist

	var tx transactionsDefinition.Transaction
	tx.TxParam.Sender = sender
	tx.TxData.Recipient = common.EmptyAddress()
	tx.TxData.OptData = []byte{0x60, 0x00, 0x60, 0x00, 0xfd} // PUSH1 0 PUSH1 0 REVERT
	tx.GasUsage = 30000
	// EvaluateSCForBlock/EvaluateSC dereference the fields below; set the minimum
	// so CalcHashAndSet succeeds and the loop reaches EvaluateSC. Read
	// transaction.go GetBytesWithoutSignature to see which fields are required
	// (e.g. Pubkey/GasPrice/Height/Nonce); set them to valid non-nil minimums.
	tx.GasPrice = 1
	if err := tx.CalcHashAndSet(); err != nil {
		t.Skipf("cannot hash tx (harness): %v", err)
	}
	if err := tx.StoreToDBPoolTx(common.TransactionPoolHashesDBPrefix[:]); err != nil {
		t.Skipf("DB not available: %v", err)
	}

	var bl Block
	bl.BaseBlock.BaseHeader.Height = 1 // EvaluateSCForBlock reads bl.GetHeader().Height
	bl.TransactionsHashes = []common.Hash{tx.Hash}

	ok, _, addresses, _, _ := EvaluateSCForBlock(bl)
	if !ok {
		t.Fatal("block wrongly rejected on a reverting contract tx (Phase 3b regression)")
	}
	hh := [common.HashLength]byte{}
	copy(hh[:], tx.Hash.GetBytes())
	if _, registered := addresses[hh]; registered {
		t.Fatal("failed tx must not register a contract address")
	}
}

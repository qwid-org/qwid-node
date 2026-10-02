package blocks

import (
	"bytes"
	"encoding/hex"
	"sync"
	"testing"
	"time"

	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/common"
	vm "github.com/qwid-org/qwid-node/core/evm"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
)

func evmTestSender(t *testing.T) common.Address {
	t.Helper()
	withBalanceTestDB(t)
	InitStateDB()
	sender := testAddress(0x81)
	account.Accounts = account.AccountsType{AllAccounts: map[[common.AddressLength]byte]account.Account{
		sender.ByteValue: {Address: sender.ByteValue, Balance: 1_000_000_000},
	}}
	return sender
}

func evmDeployTx(sender common.Address, code []byte, declaredGas int64, nonce int64) transactionsDefinition.Transaction {
	return transactionsDefinition.Transaction{
		TxParam:  transactionsDefinition.TxParam{ChainID: common.GetChainID(), Sender: sender, Nonce: nonce},
		TxData:   transactionsDefinition.TxData{Recipient: common.EmptyAddress(), OptData: code},
		GasPrice: 1, GasUsage: declaredGas, Height: 10,
	}
}

// S6-01: per-opcode tracing made execution ~170x slower; a loop that burns
// 10M gas must finish in well under a second.
func TestEVMExecutionIsNotSlowedByTracing(t *testing.T) {
	sender := evmTestSender(t)
	loop := []byte{0x5b, 0x60, 0x00, 0x56} // JUMPDEST PUSH1 0 JUMP
	start := time.Now()
	_, _, _, _, err := EvaluateSC(evmDeployTx(sender, loop, 1_000_000, 1), Block{BaseBlock: BaseBlock{BaseHeader: BaseHeader{Height: 10}}})
	if err == nil {
		t.Fatal("expected out of gas")
	}
	if el := time.Since(start); el > 500*time.Millisecond {
		t.Fatalf("10M gas of a tight loop took %s", el.Truncate(time.Millisecond))
	}
}

// A view call must keep returning the contract's return data exactly.
func TestViewCallReturnsContractOutput(t *testing.T) {
	sender := evmTestSender(t)
	bl := Block{BaseBlock: BaseBlock{BaseHeader: BaseHeader{Height: 10}}}
	// runtime: PUSH1 0x2a PUSH1 0 MSTORE PUSH1 32 PUSH1 0 RETURN  (returns 42)
	runtime := []byte{0x60, 0x2a, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3}
	// init: copy runtime to memory and return it
	initCode := append([]byte{0x60, byte(len(runtime)), 0x60, 0x0c, 0x60, 0x00, 0x39, 0x60, byte(len(runtime)), 0x60, 0x00, 0xf3}, runtime...)
	_, _, addr, _, err := EvaluateSC(evmDeployTx(sender, initCode, 100000, 2), bl)
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	out, _, ret, _, _, err := GetViewFunctionReturns(addr, []byte{1}, bl)
	want := common.LeftPadBytes([]byte{42}, 32)
	if err != nil || !bytes.Equal(ret, want) || out != hex.EncodeToString(want) {
		t.Fatalf("view returned out=%q ret=%x err=%v, want %x", out, ret, err, want)
	}
}

// S6-02: the oracle values a contract reads during block execution must be
// the block's, whatever view calls run concurrently.
func TestOracleValuesAreNotChangedByConcurrentViews(t *testing.T) {
	sender := evmTestSender(t)
	bl := Block{BaseBlock: BaseBlock{BaseHeader: BaseHeader{Height: 10}, PriceOracle: 111}}
	call := transactionsDefinition.Transaction{
		TxParam:  transactionsDefinition.TxParam{ChainID: common.GetChainID(), Sender: sender, Nonce: 3},
		TxData:   transactionsDefinition.TxData{Recipient: vm.QwidPriceOracleAddress, OptData: []byte{1}},
		GasPrice: 1, GasUsage: 100000, Height: 10,
	}
	StateMutex.Lock() // a view call is executing
	var ret []byte
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, ret, _, _, _ = EvaluateSC(call, bl)
	}()
	time.Sleep(100 * time.Millisecond)
	vm.SetQwidOracles(999, 999) // another view for another height
	StateMutex.Unlock()
	wg.Wait()
	if want := common.LeftPadBytes([]byte{111}, 32); !bytes.Equal(ret, want) {
		t.Fatalf("contract read price %x during block execution, the block sealed 111", ret)
	}
}

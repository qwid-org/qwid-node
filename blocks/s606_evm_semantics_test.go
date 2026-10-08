package blocks

import (
	"testing"
)

// deployRuntime wraps runtime in init code that returns it.
func deployRuntime(runtime []byte) []byte {
	return append([]byte{0x60, byte(len(runtime)), 0x60, 0x0c, 0x60, 0x00, 0x39, 0x60, byte(len(runtime)), 0x60, 0x00, 0xf3}, runtime...)
}

// S6-06: a constructor that reverts leaves no account behind, so its address
// is not burnt at nonce 1.
func TestFailedConstructorLeavesNoAccount(t *testing.T) {
	sender := evmTestSender(t)
	bl := Block{BaseBlock: BaseBlock{BaseHeader: BaseHeader{Height: 10}}}
	// init: PUSH1 1 PUSH1 0 SSTORE PUSH1 0 PUSH1 0 REVERT
	initCode := []byte{0x60, 0x01, 0x60, 0x00, 0x55, 0x60, 0x00, 0x60, 0x00, 0xfd}
	_, _, addr, _, err := EvaluateSC(evmDeployTx(sender, initCode, 100000, 4), bl)
	if err == nil {
		t.Fatal("a reverting constructor succeeded")
	}
	StateMutex.Lock()
	defer StateMutex.Unlock()
	if _, ok := State.Nonces[addr.ByteValue]; ok {
		t.Fatal("the failed constructor's address kept a nonce")
	}
	if _, ok := State.Accounts[addr.ByteValue]; ok {
		t.Fatal("the failed constructor's address kept an account")
	}
	if len(State.StatesHashes[addr.ByteValue]) != 0 {
		t.Fatal("the failed constructor's storage write survived")
	}
}

// S6-06: SELFDESTRUCT ends the contract - its code and storage are gone after
// the transaction, not just its balance.
func TestSelfDestructRemovesTheContract(t *testing.T) {
	sender := evmTestSender(t)
	bl := Block{BaseBlock: BaseBlock{BaseHeader: BaseHeader{Height: 10}}}
	// runtime: CALLER SELFDESTRUCT
	_, _, addr, _, err := EvaluateSC(evmDeployTx(sender, deployRuntime([]byte{0x33, 0xff}), 100000, 5), bl)
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	call := evmDeployTx(sender, []byte{0x01}, 100000, 6) // EvaluateSC runs only with call data
	call.TxData.Recipient = addr
	if _, _, _, _, err := EvaluateSC(call, bl); err != nil {
		t.Fatalf("call: %v", err)
	}
	StateMutex.Lock()
	defer StateMutex.Unlock()
	if len(State.Codes[addr.ByteValue]) != 0 {
		t.Fatal("a self-destructed contract still has code")
	}
}

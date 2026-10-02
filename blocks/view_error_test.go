package blocks

import "testing"

// S6-05: a view call that reverts must report the failure, not hand back
// empty output as if the contract had answered (a DEX balance read as 0).
func TestViewCallReportsRevert(t *testing.T) {
	sender := evmTestSender(t)
	bl := Block{BaseBlock: BaseBlock{BaseHeader: BaseHeader{Height: 10}}}
	runtime := []byte{0x60, 0x00, 0x60, 0x00, 0xfd} // PUSH1 0 PUSH1 0 REVERT
	initCode := append([]byte{0x60, byte(len(runtime)), 0x60, 0x0c, 0x60, 0x00, 0x39, 0x60, byte(len(runtime)), 0x60, 0x00, 0xf3}, runtime...)
	_, _, addr, _, err := EvaluateSC(evmDeployTx(sender, initCode, 100000, 3), bl)
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if _, _, _, _, _, err := GetViewFunctionReturns(addr, []byte{1, 2, 3, 4}, bl); err == nil {
		t.Fatal("a reverting view call returned no error")
	}
}

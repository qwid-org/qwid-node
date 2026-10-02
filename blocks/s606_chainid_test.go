package blocks

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/qwid-org/qwid-node/common"
)

// S6-06: CHAINID inside the EVM is the QWID chain id, not the development 1337.
func TestEVMChainIDIsTheQwidChainID(t *testing.T) {
	sender := evmTestSender(t)
	bl := Block{BaseBlock: BaseBlock{BaseHeader: BaseHeader{Height: 10}}}
	// runtime: CHAINID PUSH1 0 MSTORE PUSH1 32 PUSH1 0 RETURN
	runtime := []byte{0x46, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3}
	initCode := append([]byte{0x60, byte(len(runtime)), 0x60, 0x0c, 0x60, 0x00, 0x39, 0x60, byte(len(runtime)), 0x60, 0x00, 0xf3}, runtime...)
	_, _, addr, _, err := EvaluateSC(evmDeployTx(sender, initCode, 100000, 3), bl)
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	_, _, ret, _, _, err := GetViewFunctionReturns(addr, []byte{1}, bl)
	want := common.LeftPadBytes(big.NewInt(int64(common.GetChainID())).Bytes(), 32)
	if err != nil || !bytes.Equal(ret, want) {
		t.Fatalf("CHAINID returned %x (%v), want the chain id %d", ret, err, common.GetChainID())
	}
}

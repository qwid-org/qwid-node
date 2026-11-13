package blocks

import (
	"math/big"
	"testing"

	"github.com/qwid-org/qwid-node/common"
)

// Audit 2026-11-13 (F-CONS-02, proposal 1): contracts in a block read the
// price the PARENT established. The producer of a block decides whether the
// price updates in it (it may embed too little stake to establish one) and
// orders its transactions; reading the block's own price let it trade on a
// contract at a price it had just frozen.
func TestContractsReadTheParentsPrice(t *testing.T) {
	k := registeredStageBKey(t)
	fund(k.addr)
	InitStateDB()
	// STATICCALL(gas, 0x100, 0, 0, 0, 32); SSTORE(0, MLOAD(0))
	recorder := []byte{0x60, 0x20, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x61, 0x01, 0x00, 0x5a, 0xfa, 0x50,
		0x60, 0x00, 0x51, 0x60, 0x00, 0x55, 0x00}
	_, _, addr, _, err := EvaluateSC(evmDeployTx(k.addr, deployRuntime(recorder), 200000, 1),
		Block{BaseBlock: BaseBlock{BaseHeader: BaseHeader{Height: 10}}})
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	call := evmDeployTx(k.addr, []byte{1}, 200000, 2)
	call.TxData.Recipient = addr
	call.Height = 99
	k.sign(t, &call)
	parent := parentAt(t, 99)
	parent.BaseBlock.PriceOracle = 111
	blk := childOf(parent, pooled(t, call)...)
	blk.BaseBlock.PriceOracle = 222
	if !evaluateBlockContracts(&blk, parent) {
		t.Fatal("block execution failed")
	}
	StateMutex.RLock()
	got := new(big.Int).SetBytes(State.GetState(addr, common.Hash{}).GetBytes()).Int64()
	StateMutex.RUnlock()
	if got != 111 {
		t.Fatalf("a contract in the block read price %d; the parent established 111", got)
	}
}

func evaluateBlockContracts(bl *Block, parent Block) bool { return EvaluateSmartContracts(bl, parent) }

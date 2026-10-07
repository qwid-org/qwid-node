package blocks

import (
	"testing"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
)

// Audit 2026-10-07 F1-01: SELFDESTRUCT naming the contract itself must not
// destroy its balance (the block supply check would reject the block).
func TestSelfDestructToSelfKeepsSupply(t *testing.T) {
	sender := evmTestSender(t)
	bl := Block{BaseBlock: BaseBlock{BaseHeader: BaseHeader{Height: 10}}}
	_, _, addr, _, err := EvaluateSC(evmDeployTx(sender, deployRuntime([]byte{0x30, 0xff}), 100000, 1), bl) // ADDRESS SELFDESTRUCT
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	before := GetSupplyInAccounts()
	call := evmDeployTx(sender, []byte{0x01}, 100000, 2)
	call.TxData.Recipient = addr
	call.TxData.Amount = 50_000_000
	if _, _, _, _, err := EvaluateSC(call, bl); err != nil {
		t.Fatalf("call: %v", err)
	}
	if after := GetSupplyInAccounts(); after != before {
		t.Fatalf("SELFDESTRUCT(self) destroyed %d base units", before-after)
	}
}

// Audit 2026-10-07 F1-03: a precompile rejecting its input is a failed
// transaction, not a block error - including modexp's operand-size cap.
func TestPrecompileErrorsAreExecutionErrors(t *testing.T) {
	sender := evmTestSender(t)
	bl := Block{BaseBlock: BaseBlock{BaseHeader: BaseHeader{Height: 10}}}
	modexpTooLarge := append(append(common.LeftPadBytes([]byte{0x10, 0x00}, 32), // baseLen 4096
		make([]byte, 32)...), make([]byte, 32)...)
	cases := map[byte][]byte{0x05: modexpTooLarge, 0x06: {1}, 0x07: {1}, 0x08: {1}, 0x09: {1}}
	for pc, input := range cases {
		call := evmDeployTx(sender, input, 100000, int64(pc))
		to, _ := common.BytesToAddress(append(make([]byte, 19), pc))
		call.TxData.Recipient = to
		_, _, _, _, err := EvaluateSC(call, bl)
		if err == nil || !isEVMExecutionError(err) {
			t.Fatalf("precompile 0x%02x: err=%v is not treated as a failed transaction", pc, err)
		}
	}
}

// Audit 2026-10-07 F1-02: a DEX order that cannot execute is skipped (fee
// paid); the block stays valid.
func TestUnexecutableDexOrderDoesNotInvalidateBlock(t *testing.T) {
	k := registeredStageBKey(t)
	fund(k.addr)
	InitStateDB()
	last := parentAt(t, 99)
	tx := transactionsDefinition.Transaction{
		TxParam: transactionsDefinition.TxParam{ChainID: common.GetChainID(), Sender: k.addr, SendingTime: 1, Nonce: 1},
		TxData:  transactionsDefinition.TxData{Recipient: common.GetDelegatedAccountAddress(512 + 3), OptData: transactionsDefinition.DexOrderOptData(1000, 0)},
		Height:  99, GasPrice: 1, GasUsage: 300000,
	}
	tx.ContractAddress.ByteValue[19] = 0xEE // no such token
	k.sign(t, &tx)
	blk := childOf(last, pooled(t, tx)...)
	if !EvaluateSmartContracts(&blk) {
		t.Fatal("an unexecutable DEX order invalidated the whole block")
	}
}

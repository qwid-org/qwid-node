package transactionsDefinition

import (
	"testing"

	"github.com/qwid-org/qwid-node/common"
)

// S6-03: the EVM runs on exactly the declared gas, so everything it may burn
// is paid for. Wallets estimate with headroom for contract calls; the
// validation minimum carries none.
func TestGasEstimateAndMinimum(t *testing.T) {
	contract, _ := common.BytesToAddress(append(make([]byte, 18), 0xC0, 0xDE))
	call := Transaction{TxData: TxData{Recipient: contract, OptData: make([]byte, 68)}}
	if call.MinGasUsage() != 30000+68*100 {
		t.Fatalf("call minimum = %d", call.MinGasUsage())
	}
	if call.GasUsageEstimate() != common.EVMGasEstimateHeadroom*call.MinGasUsage() {
		t.Fatalf("call estimate = %d", call.GasUsageEstimate())
	}

	huge := Transaction{TxData: TxData{Recipient: contract, OptData: make([]byte, 100_000)}}
	if huge.GasUsageEstimate() != common.MaxGasUsage {
		t.Fatalf("estimate must be capped at MaxGasUsage, got %d", huge.GasUsageEstimate())
	}

	plain := Transaction{TxData: TxData{Recipient: contract}}
	if plain.GasUsageEstimate() != plain.MinGasUsage() || plain.MinGasUsage() != 30000 {
		t.Fatalf("plain transfer: estimate=%d min=%d", plain.GasUsageEstimate(), plain.MinGasUsage())
	}

	dex := Transaction{TxData: TxData{Recipient: common.GetDelegatedAccountAddress(600), OptData: make([]byte, 20)}}
	if dex.MinGasUsage() != 30000+20*100+common.DexTokenCallGas {
		t.Fatalf("a DEX operation must pay for its token call: min=%d", dex.MinGasUsage())
	}
	if dex.GasUsageEstimate() != dex.MinGasUsage() {
		t.Fatalf("DEX estimate needs no headroom: %d", dex.GasUsageEstimate())
	}

	staking := Transaction{TxData: TxData{Recipient: common.GetDelegatedAccountAddress(3), OptData: []byte{1}}}
	if staking.GasUsageEstimate() != staking.MinGasUsage() {
		t.Fatal("a delegated recipient runs no EVM and needs no headroom")
	}
}

package blocks

import (
	"testing"

	"github.com/qwid-org/qwid-node/common"
)

// S6-03: no hidden multiplier between the gas paid for and the gas executed.
func TestEVMGasBudgetIsTheDeclaredGas(t *testing.T) {
	if evmGasBudget(50_000) != 50_000 {
		t.Fatalf("budget = %d", evmGasBudget(50_000))
	}
	if evmGasBudget(common.MaxGasUsage+1) != uint64(common.MaxGasUsage) || evmGasBudget(-1) != 0 {
		t.Fatal("budget must stay within [0, MaxGasUsage]")
	}
}

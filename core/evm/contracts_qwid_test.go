package vm

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/params"
)

func word(v int64) []byte {
	return common.LeftPadBytes(new(big.Int).SetInt64(v).Bytes(), 32)
}

// TestQwidOraclePrecompilesReturnBlockValues verifies the precompiles return
// exactly the values the evaluator published, encoded as one 32-byte EVM word.
func TestQwidOraclePrecompilesReturnBlockValues(t *testing.T) {
	SetQwidOracles(6_412_345_000_000, 987654321) // BTC/USD-style price, rand
	defer SetQwidOracles(0, 0)

	price := &qwidPriceOracle{}
	rand := &qwidRandOracle{}

	out, err := price.Run(nil)
	if err != nil {
		t.Fatalf("price Run: %v", err)
	}
	if !bytes.Equal(out, word(6_412_345_000_000)) {
		t.Fatalf("price word = %x, want %x", out, word(6_412_345_000_000))
	}
	out, err = rand.Run([]byte{0xde, 0xad}) // input must be ignored
	if err != nil {
		t.Fatalf("rand Run: %v", err)
	}
	if !bytes.Equal(out, word(987654321)) {
		t.Fatalf("rand word = %x, want %x", out, word(987654321))
	}
	if len(out) != 32 {
		t.Fatalf("output must be one EVM word, got %d bytes", len(out))
	}
}

// TestQwidOraclePrecompilesClampNegative pins the negative-value policy: clamp
// to zero rather than wrap into a huge uint256.
func TestQwidOraclePrecompilesClampNegative(t *testing.T) {
	SetQwidOracles(-1, -42)
	defer SetQwidOracles(0, 0)
	out, _ := (&qwidPriceOracle{}).Run(nil)
	if !bytes.Equal(out, word(0)) {
		t.Fatalf("negative price must clamp to 0, got %x", out)
	}
	out, _ = (&qwidRandOracle{}).Run(nil)
	if !bytes.Equal(out, word(0)) {
		t.Fatalf("negative rand must clamp to 0, got %x", out)
	}
}

// TestQwidOraclePrecompilesRegistered verifies both precompiles are reachable
// in every fork set evm.precompile can select, and listed in the active-address
// lists (Berlin access-list warming).
func TestQwidOraclePrecompilesRegistered(t *testing.T) {
	sets := map[string]map[common.Address]PrecompiledContract{
		"Homestead": PrecompiledContractsHomestead,
		"Byzantium": PrecompiledContractsByzantium,
		"Istanbul":  PrecompiledContractsIstanbul,
		"Berlin":    PrecompiledContractsBerlin,
	}
	for name, m := range sets {
		if _, ok := m[QwidPriceOracleAddress]; !ok {
			t.Errorf("%s: price oracle precompile not registered", name)
		}
		if _, ok := m[QwidRandOracleAddress]; !ok {
			t.Errorf("%s: rand oracle precompile not registered", name)
		}
	}
	found := 0
	for _, a := range ActivePrecompiles(params.Rules{IsBerlin: true}) {
		if a == QwidPriceOracleAddress || a == QwidRandOracleAddress {
			found++
		}
	}
	if found != 2 {
		t.Errorf("Berlin active-precompile list holds %d of the 2 oracle addresses", found)
	}
}

// TestQwidOraclePrecompileGasCharge runs through RunPrecompiledContract and
// verifies the fixed gas cost is charged (and insufficient gas fails).
func TestQwidOraclePrecompileGasCharge(t *testing.T) {
	SetQwidOracles(7, 8)
	defer SetQwidOracles(0, 0)

	out, remaining, err := RunPrecompiledContract(&qwidPriceOracle{}, nil, QwidOracleGas+5)
	if err != nil {
		t.Fatalf("RunPrecompiledContract: %v", err)
	}
	if remaining != 5 {
		t.Fatalf("remaining gas = %d, want 5", remaining)
	}
	if !bytes.Equal(out, word(7)) {
		t.Fatalf("output = %x, want %x", out, word(7))
	}

	if _, _, err := RunPrecompiledContract(&qwidRandOracle{}, nil, QwidOracleGas-1); err == nil {
		t.Fatal("running with insufficient gas must fail")
	}
}

// TestStandardPrecompilesReachable pins the SetBytes left-padding fix: before
// it, every short BytesToVMAddress input collapsed to the zero address, so ALL
// standard precompiles shared one 0x00 map key and a contract calling 0x…01
// (whose callee address is built 20-byte via SetByteAddress) never matched —
// no precompile was reachable in this fork.
func TestStandardPrecompilesReachable(t *testing.T) {
	if len(PrecompiledContractsBerlin) < 11 { // 9 standard + 2 QWID oracles
		t.Fatalf("Berlin precompile map holds %d entries; standard addresses have collapsed", len(PrecompiledContractsBerlin))
	}
	// The map key for ecrecover must equal the address a contract's CALL builds.
	var one [20]byte
	one[19] = 1
	runtimeAddr := common.SetByteAddress(one)
	if _, ok := PrecompiledContractsBerlin[runtimeAddr]; !ok {
		t.Fatal("ecrecover is not reachable at the runtime-built 0x…01 address")
	}
	// And the QWID oracles at theirs.
	var price20, rand20 [20]byte
	price20[18], price20[19] = 1, 0
	rand20[18], rand20[19] = 1, 1
	if _, ok := PrecompiledContractsBerlin[common.SetByteAddress(price20)]; !ok {
		t.Fatal("price oracle is not reachable at the runtime-built 0x…0100 address")
	}
	if _, ok := PrecompiledContractsBerlin[common.SetByteAddress(rand20)]; !ok {
		t.Fatal("rand oracle is not reachable at the runtime-built 0x…0101 address")
	}
}

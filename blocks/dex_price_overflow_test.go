package blocks

import (
	"math"
	"testing"

	"github.com/qwid-org/qwid-node/common"
)

// The on-chain token price is stored as int64 in the DEX account and is
// serialised into consensus state (account/dexAccount.go). It is produced by
// scaling a float price by 10^(coinDecimals+tokenDecimals) — the SUM, not the
// difference — so the multiplier is 10^16 for an 8-decimal token and the
// headroom is small: any price at or above ~922 overflows int64.
//
// An overflowing `int64(f)` conversion is implementation-defined in Go: amd64
// yields the minimum int64, arm64 saturates to the maximum. Two nodes on
// different architectures would therefore write different TokenPrice values
// into state for the same block and fork. These tests pin the boundary so the
// guard cannot be removed or widened by accident.

func TestScaleTokenPriceRefusesOverflow(t *testing.T) {
	const tokenDecimals uint8 = 8 // 10^(8+8) = 10^16

	// A price of 1000 coins per token is ordinary, not an attack: 1000 * 10^16
	// is 10^19, above MaxInt64 (~9.22e18).
	if v, ok := scaleTokenPrice(1000, common.Decimals, tokenDecimals); ok {
		t.Fatalf("scaleTokenPrice(1000) reported success and returned %d; 1000 * 10^16 does not fit in int64", v)
	}

	// Just under the boundary must still work, or the guard is too aggressive
	// and would reject prices the DEX has always accepted.
	if _, ok := scaleTokenPrice(900, common.Decimals, tokenDecimals); !ok {
		t.Fatal("scaleTokenPrice(900) was refused; 900 * 10^16 fits in int64 and must keep working")
	}
}

func TestScaleTokenPriceHandlesOrdinaryValues(t *testing.T) {
	const tokenDecimals uint8 = 8

	got, ok := scaleTokenPrice(1.5, common.Decimals, tokenDecimals)
	if !ok {
		t.Fatal("scaleTokenPrice(1.5) was refused")
	}
	if want := int64(1.5 * 1e16); got != want {
		t.Fatalf("scaleTokenPrice(1.5) = %d, expected %d", got, want)
	}

	if got, ok := scaleTokenPrice(0, common.Decimals, tokenDecimals); !ok || got != 0 {
		t.Fatalf("scaleTokenPrice(0) = %d, %v; expected 0, true", got, ok)
	}
}

func TestScaleTokenPriceRefusesNaNAndInf(t *testing.T) {
	for _, v := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		if _, ok := scaleTokenPrice(v, common.Decimals, 8); ok {
			t.Errorf("scaleTokenPrice(%v) reported success", v)
		}
	}
}

// A token with many decimals shrinks the headroom drastically: at 18 decimals
// the multiplier is 10^26 and even a price of 1 does not fit.
func TestScaleTokenPriceHighDecimalTokens(t *testing.T) {
	if v, ok := scaleTokenPrice(1, common.Decimals, 18); ok {
		t.Fatalf("scaleTokenPrice(1, 18 decimals) reported success and returned %d; 10^26 cannot fit in int64", v)
	}
}

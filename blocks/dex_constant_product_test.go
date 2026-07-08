package blocks

import (
	"math"
	"testing"
)

// roundDecimals used by the DEX (common.Decimals=8 + an 8-decimal token).
const rdTest = 16

func TestConstantProductPreservesK(t *testing.T) {
	coinPool, tokenPool := 1000.0, 1000.0
	k := coinPool * tokenPool

	// BUY Δ tokens: price = coin/(token-Δ); coinPaid = price*Δ; pool -> (coin+paid, token-Δ).
	buy := 100.0
	pB := constantProductPrice(coinPool, tokenPool, buy, rdTest)
	if pB <= 0 {
		t.Fatal("buy price must be positive")
	}
	coinPaid := pB * buy
	if kB := (coinPool + coinPaid) * (tokenPool - buy); math.Abs(kB-k)/k > 1e-6 {
		t.Fatalf("BUY broke k: got %v want %v", kB, k)
	}

	// SELL Δ tokens: caller negates amountToken, so pass -Δ; pool -> (coin-recv, token+Δ).
	sell := 100.0
	pS := constantProductPrice(coinPool, tokenPool, -sell, rdTest)
	if pS <= 0 {
		t.Fatal("sell price must be positive")
	}
	coinRecv := pS * sell
	if kS := (coinPool - coinRecv) * (tokenPool + sell); math.Abs(kS-k)/k > 1e-6 {
		t.Fatalf("SELL broke k: got %v want %v", kS, k)
	}
}

func TestConstantProductHalfPoolBoundedAndGuard(t *testing.T) {
	coinPool, tokenPool := 1000.0, 1000.0
	// Half-pool buy: previously the -2*amount guard made this a no-op (denom 0);
	// now it prices at 2*poolPrice (finite), costing ~the whole coin pool.
	pHalf := constantProductPrice(coinPool, tokenPool, 500.0, rdTest)
	if pHalf <= 0 {
		t.Fatal("half-pool buy must now be priced (bounded), not a no-op")
	}
	if math.Abs(pHalf-2.0) > 1e-6 {
		t.Fatalf("half-pool price = %v, want 2.0", pHalf)
	}
	// Full-pool and beyond: rejected by the denom>0 guard (price 0).
	if p := constantProductPrice(coinPool, tokenPool, 1000.0, rdTest); p != 0 {
		t.Fatalf("full-pool buy must be rejected (price 0), got %v", p)
	}
	if p := constantProductPrice(coinPool, tokenPool, 1200.0, rdTest); p != 0 {
		t.Fatalf("over-full buy must be rejected (price 0), got %v", p)
	}
	// Non-positive pool: price 0.
	if p := constantProductPrice(0, tokenPool, 100.0, rdTest); p != 0 {
		t.Fatalf("empty coin pool must yield price 0, got %v", p)
	}
}

func TestScaleToInt64(t *testing.T) {
	// Normal value scales correctly.
	if got, ok := scaleToInt64(1.5, 8); !ok || got != 150000000 {
		t.Fatalf("normal value: got (%v, %v), want (150000000, true)", got, ok)
	}

	// Negative value scales correctly.
	if got, ok := scaleToInt64(-1.5, 8); !ok || got != -150000000 {
		t.Fatalf("negative value: got (%v, %v), want (-150000000, true)", got, ok)
	}

	// Huge value overflows int64.
	if got, ok := scaleToInt64(1e30, 8); ok || got != 0 {
		t.Fatalf("huge value: got (%v, %v), want (0, false)", got, ok)
	}

	// Boundary: a value whose scaled result is >= float64(math.MaxInt64) must be rejected
	// (float64(math.MaxInt64) rounds up to 2^63, which does not fit in int64).
	if got, ok := scaleToInt64(float64(math.MaxInt64), 0); ok || got != 0 {
		t.Fatalf("boundary value: got (%v, %v), want (0, false)", got, ok)
	}

	// NaN and Inf are rejected.
	if got, ok := scaleToInt64(math.NaN(), 8); ok || got != 0 {
		t.Fatalf("NaN: got (%v, %v), want (0, false)", got, ok)
	}
	if got, ok := scaleToInt64(math.Inf(1), 8); ok || got != 0 {
		t.Fatalf("+Inf: got (%v, %v), want (0, false)", got, ok)
	}
	if got, ok := scaleToInt64(math.Inf(-1), 8); ok || got != 0 {
		t.Fatalf("-Inf: got (%v, %v), want (0, false)", got, ok)
	}
}

func TestConstantProductRoundTripNoValueCreation(t *testing.T) {
	coinPool, tokenPool := 1000.0, 1000.0
	d := 50.0
	// Buy d, then sell d against the resulting pool: coin received must ~equal coin paid
	// (no fee => buy-then-sell of the same amount is a wash).
	pB := constantProductPrice(coinPool, tokenPool, d, rdTest)
	coinPaid := pB * d
	c2, t2 := coinPool+coinPaid, tokenPool-d
	pS := constantProductPrice(c2, t2, -d, rdTest)
	coinRecv := pS * d
	if math.Abs(coinPaid-coinRecv)/coinPaid > 1e-6 {
		t.Fatalf("round-trip leaked value: paid %v received %v", coinPaid, coinRecv)
	}
}

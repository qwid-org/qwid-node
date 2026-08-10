package blocks

import (
	"math"
	"testing"
)

// The existing constant-product tests check single points. These check the
// properties a trader could otherwise exploit: that a bigger trade is never
// cheaper, that a round trip cannot mint value, that the pool can never be
// drained, and that the arithmetic stays sane at the magnitudes real pools use.
//
// constantProductPrice returns the AVERAGE execution price coin/(token-Δ),
// with Δ signed: positive buys tokens out of the pool, negative sells into it.

// coinFor returns the coin delta implied by a trade, positive when the trader
// pays in and negative when the trader takes out.
func coinFor(coinPool, tokenPool, delta float64) (price, coin float64) {
	price = constantProductPrice(coinPool, tokenPool, delta, rdTest)
	return price, price * delta
}

// Buying more tokens must never yield a better average price. If it did, a
// trader could split or merge orders to extract value from the pool.
func TestLargerBuyNeverGetsABetterPrice(t *testing.T) {
	const coinPool, tokenPool = 1_000_000.0, 1_000_000.0

	prev := 0.0
	for _, size := range []float64{1, 10, 100, 1_000, 10_000, 100_000, 400_000} {
		p := constantProductPrice(coinPool, tokenPool, size, rdTest)
		if p <= 0 {
			t.Fatalf("buy of %v was rejected in a pool that can serve it", size)
		}
		if p < prev {
			t.Fatalf("buying %v priced at %v, cheaper than the smaller trade at %v", size, p, prev)
		}
		prev = p
	}
}

// The mirror property for sells: selling more must never pay better per token.
func TestLargerSellNeverPaysBetter(t *testing.T) {
	const coinPool, tokenPool = 1_000_000.0, 1_000_000.0

	prev := math.MaxFloat64
	for _, size := range []float64{1, 10, 100, 1_000, 10_000, 100_000, 400_000} {
		p := constantProductPrice(coinPool, tokenPool, -size, rdTest)
		if p <= 0 {
			t.Fatalf("sell of %v was rejected", size)
		}
		if p > prev {
			t.Fatalf("selling %v paid %v, better than the smaller trade at %v", size, p, prev)
		}
		prev = p
	}
}

// Splitting a buy into two halves must not beat doing it in one go. This is the
// classic way to milk a badly specified curve.
func TestSplittingABuyDoesNotBeatOneTrade(t *testing.T) {
	const coinPool, tokenPool = 1_000_000.0, 1_000_000.0
	const total = 100_000.0

	_, oneShot := coinFor(coinPool, tokenPool, total)

	// First half, then the second against the moved pool.
	p1, paid1 := coinFor(coinPool, tokenPool, total/2)
	if p1 <= 0 {
		t.Fatal("first half was rejected")
	}
	c2, t2 := coinPool+paid1, tokenPool-total/2
	_, paid2 := coinFor(c2, t2, total/2)

	split := paid1 + paid2
	if split < oneShot*(1-1e-9) {
		t.Fatalf("splitting paid %v for the same tokens the single trade charged %v — "+
			"a trader could shave value off the pool by chunking orders", split, oneShot)
	}
}

// Buying then immediately selling back the same tokens must not return more
// coin than was paid. Anything else is free money out of the pool.
func TestBuyThenSellBackCannotProfit(t *testing.T) {
	for _, size := range []float64{1, 100, 10_000, 250_000} {
		const coinPool, tokenPool = 1_000_000.0, 1_000_000.0

		pBuy, paid := coinFor(coinPool, tokenPool, size)
		if pBuy <= 0 {
			t.Fatalf("buy of %v rejected", size)
		}
		afterCoin, afterToken := coinPool+paid, tokenPool-size

		pSell := constantProductPrice(afterCoin, afterToken, -size, rdTest)
		if pSell <= 0 {
			t.Fatalf("sell-back of %v rejected", size)
		}
		received := pSell * size

		if received > paid*(1+1e-9) {
			t.Fatalf("round trip of %v tokens paid %v and returned %v — the pool lost value",
				size, paid, received)
		}
	}
}

// A trade must never be able to take the pool to or past empty. The guard is
// the only thing standing between a large order and a drained pool.
func TestPoolCannotBeDrainedByAnyBuy(t *testing.T) {
	const coinPool, tokenPool = 1_000.0, 1_000.0

	for _, size := range []float64{tokenPool, tokenPool + 1e-9, tokenPool * 2, 1e18} {
		if p := constantProductPrice(coinPool, tokenPool, size, rdTest); p != 0 {
			t.Errorf("a buy of %v (pool has %v) priced at %v instead of being rejected",
				size, tokenPool, p)
		}
	}

	// Just under the full pool must still be servable, however expensive.
	if p := constantProductPrice(coinPool, tokenPool, tokenPool-1e-6, rdTest); p <= 0 {
		t.Error("a trade just short of the full pool was rejected")
	}
}

// Degenerate pools must price at zero rather than producing infinities or NaN
// that would later be scaled into an int64.
func TestDegeneratePoolsPriceAtZero(t *testing.T) {
	cases := []struct {
		name                          string
		coinPool, tokenPool, amount   float64
	}{
		{"empty coin pool", 0, 1_000, 10},
		{"negative coin pool", -1, 1_000, 10},
		{"empty token pool", 1_000, 0, 10},
		{"negative token pool", 1_000, -1, 10},
		{"both empty", 0, 0, 10},
		{"sell into empty coin pool", 0, 1_000, -10},
	}
	for _, c := range cases {
		p := constantProductPrice(c.coinPool, c.tokenPool, c.amount, rdTest)
		if p != 0 {
			t.Errorf("%s: priced at %v, want 0", c.name, p)
		}
		if math.IsNaN(p) || math.IsInf(p, 0) {
			t.Errorf("%s: produced %v", c.name, p)
		}
	}
}

// Whatever the curve says, the result has to survive conversion to base units.
// scaleToInt64 is the last line before a price becomes an on-chain amount, and
// the value it is handed near the pool boundary is astronomic.
//
// The pool sizes are chosen so the subtraction stays representable: with a
// 1e12 token pool, tokenPool-1e-9 rounds back to tokenPool in float64 and the
// guard rejects the trade before anything is priced, which would test nothing.
func TestExtremePricesDoNotOverflowIntoBaseUnits(t *testing.T) {
	const coinPool, tokenPool = 1e15, 1_000.0
	const amount = 999.999999 // leaves a 1e-6 denominator

	p := constantProductPrice(coinPool, tokenPool, amount, rdTest)
	if p <= 0 {
		t.Fatalf("the trade was rejected before pricing; the test needs a priced trade")
	}
	if _, ok := scaleToInt64(p*amount, 8); ok {
		t.Fatalf("a coin amount of ~%.3g converted to int64 instead of being refused", p*amount)
	}

	// And the ordinary case still converts, so the guard is not simply refusing
	// everything.
	if v, ok := scaleToInt64(1.5, 8); !ok || v != 150_000_000 {
		t.Fatalf("a normal amount failed to convert: %d ok=%t", v, ok)
	}
}

// Realistic magnitudes: an 8-decimal token and a pool worth millions must still
// price with usable precision rather than collapsing to zero or to the pool price.
func TestPricingIsUsableAtRealisticPoolSizes(t *testing.T) {
	const coinPool = 5_000_000.0  // 5M coin
	const tokenPool = 2_500_000.0 // 2.5M token -> pool price 2.0

	poolPrice := coinPool / tokenPool
	small := constantProductPrice(coinPool, tokenPool, 1.0, rdTest)

	if small <= 0 {
		t.Fatal("a one-token buy was rejected")
	}
	if small < poolPrice {
		t.Fatalf("a buy priced at %v, below the pool price %v", small, poolPrice)
	}
	// A single token out of 2.5M should barely move the price.
	if rel := (small - poolPrice) / poolPrice; rel > 1e-5 {
		t.Fatalf("a one-token buy moved the price by %.6f%% — precision is being lost", rel*100)
	}
}

func TestScaleToInt64RefusesNaNAndInf(t *testing.T) {
	for _, v := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		if _, ok := scaleToInt64(v, 8); ok {
			t.Errorf("scaleToInt64(%v) reported success", v)
		}
	}
}

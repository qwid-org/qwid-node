package oracles

import (
	"math"
	"testing"
)

// S4-09: the midpoint of two large prices must not overflow.
func TestMedianDoesNotOverflow(t *testing.T) {
	got := Median([]int64{math.MaxInt64 - 1, math.MaxInt64 - 1})
	if got != math.MaxInt64-1 {
		t.Fatalf("median = %d", got)
	}
	if Median([]int64{2, 5}) != 3 || Median([]int64{1, 2, 3}) != 2 {
		t.Fatal("ordinary medians changed")
	}
}

// S4-09: a non-positive price is never a valid proposal - generation already
// required > 0, parsing did not.
func TestParsePriceDataRejectsNonPositive(t *testing.T) {
	entry := func(price int64) []byte {
		b := append([]byte{1}, make([]byte, 8)...)
		p := make([]byte, 8)
		for i := 0; i < 8; i++ {
			p[i] = byte(uint64(price) >> (8 * i))
		}
		return append(b, p...)
	}
	for _, price := range []int64{0, -5} {
		if _, _, _, err := ParsePriceData(entry(price)); err == nil {
			t.Fatalf("price %d accepted", price)
		}
	}
}

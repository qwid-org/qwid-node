package transactionsDefinition

import "testing"

// S7-07: an order may carry a signed coin limit; old 8-byte orders still parse.
func TestDexOrderOptData(t *testing.T) {
	amount, limit, err := ParseDexOptData(DexOrderOptData(500, 0), 3)
	if err != nil || amount != 500 || limit != 0 || len(DexOrderOptData(500, 0)) != 8 {
		t.Fatalf("an order without a limit: %d %d %v", amount, limit, err)
	}
	amount, limit, err = ParseDexOptData(DexOrderOptData(500, 7_000), 4)
	if err != nil || amount != 500 || limit != 7_000 {
		t.Fatalf("an order with a limit: %d %d %v", amount, limit, err)
	}
	if _, _, err := ParseDexOptData(DexOrderOptData(500, 7_000), 2); err == nil {
		t.Fatal("a limit on adding liquidity was accepted")
	}
	neg := DexOrderOptData(500, 1)
	copy(neg[8:], DexOrderOptData(-1, 0))
	if _, _, err := ParseDexOptData(neg, 3); err == nil {
		t.Fatal("a negative limit was accepted")
	}
	for _, n := range []int{0, 7, 9, 24} {
		if _, _, err := ParseDexOptData(make([]byte, n), 3); err == nil {
			t.Fatalf("%d bytes of order data were accepted", n)
		}
	}
}

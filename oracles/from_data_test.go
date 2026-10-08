package oracles

import "testing"

// The producer's value must be what the validator recomputes from the same
// data. Without stake behind the data the price cannot be established, and
// the block must carry the parent's price forward - never 0 (S4-06).
func TestValuesFromDataAgreeWithVerify(t *testing.T) {
	data := append(append([]byte{2}, make([]byte, 8)...), 0, 0, 0, 0, 0, 0, 0, 7)
	if _, err := PriceFromData(data, 1_000); err == nil {
		t.Fatal("a price without stake behind it was established")
	}
	const parent = 777
	if !VerifyPriceOracle(10, 1_000, parent, data, parent) {
		t.Fatal("carrying the parent's price forward was rejected")
	}
	if VerifyPriceOracle(10, 1_000, 0, data, parent) {
		t.Fatal("a producer could publish 0 by embedding too little stake")
	}
	if _, err := PriceFromData([]byte{1, 2}, 1_000); err == nil {
		t.Fatal("malformed data must fail")
	}
}

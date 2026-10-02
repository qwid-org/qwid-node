package oracles

import "testing"

// The producer's value must be what the validator recomputes from the same
// data. Without stake behind the data both sides land on 0.
func TestValuesFromDataAgreeWithVerify(t *testing.T) {
	data := append(append([]byte{2}, make([]byte, 8)...), 0, 0, 0, 0, 0, 0, 0, 7)
	p, err := PriceFromData(data, 1_000)
	if err == nil || p != 0 || !VerifyPriceOracle(10, 1_000, p, data) {
		t.Fatalf("price without stake: p=%d err=%v", p, err)
	}
	r, err := RandFromData(data, 1_000)
	if err == nil || r != 0 || !VerifyRandOracle(10, 1_000, r, data) {
		t.Fatalf("rand without stake: r=%d err=%v", r, err)
	}
	if _, err := PriceFromData([]byte{1, 2}, 1_000); err == nil {
		t.Fatal("malformed data must fail")
	}
}

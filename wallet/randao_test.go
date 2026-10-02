package wallet

import (
	"bytes"
	"testing"
)

// Seeds are re-derived when revealed, so the same height must always give the
// same seed, and different heights or wallets different ones (S4-06).
func TestRandaoSeedIsDeterministicPerHeight(t *testing.T) {
	w := &Wallet{seed: bytes.Repeat([]byte{7}, 64)}
	a, err := w.RandaoSeed(10)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := w.RandaoSeed(10)
	other, _ := w.RandaoSeed(11)
	if !bytes.Equal(a, again) {
		t.Fatal("the seed of a height changed between derivations")
	}
	if bytes.Equal(a, other) {
		t.Fatal("two heights gave the same seed")
	}
	if bytes.Equal(a, w.seed[:len(a)]) {
		t.Fatal("the seed exposes the wallet secret")
	}
	if x, _ := (&Wallet{seed: bytes.Repeat([]byte{8}, 64)}).RandaoSeed(10); bytes.Equal(a, x) {
		t.Fatal("two wallets gave the same seed")
	}
	if _, err := (&Wallet{}).RandaoSeed(10); err == nil {
		t.Fatal("a wallet without a secret produced a seed")
	}
}

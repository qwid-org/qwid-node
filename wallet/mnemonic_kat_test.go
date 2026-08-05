package wallet

import "testing"

// katPhrase is the standard BIP39 all-"abandon" test vector, 24-word variant.
const katPhrase = "abandon abandon abandon abandon abandon abandon abandon abandon " +
	"abandon abandon abandon abandon abandon abandon abandon abandon " +
	"abandon abandon abandon abandon abandon abandon abandon art"

// Addresses this phrase must always produce. Recorded once, from a single run
// of the implementation (see the now-deleted wallet/kat_gen_test.go), and
// must NEVER be updated to make a failing run pass again: if this test starts
// failing, the derivation itself changed, and every wallet ever created from
// a recovery phrase would now restore to a different, empty account on any
// clean machine. A failure here means STOP AND INVESTIGATE THE DERIVATION
// CODE — it is never, under any circumstance, a signal to re-record these
// constants from the new output.
//
// The usual causes are a liboqs upgrade that alters how a scheme consumes its
// keygen seed, a change to hkdfSalt or detKeygenInfo, or a different active
// signature scheme in the test environment.
const (
	katPrimaryAddress   = "b0d5c129b78983f33c5e256aaaa4cb8de9191fa2"
	katSecondaryAddress = "e3e10a9738ed934220871e9cdc5a13a5cdcc36c0"
)

func TestKnownAnswerDerivation(t *testing.T) {
	w := newSeedTestWallet(t, 241)
	if err := w.SetMnemonic([]byte(katPhrase)); err != nil {
		t.Fatal(err)
	}

	primary, err := GenerateNewAccountFromSeed(*w, w.SigName, true)
	if err != nil {
		t.Fatal(err)
	}
	w.MainAddress = primary.Address
	secondary, err := GenerateNewAccountFromSeed(*w, w.SigName2, false)
	if err != nil {
		t.Fatal(err)
	}

	if got := primary.Address.GetHex(); got != katPrimaryAddress {
		t.Fatalf("adres podstawowy = %s, przypięty %s — derywacja się zmieniła, "+
			"istniejące frazy odtworzą inny portfel", got, katPrimaryAddress)
	}
	if got := secondary.Address.GetHex(); got != katSecondaryAddress {
		t.Fatalf("adres dodatkowy = %s, przypięty %s — derywacja się zmieniła, "+
			"istniejące frazy odtworzą inny portfel", got, katSecondaryAddress)
	}
}

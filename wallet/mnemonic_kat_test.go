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
// Re-recorded once, on 2026-08-28, when the default schemes changed from
// Falcon-512/MAYO-5 to Falcon-padded-512/MAYO-2. That re-recording was only
// permissible because derivation was first PROVEN unchanged: run under the old
// pair, the code still produced the previous constants exactly —
// b0d5c129b78983f33c5e256aaaa4cb8de9191fa2 and
// e3e10a9738ed934220871e9cdc5a13a5cdcc36c0. Any future scheme change must clear
// the same bar before these values are touched: derive under the OLD pair,
// confirm the OLD constants still come out, and only then record the new ones.
// If the old pair no longer reproduces them, derivation has broken and no new
// constant may be written.
const (
	katPrimaryAddress   = "8a1ded4643b82f4667535bf0e86489b672c61446"
	katSecondaryAddress = "facd5d2e4d0dd671bd93936918fba513ba87c24e"
)

// The schemes the pinned addresses above were recorded under. The addresses are
// only meaningful together with these names: derivation is domain-separated per
// scheme (DeriveKeySeed), so running the same phrase under a different scheme
// legitimately yields a different address. Asserted explicitly so that a change
// to the default config fails with "the test environment is configured for a
// different scheme" instead of the address mismatch below, which claims the
// derivation changed when it did not.
const (
	katPrimaryScheme   = "Falcon-padded-512"
	katSecondaryScheme = "MAYO-2"
)

func TestKnownAnswerDerivation(t *testing.T) {
	w := newSeedTestWallet(t, 241)
	if w.SigName != katPrimaryScheme || w.SigName2 != katSecondaryScheme {
		t.Fatalf("the pinned addresses were recorded for schemes %q/%q while the test environment uses %q/%q — "+
			"this does NOT mean derivation changed; the pinned values belong to different schemes",
			katPrimaryScheme, katSecondaryScheme, w.SigName, w.SigName2)
	}
	if err := w.SetMnemonic([]byte(katPhrase)); err != nil {
		t.Fatal(err)
	}

	primary, err := GenerateNewAccountFromSeed(*w, katPrimaryScheme, true)
	if err != nil {
		t.Fatal(err)
	}
	w.MainAddress = primary.Address
	secondary, err := GenerateNewAccountFromSeed(*w, katSecondaryScheme, false)
	if err != nil {
		t.Fatal(err)
	}

	if got := primary.Address.GetHex(); got != katPrimaryAddress {
		t.Fatalf("primary address = %s, pinned %s — derivation has changed, "+
			"existing phrases will restore a different wallet", got, katPrimaryAddress)
	}
	if got := secondary.Address.GetHex(); got != katSecondaryAddress {
		t.Fatalf("secondary address = %s, pinned %s — derivation has changed, "+
			"existing phrases will restore a different wallet", got, katSecondaryAddress)
	}
}

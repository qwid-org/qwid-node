package wallet

import (
	"strings"
	"testing"

	"github.com/qwid-org/qwid-node/common"
)

// TestSchemeChangeIsReproducibleFromPhrase: when the chain votes in a new
// scheme, the node generates that key unattended. If it were random, the
// recovery phrase would stop being enough to restore the wallet.
func TestSchemeChangeIsReproducibleFromPhrase(t *testing.T) {
	mnemonic, err := NewMnemonic24()
	if err != nil {
		t.Fatal(err)
	}

	newScheme := common.SigName2()

	w1 := newSeedTestWallet(t, 210)
	if err := w1.SetMnemonic(mnemonic); err != nil {
		t.Fatal(err)
	}
	fillAccountsFromSeed(t, w1)
	if err := w1.AddNewEncryptionToActiveWallet(newScheme, true); err != nil {
		t.Fatal(err)
	}

	w2 := newSeedTestWallet(t, 210)
	if err := w2.SetMnemonic(mnemonic); err != nil {
		t.Fatal(err)
	}
	fillAccountsFromSeed(t, w2)
	if err := w2.AddNewEncryptionToActiveWallet(newScheme, true); err != nil {
		t.Fatal(err)
	}

	if w1.Account1.Address.GetHex() != w2.Account1.Address.GetHex() {
		t.Fatalf("klucz dla nowego schematu nie jest odtwarzalny z frazy: %s vs %s",
			w1.Account1.Address.GetHex(), w2.Account1.Address.GetHex())
	}
}

// TestSchemeChangeIsReproducibleFromPhraseUnknownScheme covers the case a
// real chain vote actually produces: a scheme that is neither this node's
// currently configured primary (Falcon-512) nor secondary (MAYO-5). Using
// common.SigName2() (MAYO-5) as the "new" scheme in
// TestSchemeChangeIsReproducibleFromPhrase above is not representative of
// that — MAYO-5's public key length (5554) happens to equal the currently
// configured secondary length, so common.PubKey.Init's length check
// (common/types.go:326, `len(b) != PubKeyLength(false) && len(b) !=
// PubKeyLength2(false)`) passes via the secondary-length branch even though
// the key is written into the PRIMARY slot with primary=true — a
// coincidence, not proof the primary/secondary handling is correct.
//
// In production, blocks/processEncryption.go's SetVoteEncryption drives
// common.SetEncryption to the new scheme's lengths BEFORE
// blocks/processPubKey.go calls AddNewPubKeyToActiveWallet into this
// function, so withSchemeChangeTarget (which does the same thing for tests)
// reproduces the actual state this function runs in.
func TestSchemeChangeIsReproducibleFromPhraseUnknownScheme(t *testing.T) {
	mnemonic, err := NewMnemonic24()
	if err != nil {
		t.Fatal(err)
	}

	w1 := newSeedTestWallet(t, 222)
	if err := w1.SetMnemonic(mnemonic); err != nil {
		t.Fatal(err)
	}
	fillAccountsFromSeed(t, w1)

	w2 := newSeedTestWallet(t, 223)
	if err := w2.SetMnemonic(mnemonic); err != nil {
		t.Fatal(err)
	}
	fillAccountsFromSeed(t, w2)

	// Mirrors a real scheme-change vote: the global config flips to the new
	// scheme before the unattended key-generation call.
	withSchemeChangeTarget(t)

	if err := w1.AddNewEncryptionToActiveWallet(schemeChangeTarget, true); err != nil {
		t.Fatal(err)
	}
	if err := w2.AddNewEncryptionToActiveWallet(schemeChangeTarget, true); err != nil {
		t.Fatal(err)
	}

	if w1.Account1.Address.GetHex() != w2.Account1.Address.GetHex() {
		t.Fatalf("klucz dla nieznanego schematu %q nie jest odtwarzalny z frazy: %s vs %s",
			schemeChangeTarget, w1.Account1.Address.GetHex(), w2.Account1.Address.GetHex())
	}
}

// TestSchemeChangeRefusedWithoutPhrase is the live-path half of the refusal the
// load path already implements (loadWalletFromStruct's scheme-change branches,
// covered by TestLegacyWalletSchemeChangeFailsSafely).
//
// This function is what a chain-voted scheme change actually runs on a live
// node: blocks/processEncryption.go -> AddNewPubKeyToActiveWallet ->
// AddNewEncryptionToActiveWallet, and the caller then persists the result with
// StoreJSON. It used to generate a RANDOM key for a phrase-less wallet, which
// made the load path's refusal unreachable: the random key was archived under
// the new scheme name, so the next restart found an archive entry, adopted it,
// and repointed MainAddress at it — replacing the staked identity silently,
// which is exactly what the refusal exists to prevent. It must refuse instead,
// and the message must name the scheme so the operator knows what to restore
// for.
func TestSchemeChangeRefusedWithoutPhrase(t *testing.T) {
	w := newSeedTestWallet(t, 211)
	acc, err := GenerateNewAccount(*w, w.SigName)
	if err != nil {
		t.Fatal(err)
	}
	w.MainAddress = acc.Address
	w.Account1 = acc
	acc2, err := GenerateNewAccount(*w, w.SigName2)
	if err != nil {
		t.Fatal(err)
	}
	w.Account2 = acc2
	if w.HasSeed() {
		t.Fatal("test wallet unexpectedly has a seed")
	}
	addressBefore := w.Account1.Address.GetHex()

	newScheme := common.SigName2()
	err = w.AddNewEncryptionToActiveWallet(newScheme, true)
	if err == nil {
		t.Fatal("portfel bez frazy wygenerował losowy klucz dla nowego schematu zamiast odmówić")
	}
	if !strings.Contains(err.Error(), newScheme) {
		t.Fatalf("komunikat nie nazywa nowego schematu %q: %v", newScheme, err)
	}
	for _, want := range []string{"recovery phrase", "wallet-file backup"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("komunikat nie mówi operatorowi o %q: %v", want, err)
		}
	}
	if w.Account1.Address.GetHex() != addressBefore {
		t.Fatalf("odmowa mimo to podmieniła tożsamość: %s -> %s", addressBefore, w.Account1.Address.GetHex())
	}
}

package wallet

import (
	"bytes"
	"strings"
	"testing"
)

// TestGetMnemonicWordsReturnsThePhraseThatCreatedTheWallet replaces the old
// CW-M2 behaviour. The phrase is no longer an encoding of the secret key — which
// is impossible for post-quantum keys — but the input the wallet was built from.
func TestGetMnemonicWordsReturnsThePhraseThatCreatedTheWallet(t *testing.T) {
	mnemonic, err := NewMnemonic24()
	if err != nil {
		t.Fatal(err)
	}
	w := newSeedTestWallet(t, 220)
	if err := w.SetMnemonic(mnemonic); err != nil {
		t.Fatal(err)
	}
	fillAccountsFromSeed(t, w)

	got, err := w.GetMnemonicWords(true)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(mnemonic) {
		t.Fatalf("the returned phrase differs from the one given at creation")
	}
	if n := len(strings.Fields(got)); n != MnemonicWordCount {
		t.Fatalf("word count = %d, expected %d", n, MnemonicWordCount)
	}
}

// TestGetMnemonicWordsOnLegacyWalletExplainsWhy: a wallet created before this
// feature has no phrase and never can — the caller must be told to back up the
// file instead.
func TestGetMnemonicWordsOnLegacyWalletExplainsWhy(t *testing.T) {
	w := newSeedTestWallet(t, 221)
	_, err := w.GetMnemonicWords(true)
	if err == nil {
		t.Fatal("expected an error for a wallet with no phrase")
	}
	if !strings.Contains(err.Error(), "wallet-file") {
		t.Fatalf("message %q does not point at the wallet-file backup", err.Error())
	}
}

func TestRestoreFromMnemonicRebuildsTheSameKeys(t *testing.T) {
	mnemonic, err := NewMnemonic24()
	if err != nil {
		t.Fatal(err)
	}
	original := newSeedTestWallet(t, 222)
	if err := original.SetMnemonic(mnemonic); err != nil {
		t.Fatal(err)
	}
	fillAccountsFromSeed(t, original)

	restored := newSeedTestWallet(t, 222)
	if err := restored.RestoreSecretKeyFromMnemonic(string(mnemonic), true); err != nil {
		t.Fatal(err)
	}
	if err := restored.RestoreSecretKeyFromMnemonic(string(mnemonic), false); err != nil {
		t.Fatal(err)
	}

	if restored.Account1.Address.GetHex() != original.Account1.Address.GetHex() {
		t.Fatal("the restored primary key has a different address")
	}
	if restored.Account2.Address.GetHex() != original.Account2.Address.GetHex() {
		t.Fatal("the restored secondary key has a different address")
	}

	sig, err := restored.Sign([]byte("qwid"), true)
	if err != nil {
		t.Fatal(err)
	}
	if !Verify([]byte("qwid"), sig.GetBytes(), original.Account1.PublicKey.GetBytes(),
		original.SigName, original.SigName2, false, false) {
		t.Fatal("a signature made with the restored key does not verify against the original public key")
	}
}

func TestRestoreFromMnemonicRejectsBadPhrase(t *testing.T) {
	w := newSeedTestWallet(t, 223)
	if err := w.RestoreSecretKeyFromMnemonic("abandon abandon abandon", true); err == nil {
		t.Fatal("expected an error for a phrase of the wrong length")
	}
}

// TestRestoreFromMnemonicTwiceRebuildsBothAccountsFromTheSecondPhrase covers
// the fund-loss bug: restoring only the secondary role from a second, different
// phrase must still rebuild BOTH accounts from that second phrase — the phrase
// GetMnemonicWords hands back afterwards has to actually reconstruct the whole
// wallet, not just the role the caller happened to ask for.
func TestRestoreFromMnemonicTwiceRebuildsBothAccountsFromTheSecondPhrase(t *testing.T) {
	mnemonicA, err := NewMnemonic24()
	if err != nil {
		t.Fatal(err)
	}
	mnemonicB, err := NewMnemonic24()
	if err != nil {
		t.Fatal(err)
	}

	w := newSeedTestWallet(t, 224)
	if err := w.RestoreSecretKeyFromMnemonic(string(mnemonicA), true); err != nil {
		t.Fatal(err)
	}
	if err := w.RestoreSecretKeyFromMnemonic(string(mnemonicB), false); err != nil {
		t.Fatal(err)
	}

	wantB := newSeedTestWallet(t, 225)
	if err := wantB.SetMnemonic(mnemonicB); err != nil {
		t.Fatal(err)
	}
	fillAccountsFromSeed(t, wantB)

	got, err := w.GetMnemonicWords(true)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(mnemonicB) {
		t.Fatalf("GetMnemonicWords returned a phrase other than the one last set (phrase B)")
	}
	if w.Account1.Address.GetHex() != wantB.Account1.Address.GetHex() {
		t.Fatalf("Account1 does not match phrase B after the second restore (partial restore bug)")
	}
	if w.Account2.Address.GetHex() != wantB.Account2.Address.GetHex() {
		t.Fatalf("Account2 does not match phrase B after the second restore")
	}
}

// TestRestoreFromMnemonicUpdatesMainAddress covers the MainAddress-stale bug:
// restoring the primary key of an already-initialised wallet (MainAddress
// already set to something else) must repoint MainAddress at the new
// Account1, not leave it pointing at the old address the new key never had.
func TestRestoreFromMnemonicUpdatesMainAddress(t *testing.T) {
	w := newSeedTestWallet(t, 226)
	acc1, err := GenerateNewAccount(*w, w.SigName)
	if err != nil {
		t.Fatal(err)
	}
	w.MainAddress = acc1.Address
	acc1.PublicKey.MainAddress = w.MainAddress
	w.Account1 = acc1
	acc2, err := GenerateNewAccount(*w, w.SigName2)
	if err != nil {
		t.Fatal(err)
	}
	w.Account2 = acc2
	oldMainAddress := w.MainAddress.GetHex()

	mnemonic, err := NewMnemonic24()
	if err != nil {
		t.Fatal(err)
	}
	if err := w.RestoreSecretKeyFromMnemonic(string(mnemonic), true); err != nil {
		t.Fatal(err)
	}

	if w.MainAddress.GetHex() == oldMainAddress {
		t.Fatal("MainAddress was not updated after the restore (stale-MainAddress bug)")
	}
	if w.MainAddress.GetHex() != w.Account1.Address.GetHex() {
		t.Fatalf("MainAddress (%s) differs from Account1.Address (%s) after the restore",
			w.MainAddress.GetHex(), w.Account1.Address.GetHex())
	}
}

// TestRestoreFromMnemonicIsRoleIndependent: since one phrase now covers the
// whole wallet, the ignored `primary` parameter must not change the outcome —
// restoring with primary=true or primary=false from the same phrase must
// produce byte-identical wallets. This is also what makes the operation safe
// to call twice in a row (once per role), as cmd/gui/qtwidgets/wallet.go does.
func TestRestoreFromMnemonicIsRoleIndependent(t *testing.T) {
	mnemonic, err := NewMnemonic24()
	if err != nil {
		t.Fatal(err)
	}

	wTrue := newSeedTestWallet(t, 227)
	if err := wTrue.RestoreSecretKeyFromMnemonic(string(mnemonic), true); err != nil {
		t.Fatal(err)
	}
	wFalse := newSeedTestWallet(t, 228)
	if err := wFalse.RestoreSecretKeyFromMnemonic(string(mnemonic), false); err != nil {
		t.Fatal(err)
	}

	if wTrue.Account1.Address.GetHex() != wFalse.Account1.Address.GetHex() {
		t.Fatal("Account1 depends on the primary value passed to restore")
	}
	if wTrue.Account2.Address.GetHex() != wFalse.Account2.Address.GetHex() {
		t.Fatal("Account2 depends on the primary value passed to restore")
	}
	if wTrue.MainAddress.GetHex() != wFalse.MainAddress.GetHex() {
		t.Fatal("MainAddress depends on the primary value passed to restore")
	}
}

// TestRestoreFromMnemonicLeavesWalletUnchangedOnBadPhrase: a failed restore
// (bad phrase) must not touch Account1, Account2, MainAddress or the stored
// EncryptedMnemonic — the wallet must come out byte-for-byte as it went in.
func TestRestoreFromMnemonicLeavesWalletUnchangedOnBadPhrase(t *testing.T) {
	mnemonic, err := NewMnemonic24()
	if err != nil {
		t.Fatal(err)
	}
	w := newSeedTestWallet(t, 229)
	if err := w.SetMnemonic(mnemonic); err != nil {
		t.Fatal(err)
	}
	fillAccountsFromSeed(t, w)

	wantAccount1 := w.Account1.Address.GetHex()
	wantAccount2 := w.Account2.Address.GetHex()
	wantMain := w.MainAddress.GetHex()
	wantEncMnemonic := append([]byte(nil), w.EncryptedMnemonic...)

	if err := w.RestoreSecretKeyFromMnemonic("abandon abandon abandon", true); err == nil {
		t.Fatal("expected an error for a phrase of the wrong length")
	}

	if w.Account1.Address.GetHex() != wantAccount1 {
		t.Fatal("Account1 changed despite an invalid phrase")
	}
	if w.Account2.Address.GetHex() != wantAccount2 {
		t.Fatal("Account2 changed despite an invalid phrase")
	}
	if w.MainAddress.GetHex() != wantMain {
		t.Fatal("MainAddress changed despite an invalid phrase")
	}
	if !bytes.Equal(w.EncryptedMnemonic, wantEncMnemonic) {
		t.Fatal("EncryptedMnemonic changed despite an invalid phrase")
	}
}

// TestRestoreFromMnemonicLeavesWalletUnchangedOnDerivationFailure covers the
// same fund-loss shape as the partial-restore bug, but triggered by a
// mid-operation derivation failure instead of a bad phrase: the phrase can be
// perfectly valid and still fail to produce a key, e.g. because the network
// has voted in a signature scheme this build of liboqs does not support
// (loadKeys already has to handle exactly that case). A restore that commits
// the new seed/EncryptedMnemonic before deriving both accounts would leave
// the stored phrase pointing at keys the wallet doesn't actually hold.
func TestRestoreFromMnemonicLeavesWalletUnchangedOnDerivationFailure(t *testing.T) {
	original, err := NewMnemonic24()
	if err != nil {
		t.Fatal(err)
	}
	w := newSeedTestWallet(t, 230)
	if err := w.SetMnemonic(original); err != nil {
		t.Fatal(err)
	}
	fillAccountsFromSeed(t, w)

	wantAccount1 := w.Account1.Address.GetHex()
	wantAccount2 := w.Account2.Address.GetHex()
	wantMain := w.MainAddress.GetHex()
	wantEncMnemonic := append([]byte(nil), w.EncryptedMnemonic...)

	// A scheme name liboqs does not support: acc1 (SigName, unchanged) derives
	// fine, acc2 (SigName2) fails — exactly the partway-through case.
	w.SigName2 = "No-Such-Scheme-42"

	other, err := NewMnemonic24()
	if err != nil {
		t.Fatal(err)
	}
	if err := w.RestoreSecretKeyFromMnemonic(string(other), true); err == nil {
		t.Fatal("expected an error for an unsupported signature scheme")
	}

	got, err := w.GetMnemonicWords(true)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(original) {
		t.Fatalf("GetMnemonicWords returned a new phrase even though key derivation failed")
	}
	if w.Account1.Address.GetHex() != wantAccount1 {
		t.Fatal("Account1 changed even though key derivation failed")
	}
	if w.Account2.Address.GetHex() != wantAccount2 {
		t.Fatal("Account2 changed even though key derivation failed")
	}
	if w.MainAddress.GetHex() != wantMain {
		t.Fatal("MainAddress changed even though key derivation failed")
	}
	if !bytes.Equal(w.EncryptedMnemonic, wantEncMnemonic) {
		t.Fatal("EncryptedMnemonic changed even though key derivation failed")
	}
}

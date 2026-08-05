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
		t.Fatalf("zwrócona fraza różni się od podanej przy tworzeniu")
	}
	if n := len(strings.Fields(got)); n != MnemonicWordCount {
		t.Fatalf("liczba słów = %d, oczekiwano %d", n, MnemonicWordCount)
	}
}

// TestGetMnemonicWordsOnLegacyWalletExplainsWhy: a wallet created before this
// feature has no phrase and never can — the caller must be told to back up the
// file instead.
func TestGetMnemonicWordsOnLegacyWalletExplainsWhy(t *testing.T) {
	w := newSeedTestWallet(t, 221)
	_, err := w.GetMnemonicWords(true)
	if err == nil {
		t.Fatal("oczekiwano błędu dla portfela bez frazy")
	}
	if !strings.Contains(err.Error(), "wallet-file") {
		t.Fatalf("komunikat %q nie kieruje do kopii pliku portfela", err.Error())
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
		t.Fatal("odtworzony klucz podstawowy ma inny adres")
	}
	if restored.Account2.Address.GetHex() != original.Account2.Address.GetHex() {
		t.Fatal("odtworzony klucz dodatkowy ma inny adres")
	}

	sig, err := restored.Sign([]byte("qwid"), true)
	if err != nil {
		t.Fatal(err)
	}
	if !Verify([]byte("qwid"), sig.GetBytes(), original.Account1.PublicKey.GetBytes(),
		original.SigName, original.SigName2, false, false) {
		t.Fatal("podpis odtworzonym kluczem nie weryfikuje się oryginalnym kluczem publicznym")
	}
}

func TestRestoreFromMnemonicRejectsBadPhrase(t *testing.T) {
	w := newSeedTestWallet(t, 223)
	if err := w.RestoreSecretKeyFromMnemonic("abandon abandon abandon", true); err == nil {
		t.Fatal("oczekiwano błędu dla frazy o złej długości")
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
		t.Fatalf("GetMnemonicWords zwróciła frazę inną niż ostatnio ustawiona (fraza B)")
	}
	if w.Account1.Address.GetHex() != wantB.Account1.Address.GetHex() {
		t.Fatalf("Account1 nie odpowiada frazie B po drugim restore (partial restore bug)")
	}
	if w.Account2.Address.GetHex() != wantB.Account2.Address.GetHex() {
		t.Fatalf("Account2 nie odpowiada frazie B po drugim restore")
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
		t.Fatal("MainAddress nie została zaktualizowana po restore (stale-MainAddress bug)")
	}
	if w.MainAddress.GetHex() != w.Account1.Address.GetHex() {
		t.Fatalf("MainAddress (%s) różni się od Account1.Address (%s) po restore",
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
		t.Fatal("Account1 zależy od wartości primary przekazanej do restore")
	}
	if wTrue.Account2.Address.GetHex() != wFalse.Account2.Address.GetHex() {
		t.Fatal("Account2 zależy od wartości primary przekazanej do restore")
	}
	if wTrue.MainAddress.GetHex() != wFalse.MainAddress.GetHex() {
		t.Fatal("MainAddress zależy od wartości primary przekazanej do restore")
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
		t.Fatal("oczekiwano błędu dla frazy o złej długości")
	}

	if w.Account1.Address.GetHex() != wantAccount1 {
		t.Fatal("Account1 zmienił się mimo błędnej frazy")
	}
	if w.Account2.Address.GetHex() != wantAccount2 {
		t.Fatal("Account2 zmienił się mimo błędnej frazy")
	}
	if w.MainAddress.GetHex() != wantMain {
		t.Fatal("MainAddress zmienił się mimo błędnej frazy")
	}
	if !bytes.Equal(w.EncryptedMnemonic, wantEncMnemonic) {
		t.Fatal("EncryptedMnemonic zmienił się mimo błędnej frazy")
	}
}

package wallet

import (
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

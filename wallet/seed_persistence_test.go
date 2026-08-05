package wallet

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/wonabru/qwid-node/common"
)

// newTestWallet builds a wallet whose files land in a throwaway directory.
func newSeedTestWallet(t *testing.T, number uint8) *Wallet {
	t.Helper()
	w := EmptyWallet(number, common.SigName(), common.SigName2())
	w.HomePath = t.TempDir()
	w.SetPassword("test-password-123")
	w.Iv = GenerateNewIv()
	return &w
}

func fillAccountsFromSeed(t *testing.T, w *Wallet) {
	t.Helper()
	acc, err := GenerateNewAccountFromSeed(*w, w.SigName, true)
	if err != nil {
		t.Fatal(err)
	}
	w.MainAddress = acc.Address
	acc.PublicKey.MainAddress = w.MainAddress
	w.Account1 = acc

	acc2, err := GenerateNewAccountFromSeed(*w, w.SigName2, false)
	if err != nil {
		t.Fatal(err)
	}
	w.Account2 = acc2
}

func TestSetMnemonicRejectsInvalidPhrase(t *testing.T) {
	w := newSeedTestWallet(t, 200)
	if err := w.SetMnemonic([]byte("not a real phrase")); err == nil {
		t.Fatal("oczekiwano błędu dla nieprawidłowej frazy")
	}
	if w.HasSeed() {
		t.Fatal("portfel ma ziarno mimo odrzuconej frazy")
	}
}

func TestSeededWalletIsReproducibleFromPhrase(t *testing.T) {
	mnemonic, err := NewMnemonic24()
	if err != nil {
		t.Fatal(err)
	}

	w1 := newSeedTestWallet(t, 201)
	if err := w1.SetMnemonic(mnemonic); err != nil {
		t.Fatal(err)
	}
	fillAccountsFromSeed(t, w1)

	w2 := newSeedTestWallet(t, 201)
	if err := w2.SetMnemonic(mnemonic); err != nil {
		t.Fatal(err)
	}
	fillAccountsFromSeed(t, w2)

	if w1.MainAddress.GetHex() != w2.MainAddress.GetHex() {
		t.Fatalf("ta sama fraza dała różne adresy: %s vs %s",
			w1.MainAddress.GetHex(), w2.MainAddress.GetHex())
	}
	if w1.Account2.Address.GetHex() != w2.Account2.Address.GetHex() {
		t.Fatal("ta sama fraza dała różne adresy drugiego konta")
	}
}

func TestDifferentPhrasesGiveDifferentWallets(t *testing.T) {
	m1, err := NewMnemonic24()
	if err != nil {
		t.Fatal(err)
	}
	m2, err := NewMnemonic24()
	if err != nil {
		t.Fatal(err)
	}

	w1 := newSeedTestWallet(t, 202)
	if err := w1.SetMnemonic(m1); err != nil {
		t.Fatal(err)
	}
	fillAccountsFromSeed(t, w1)

	w2 := newSeedTestWallet(t, 202)
	if err := w2.SetMnemonic(m2); err != nil {
		t.Fatal(err)
	}
	fillAccountsFromSeed(t, w2)

	if w1.MainAddress.GetHex() == w2.MainAddress.GetHex() {
		t.Fatal("różne frazy dały ten sam adres")
	}
}

func TestMnemonicSurvivesStoreAndLoad(t *testing.T) {
	mnemonic, err := NewMnemonic24()
	if err != nil {
		t.Fatal(err)
	}
	w := newSeedTestWallet(t, 203)
	if err := w.SetMnemonic(mnemonic); err != nil {
		t.Fatal(err)
	}
	fillAccountsFromSeed(t, w)
	if err := w.StoreJSON(); err != nil {
		t.Fatal(err)
	}
	if len(w.EncryptedMnemonic) == 0 {
		t.Fatal("StoreJSON nie zapisał zaszyfrowanej frazy")
	}

	loaded, err := LoadJSONFromDir(w.HomePath, 203, "test-password-123", w.SigName, w.SigName2)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.HasSeed() {
		t.Fatal("wczytany portfel nie ma ziarna")
	}
	if loaded.MainAddress.GetHex() != w.MainAddress.GetHex() {
		t.Fatal("adres zmienił się po zapisie i odczycie")
	}
}

func TestLegacyWalletLoadsWithoutSeed(t *testing.T) {
	w := newSeedTestWallet(t, 204)
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

	if err := w.StoreJSON(); err != nil {
		t.Fatal(err)
	}

	data, err := readWalletFile(t, w.HomePath, 204)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(data, "encrypted_mnemonic") {
		t.Fatal("portfel bez frazy zapisał puste pole encrypted_mnemonic — brakuje omitempty")
	}

	loaded, err := LoadJSONFromDir(w.HomePath, 204, "test-password-123", w.SigName, w.SigName2)
	if err != nil {
		t.Fatalf("portfel starego typu nie wczytał się: %v", err)
	}
	if loaded.HasSeed() {
		t.Fatal("portfel starego typu zgłasza posiadanie ziarna")
	}
	if _, err := loaded.Sign([]byte("qwid"), true); err != nil {
		t.Fatalf("portfel starego typu nie podpisuje: %v", err)
	}
}

func TestWipeClearsSeed(t *testing.T) {
	mnemonic, err := NewMnemonic24()
	if err != nil {
		t.Fatal(err)
	}
	w := newSeedTestWallet(t, 205)
	if err := w.SetMnemonic(mnemonic); err != nil {
		t.Fatal(err)
	}
	fillAccountsFromSeed(t, w)

	w.Wipe()
	if w.HasSeed() {
		t.Fatal("Wipe nie wyczyścił ziarna")
	}
}

func readWalletFile(t *testing.T, dir string, number uint8) (string, error) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "wallet"+strconv.Itoa(int(number))+".json"))
	return string(b), err
}

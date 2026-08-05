package wallet

import (
	"testing"

	"github.com/wonabru/qwid-node/common"
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

// TestSchemeChangeStaysRandomWithoutPhrase keeps pre-existing wallets on their
// previous behaviour.
func TestSchemeChangeStaysRandomWithoutPhrase(t *testing.T) {
	newScheme := common.SigName2()

	addr := func() string {
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
		if err := w.AddNewEncryptionToActiveWallet(newScheme, true); err != nil {
			t.Fatal(err)
		}
		return w.Account1.Address.GetHex()
	}

	if addr() == addr() {
		t.Fatal("portfel bez frazy dał ten sam klucz dwa razy — generowanie przestało być losowe")
	}
}

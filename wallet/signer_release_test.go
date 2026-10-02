package wallet

import (
	"testing"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/crypto/oqs"
)

// S5-03: replacing the key for a new scheme releases the previous signer's C
// context and cleanses the secret key it holds, instead of leaking both.
func TestSchemeChangeReleasesPreviousSigner(t *testing.T) {
	mnemonic, err := NewMnemonic24()
	if err != nil {
		t.Fatal(err)
	}
	w := newSeedTestWallet(t, 211)
	if err := w.SetMnemonic(mnemonic); err != nil {
		t.Fatal(err)
	}
	fillAccountsFromSeed(t, w)

	released := 0
	saved := releaseSigner
	releaseSigner = func(s *oqs.Signature) { released++; saved(s) }
	defer func() { releaseSigner = saved }()

	if err := w.AddNewEncryptionToActiveWallet(common.SigName2(), true); err != nil {
		t.Fatal(err)
	}
	if released != 1 {
		t.Fatalf("previous signer released %d times, want 1", released)
	}
}

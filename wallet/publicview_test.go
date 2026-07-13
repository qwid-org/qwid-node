package wallet

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPublicViewRedactsEncryptionMaterial(t *testing.T) {
	w := &Wallet{
		Iv:           []byte("legacy-iv-bytes"),
		KdfSalt:      []byte("argon2id-salt-16"),
		HomePath:     "/home/user/.qwid",
		WalletNumber: 7,
		SigName:      "Falcon-512",
		SigName2:     "MAYO-5",
	}
	w.Account1.EncryptedSecretKey = []byte("ENCRYPTED-SECRET-1")
	w.Account2.EncryptedSecretKey = []byte("ENCRYPTED-SECRET-2")

	b, err := json.Marshal(w.PublicView())
	if err != nil {
		t.Fatalf("marshal PublicView: %v", err)
	}
	s := string(b)

	// The encryption material and local path must be absent.
	for _, leak := range []string{"kdf_salt", "encrypted_secret_key", "\"iv\"", "home_path", "\"accounts\""} {
		if strings.Contains(s, leak) {
			t.Fatalf("PublicView JSON leaks %q:\n%s", leak, s)
		}
	}
	// The public identity fields must be present.
	for _, keep := range []string{"wallet_number", "main_address", "sig_name", "public_key", "account_1"} {
		if !strings.Contains(s, keep) {
			t.Fatalf("PublicView JSON missing %q:\n%s", keep, s)
		}
	}
}

func TestPublicViewNilSafe(t *testing.T) {
	var w *Wallet
	_ = w.PublicView() // must not panic
}

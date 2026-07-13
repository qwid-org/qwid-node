package wallet

import (
	"bytes"
	"testing"
)

// TestEncryptDoesNotRetainPlaintext proves that Wallet.encrypt captures its
// input by value: cleansing the plaintext slice after encrypt returns must not
// affect the ciphertext, which must still decrypt to the original. This is the
// invariant that makes the CW-H2 ephemeral `ds` cleanse safe. Pure AES-GCM, no CGO.
func TestEncryptDoesNotRetainPlaintext(t *testing.T) {
	w := &Wallet{passwordBytes: make([]byte, 32)} // AES-256 key (zeros are fine for a round-trip test)
	orig := []byte("super-secret-key-material-1234567")
	ds := append([]byte(nil), orig...)

	se, err := w.encrypt(ds)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	// Cleanse ds exactly as the CW-H2 fix does after re-encrypting.
	for i := range ds {
		ds[i] = 0
	}
	dec, err := w.decrypt(se)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(dec, orig) {
		t.Fatalf("decrypt after cleansing ds = %q, want %q", dec, orig)
	}
}

package wallet

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// TestEncryptWithKeyRoundTrip proves encryptWithKey encrypts under the GIVEN key
// (independent of w.passwordBytes), and the ciphertext decrypts back with that key.
func TestEncryptWithKeyRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	w := &Wallet{}
	plain := []byte("secret-key-material-xyz")

	se, err := w.encryptWithKey(key, plain)
	if err != nil {
		t.Fatalf("encryptWithKey: %v", err)
	}
	// decrypt reads w.passwordBytes; set it to the same key and round-trip.
	w.passwordBytes = key
	dec, err := w.decrypt(se)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(dec, plain) {
		t.Fatalf("round-trip mismatch: %q != %q", dec, plain)
	}
}

// TestEncryptWithKeyWrongKeyFails proves ciphertext from key K1 does not decrypt
// under a different key (GCM auth fails; the legacy fallback also errors with no Iv).
func TestEncryptWithKeyWrongKeyFails(t *testing.T) {
	w := &Wallet{}
	k1 := make([]byte, 32)
	k2 := make([]byte, 32)
	k2[0] = 0xff

	se, err := w.encryptWithKey(k1, []byte("data-to-protect"))
	if err != nil {
		t.Fatal(err)
	}
	w.passwordBytes = k2 // wrong key; w.Iv is nil, so the legacy fallback errors too
	if _, err := w.decrypt(se); err == nil {
		t.Fatal("decrypt with the wrong key must fail")
	}
}

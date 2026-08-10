package wallet

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"testing"

	"github.com/wonabru/qwid-node/common"
)

// newTestWallet builds a minimal Wallet with just the fields encrypt/decrypt use.
func newTestWallet(password string) *Wallet {
	w := &Wallet{}
	w.SetPassword(password)
	w.Iv = GenerateNewIv()
	return w
}

// TestEncryptDecryptRoundTrip verifies AES-GCM encryption round-trips correctly.
func TestEncryptDecryptRoundTrip(t *testing.T) {
	w := newTestWallet("correct horse battery staple")
	secret := []byte("this is a secret private key blob")

	ct, err := w.encrypt(secret)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}
	pt, err := w.decrypt(ct)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	if !bytes.Equal(pt, secret) {
		t.Fatalf("round-trip mismatch: got %q want %q", pt, secret)
	}
}

// TestEncryptUsesFreshNonce verifies CW-C2: two encryptions of the same plaintext
// never produce the same ciphertext (no IV/nonce reuse).
func TestEncryptUsesFreshNonce(t *testing.T) {
	w := newTestWallet("pw")
	secret := []byte("same plaintext")

	a, err := w.encrypt(secret)
	if err != nil {
		t.Fatal(err)
	}
	b, err := w.encrypt(secret)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("two encryptions produced identical ciphertext: nonce reuse")
	}
}

// TestDecryptDetectsTampering verifies CW-C1: flipping a ciphertext bit is
// detected by GCM authentication rather than silently returning altered data.
func TestDecryptDetectsTampering(t *testing.T) {
	w := newTestWallet("pw")
	ct, err := w.encrypt([]byte("integrity matters"))
	if err != nil {
		t.Fatal(err)
	}
	ct[len(ct)-1] ^= 0x01 // flip a bit in the auth tag / ciphertext
	if _, err := w.decrypt(ct); err == nil {
		t.Fatal("tampered ciphertext decrypted without error (no authentication)")
	}
}

// TestWrongPasswordFails verifies a wrong password does not decrypt.
func TestWrongPasswordFails(t *testing.T) {
	w := newTestWallet("right")
	ct, err := w.encrypt([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	w2 := newTestWallet("wrong")
	if _, err := w2.decrypt(ct); err == nil {
		t.Fatal("wrong password decrypted ciphertext")
	}
}

// TestArgon2idKDF verifies CW-C3: SetPassword derives the key with Argon2id and
// a stored random salt, so two wallets with the same password get different keys.
func TestArgon2idKDF(t *testing.T) {
	w1 := &Wallet{}
	w1.SetPassword("same-password")
	w2 := &Wallet{}
	w2.SetPassword("same-password")

	if len(w1.KdfSalt) != kdfSaltLen {
		t.Fatalf("expected %d-byte salt, got %d", kdfSaltLen, len(w1.KdfSalt))
	}
	if bytes.Equal(w1.KdfSalt, w2.KdfSalt) {
		t.Fatal("two wallets got the same salt")
	}
	if bytes.Equal(w1.passwordBytes, w2.passwordBytes) {
		t.Fatal("same password + different salt produced the same key")
	}
	// Deterministic for a fixed salt.
	if !bytes.Equal(w1.passwordBytes, argon2Key("same-password", w1.KdfSalt)) {
		t.Fatal("Argon2id derivation is not deterministic for a fixed salt")
	}
}

// TestVerifyPassword verifies WH-C5's re-auth helper accepts the correct
// password and rejects wrong ones.
func TestVerifyPassword(t *testing.T) {
	w := newTestWallet("s3cretpass")
	if !w.VerifyPassword("s3cretpass") {
		t.Fatal("correct password rejected")
	}
	if w.VerifyPassword("wrongpass") {
		t.Fatal("wrong password accepted")
	}
	if w.VerifyPassword("") {
		t.Fatal("empty password accepted")
	}
}

// TestLegacyCTRDecrypt verifies backward compatibility: a wallet secret written
// in the old AES-CTR format still decrypts via the fallback path.
func TestLegacyCTRDecrypt(t *testing.T) {
	password := "legacy-pw"
	w := newTestWallet(password)
	secret := []byte("legacy secret key material")

	// Reproduce the old on-disk format: AES-CTR with legacy SHAKE key, static
	// wallet IV, "validationTag" prefix, and a dead 16-byte leading block.
	cb, err := aes.NewCipher(legacyPasswordToByte(password))
	if err != nil {
		t.Fatal(err)
	}
	v := append([]byte(common.ValidationTag), secret...)
	legacyBlob := make([]byte, aes.BlockSize+len(v))
	stream := cipher.NewCTR(cb, w.Iv)
	stream.XORKeyStream(legacyBlob[aes.BlockSize:], v)

	pt, err := w.decrypt(legacyBlob)
	if err != nil {
		t.Fatalf("legacy decrypt failed: %v", err)
	}
	if !bytes.Equal(pt, secret) {
		t.Fatalf("legacy round-trip mismatch: got %q want %q", pt, secret)
	}
}

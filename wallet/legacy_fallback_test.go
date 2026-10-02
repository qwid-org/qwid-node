package wallet

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"testing"

	"github.com/qwid-org/qwid-node/common"
)

func legacyCiphertext(t *testing.T, password string, iv, secret []byte) []byte {
	t.Helper()
	cb, err := aes.NewCipher(legacyPasswordToByte(password))
	if err != nil {
		t.Fatal(err)
	}
	pt := append([]byte(common.ValidationTag), secret...)
	ct := make([]byte, len(pt))
	cipher.NewCTR(cb, iv).XORKeyStream(ct, pt)
	return append(make([]byte, aes.BlockSize), ct...)
}

// S5-04: the unauthenticated, KDF-less AES-CTR format is read only for a
// wallet file that predates the Argon2id migration (no kdf_salt when it was
// loaded). A migrated wallet never falls back to it, so it offers no fast
// offline password check.
func TestLegacyCTRFallbackOnlyForUnmigratedWallets(t *testing.T) {
	iv := bytes.Repeat([]byte{7}, aes.BlockSize)
	secret := []byte("secret-key-bytes")
	ct := legacyCiphertext(t, "correct horse", iv, secret)

	legacy := &Wallet{Iv: iv, legacyKeys: true}
	legacy.SetPassword("correct horse")
	if got, err := legacy.decrypt(ct); err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("an unmigrated wallet must still open: %q, %v", got, err)
	}

	migrated := &Wallet{Iv: iv}
	migrated.SetPassword("correct horse")
	if _, err := migrated.decrypt(ct); err == nil {
		t.Fatal("a migrated wallet fell back to the legacy format")
	}
}

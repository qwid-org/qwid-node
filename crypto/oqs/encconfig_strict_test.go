package oqs

import "testing"

// S5-01: the config is exactly totalLength bytes. Trailing bytes used to be
// ignored while still keying the cache, so every distinct tail added a
// permanent cache entry and a key generation.
func TestEncryptionConfigRejectsTrailingBytes(t *testing.T) {
	c := NewConfigEnc2()
	base, err := GenerateBytesFromParams(c.SigName, c.PubKeyLength, c.PrivateKeyLength, c.SignatureLength, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := FromBytesToEncryptionConfig(base); err != nil {
		t.Fatalf("the canonical encoding was rejected: %v", err)
	}
	if _, err := FromBytesToEncryptionConfig(append(append([]byte{}, base...), 0xAB)); err == nil {
		t.Fatal("an encoding with a trailing byte was accepted")
	}
}

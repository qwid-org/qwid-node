package wallet

import "testing"

// TestWipeCleansesSecretKeys verifies Wipe() zeroes the retained secret-key
// bytes (CW-H2) in addition to the password (CW-C4). Zero-value signers are
// used; Wipe()'s signer.Clean() is nil-safe on them (only OQS_SIG_free(nil)),
// so no real key material or algorithm init is needed.
func TestWipeCleansesSecretKeys(t *testing.T) {
	w := &Wallet{}
	w.password = []byte{4, 5}
	w.passwordBytes = []byte{1, 2, 3}
	w.Account1.secretKey.ByteValue = []byte{7, 7, 7, 7}
	w.Account2.secretKey.ByteValue = []byte{9, 9}
	bv1 := w.Account1.secretKey.ByteValue // capture backing arrays
	bv2 := w.Account2.secretKey.ByteValue

	w.Wipe()

	for i, b := range bv1 {
		if b != 0 {
			t.Fatalf("Account1 secret byte %d = %d, want 0", i, b)
		}
	}
	for i, b := range bv2 {
		if b != 0 {
			t.Fatalf("Account2 secret byte %d = %d, want 0", i, b)
		}
	}
	if w.passwordBytes != nil {
		t.Fatal("passwordBytes must be nil after Wipe (CW-C4 preserved)")
	}
}

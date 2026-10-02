package nonceServices

import "testing"

// S2-08: a valid nonce replayed many times must be acted on once - each
// replay used to rebuild a candidate block.
func TestNonceIsProcessedOnce(t *testing.T) {
	resetSeenNonces()
	defer resetSeenNonces()
	var h [32]byte
	h[0] = 1
	if !claimNonce(h, 11, 10) {
		t.Fatal("first sight refused")
	}
	if claimNonce(h, 11, 10) {
		t.Fatal("replay accepted")
	}
	var other [32]byte
	other[0] = 2
	if !claimNonce(other, 11, 10) {
		t.Fatal("a different nonce refused")
	}
	// entries for heights below the tip are pruned
	claimNonce([32]byte{3}, 30, 29)
	seenNoncesMu.Lock()
	_, stale := seenNonces[h]
	seenNoncesMu.Unlock()
	if stale {
		t.Fatal("nonces of old heights must be forgotten")
	}
}

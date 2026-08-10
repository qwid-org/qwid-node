package common

import "testing"

// TestRandomNonce verifies WH-M2: nonces are non-negative and not trivially
// repeating.
func TestRandomNonce(t *testing.T) {
	seen := make(map[int64]bool)
	for i := 0; i < 1000; i++ {
		n := RandomNonce()
		if n < 0 {
			t.Fatalf("RandomNonce returned negative: %d", n)
		}
		seen[n] = true
	}
	// With 63 bits of entropy, 1000 draws should essentially never collide.
	if len(seen) < 999 {
		t.Fatalf("RandomNonce produced too many collisions: %d unique of 1000", len(seen))
	}
}

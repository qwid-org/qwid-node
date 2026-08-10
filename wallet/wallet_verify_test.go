package wallet

import "testing"

func TestVerifyRejectsEmptyMessageNoPanic(t *testing.T) {
	// len(msg)<1 must be rejected at the top of wallet.Verify (pure Go, no CGO),
	// mirroring the existing len(sig)<1 guard. Must not panic.
	if Verify(nil, []byte{1}, make([]byte, 897), "Falcon-512", "MAYO-5", false, false) {
		t.Fatal("empty message must not verify")
	}
	if Verify([]byte{1}, nil, make([]byte, 897), "Falcon-512", "MAYO-5", false, false) {
		t.Fatal("empty signature must not verify")
	}
}

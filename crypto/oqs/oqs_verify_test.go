package oqs

import "testing"

func TestVerifyRejectsEmptyMessageOrSignatureNoPanic(t *testing.T) {
	var s Signature
	if err := s.Init("Falcon-512", nil); err != nil {
		t.Skipf("oqs Falcon unavailable: %v", err)
	}
	defer s.Clean()
	// empty message must return (false, error), never panic on &message[0]
	if ok, err := s.Verify(nil, []byte{1}, make([]byte, 897)); ok || err == nil {
		t.Fatalf("empty message: got ok=%v err=%v, want false + error", ok, err)
	}
	// empty signature likewise
	if ok, err := s.Verify([]byte{1}, nil, make([]byte, 897)); ok || err == nil {
		t.Fatalf("empty signature: got ok=%v err=%v, want false + error", ok, err)
	}
}

package tcpip

import (
	"bytes"
	"net"
	"testing"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/crypto/oqs"
	"github.com/qwid-org/qwid-node/wallet"
)

// newTestIdentity builds a real Falcon-512 identity for handshake tests.
func newTestIdentity(t *testing.T) HandshakeIdentity {
	t.Helper()
	return newTestIdentityWith(t, common.SigName())
}

// newTestIdentityWith builds a handshake identity signing with the named scheme.
func newTestIdentityWith(t *testing.T, sigName string) HandshakeIdentity {
	t.Helper()
	var s oqs.Signature
	if err := s.Init(sigName, nil); err != nil {
		t.Skipf("oqs %s init unavailable (CGO/liboqs): %v", sigName, err)
	}
	pub, err := s.GenerateKeyPair()
	if err != nil {
		t.Skipf("oqs GenerateKeyPair unavailable: %v", err)
	}
	addr, err := common.PubKeyToAddress(pub, true)
	if err != nil {
		t.Fatalf("PubKeyToAddress: %v", err)
	}
	return HandshakeIdentity{
		PubKey:  pub,
		Address: addr,
		Sign: func(d []byte) ([]byte, error) {
			raw, err := s.Sign(d)
			if err != nil {
				return nil, err
			}
			return append([]byte{0}, raw...), nil // scheme flag 0 = Falcon-512 primary
		},
	}
}

func TestHandshakeMutualAuth(t *testing.T) {
	a := newTestIdentity(t)
	b := newTestIdentity(t)
	ca, cb := net.Pipe()
	defer ca.Close()
	defer cb.Close()

	var respAddr common.Address
	var respErr error
	var respKeys *SessionKeys
	done := make(chan struct{})
	go func() { respAddr, respKeys, respErr = HandshakeResponder(cb, b); close(done) }()

	initAddr, initKeys, initErr := HandshakeInitiator(ca, a)
	<-done

	if initErr != nil || respErr != nil {
		t.Fatalf("handshake failed: init=%v resp=%v", initErr, respErr)
	}
	if initAddr != b.Address {
		t.Fatalf("initiator learned wrong peer nodeID: %x want %x", initAddr.ByteValue, b.Address.ByteValue)
	}
	if respAddr != a.Address {
		t.Fatalf("responder learned wrong peer nodeID: %x want %x", respAddr.ByteValue, a.Address.ByteValue)
	}
	if initKeys == nil || respKeys == nil {
		t.Fatal("expected non-nil session keys from both sides")
	}
}

// A peer that has already adopted a voted-in scheme this node does not run yet
// (e.g. Falcon-1024 after a primary-scheme change) must still complete the
// handshake in BOTH directions: the presented key is self-certifying and the
// signature is judged under the scheme matching that key, not the local chain
// configuration — otherwise the lagging node could never connect to sync the
// very blocks that would teach it the new scheme.
func TestHandshakeAcrossSchemeChange(t *testing.T) {
	local := newTestIdentity(t)                       // Falcon-512: local config
	upgraded := newTestIdentityWith(t, "Falcon-1024") // scheme the local config does not run

	for _, dir := range []struct {
		name                 string
		initiator, responder HandshakeIdentity
	}{
		{"upgraded responder", local, upgraded},
		{"upgraded initiator", upgraded, local},
	} {
		ca, cb := net.Pipe()
		var respAddr common.Address
		var respErr error
		done := make(chan struct{})
		go func() { respAddr, _, respErr = HandshakeResponder(cb, dir.responder); close(done) }()
		initAddr, _, initErr := HandshakeInitiator(ca, dir.initiator)
		<-done
		ca.Close()
		cb.Close()
		if initErr != nil || respErr != nil {
			t.Fatalf("%s: handshake failed: init=%v resp=%v", dir.name, initErr, respErr)
		}
		if initAddr != dir.responder.Address || respAddr != dir.initiator.Address {
			t.Fatalf("%s: wrong peer nodeIDs learned", dir.name)
		}
	}
}

func TestHandshakeDerivesMatchingSessionKeys(t *testing.T) {
	a := newTestIdentity(t)
	b := newTestIdentity(t)
	ca, cb := net.Pipe()
	defer ca.Close()
	defer cb.Close()
	var rAddr common.Address
	var rKeys *SessionKeys
	var rErr error
	done := make(chan struct{})
	go func() { rAddr, rKeys, rErr = HandshakeResponder(cb, b); close(done) }()
	iAddr, iKeys, iErr := HandshakeInitiator(ca, a)
	<-done
	if iErr != nil || rErr != nil {
		t.Fatalf("init=%v resp=%v", iErr, rErr)
	}
	if iAddr != b.Address || rAddr != a.Address {
		t.Fatal("wrong peer nodeID")
	}
	// initiator.Write == responder.Read and vice versa
	if !bytes.Equal(iKeys.WriteKey, rKeys.ReadKey) || !bytes.Equal(iKeys.ReadKey, rKeys.WriteKey) {
		t.Fatal("session keys do not mirror across the two sides")
	}
	if bytes.Equal(iKeys.WriteKey, iKeys.ReadKey) {
		t.Fatal("the two directional keys must differ")
	}
}

func TestKEMAlgAvailable(t *testing.T) {
	if kemAlg == "" {
		t.Skip("no KEM available in this liboqs build")
	}
	found := false
	for _, k := range oqs.EnabledKEMs() {
		if k == kemAlg {
			found = true
		}
	}
	if !found {
		t.Fatalf("selected KEM %q not in EnabledKEMs", kemAlg)
	}
}

func TestHandshakeRejectsTamperAndReplay(t *testing.T) {
	a := newTestIdentity(t)
	nI := bytes.Repeat([]byte{1}, 32)
	nR := bytes.Repeat([]byte{2}, 32)
	dummyKemPub := bytes.Repeat([]byte{3}, 8)
	dummyKemCt := bytes.Repeat([]byte{4}, 8)
	tr := handshakeTranscript(nI, nR, dummyKemPub, dummyKemCt, a.Address)
	sig, err := a.Sign(tr)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	verify := func(msg, s, pk []byte) bool {
		return wallet.Verify(msg, s, pk, common.SigName(), common.SigName2(), common.IsPaused(), common.IsPaused2())
	}
	if !verify(tr, sig, a.PubKey) {
		t.Fatal("valid handshake signature must verify")
	}
	// Tampered signature must be rejected (THE security assertion).
	bad := append([]byte(nil), sig...)
	bad[len(bad)-1] ^= 0xFF
	if verify(tr, bad, a.PubKey) {
		t.Fatal("tampered signature must NOT verify")
	}
	// Signature over a different session (different nonceR) must be rejected (replay/session binding).
	trOther := handshakeTranscript(nI, bytes.Repeat([]byte{9}, 32), dummyKemPub, dummyKemCt, a.Address)
	if verify(trOther, sig, a.PubKey) {
		t.Fatal("signature must not verify against a different transcript (replay)")
	}
}

// TestHandshakeTranscriptBindsKEMMaterial directly asserts the authenticated-KEM
// property: the KEM public key and ciphertext are bound into the signed
// handshake transcript, so a MITM that swaps either value breaks signature
// verification. Nonces and addr are held constant; only kemCt, then only
// kemPubI, are mutated between verifications.
func TestHandshakeTranscriptBindsKEMMaterial(t *testing.T) {
	id := newTestIdentity(t)
	nI := bytes.Repeat([]byte{0xAA}, 32)
	nR := bytes.Repeat([]byte{0xBB}, 32)
	kemPubI := bytes.Repeat([]byte{0xCC}, 16)
	kemCt := bytes.Repeat([]byte{0xDD}, 16)

	tr := handshakeTranscript(nI, nR, kemPubI, kemCt, id.Address)
	sig, err := id.Sign(tr)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Baseline: correct transcript must verify.
	if !verifyPeer(tr, sig, id.PubKey) {
		t.Fatal("valid transcript with correct KEM material must verify")
	}

	// Only kemCt changed (different byte slice, same length) -> must fail.
	swappedCt := bytes.Repeat([]byte{0xEE}, 16)
	trBadCt := handshakeTranscript(nI, nR, kemPubI, swappedCt, id.Address)
	if verifyPeer(trBadCt, sig, id.PubKey) {
		t.Fatal("signature must NOT verify when kemCt is swapped (MITM KEM-ciphertext substitution)")
	}

	// Only kemPubI changed -> must fail.
	swappedPub := bytes.Repeat([]byte{0xFF}, 16)
	trBadPub := handshakeTranscript(nI, nR, swappedPub, kemCt, id.Address)
	if verifyPeer(trBadPub, sig, id.PubKey) {
		t.Fatal("signature must NOT verify when kemPubI is swapped (MITM KEM-key substitution)")
	}
}

func TestHandshakeTranscriptDomainSeparated(t *testing.T) {
	dummyKemPub := bytes.Repeat([]byte{5}, 10)
	dummyKemCt := bytes.Repeat([]byte{6}, 12)
	tr := handshakeTranscript(bytes.Repeat([]byte{0}, 32), bytes.Repeat([]byte{0}, 32), dummyKemPub, dummyKemCt, common.Address{})
	if !bytes.HasPrefix(tr, []byte("QWID-P2P-HS-v1")) {
		t.Fatal("transcript must start with the domain tag QWID-P2P-HS-v1")
	}
	if len(tr) != len("QWID-P2P-HS-v1")+32+32+len(dummyKemPub)+len(dummyKemCt)+common.AddressLength {
		t.Fatalf("transcript length = %d, want tag+32+32+kemPub+kemCt+%d", len(tr), common.AddressLength)
	}
}

func TestReadFrameRejectsOversize(t *testing.T) {
	ca, cb := net.Pipe()
	defer ca.Close()
	defer cb.Close()
	go func() {
		// Announce a length larger than the cap, then close.
		hdr := []byte{0x7F, 0xFF, 0xFF, 0xFF} // ~2GB
		ca.Write(hdr)
		ca.Close()
	}()
	if _, err := readFrame(cb, maxHandshakeFrame); err == nil {
		t.Fatal("readFrame must reject an oversize length")
	}
}

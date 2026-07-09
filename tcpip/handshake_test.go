package tcpip

import (
	"bytes"
	"net"
	"testing"

	"github.com/wonabru/qwid-node/common"
	"github.com/wonabru/qwid-node/crypto/oqs"
	"github.com/wonabru/qwid-node/wallet"
)

// newTestIdentity builds a real Falcon-512 identity for handshake tests.
func newTestIdentity(t *testing.T) HandshakeIdentity {
	t.Helper()
	var s oqs.Signature
	if err := s.Init(common.SigName(), nil); err != nil {
		t.Skipf("oqs Falcon init unavailable (CGO/liboqs): %v", err)
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
	done := make(chan struct{})
	go func() { respAddr, respErr = HandshakeResponder(cb, b); close(done) }()

	initAddr, initErr := HandshakeInitiator(ca, a)
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
}

func TestHandshakeRejectsTamperAndReplay(t *testing.T) {
	a := newTestIdentity(t)
	nI := bytes.Repeat([]byte{1}, 32)
	nR := bytes.Repeat([]byte{2}, 32)
	tr := handshakeTranscript(nI, nR, a.Address)
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
	trOther := handshakeTranscript(nI, bytes.Repeat([]byte{9}, 32), a.Address)
	if verify(trOther, sig, a.PubKey) {
		t.Fatal("signature must not verify against a different transcript (replay)")
	}
}

func TestHandshakeTranscriptDomainSeparated(t *testing.T) {
	tr := handshakeTranscript(bytes.Repeat([]byte{0}, 32), bytes.Repeat([]byte{0}, 32), common.Address{})
	if !bytes.HasPrefix(tr, []byte("QWID-P2P-HS-v1")) {
		t.Fatal("transcript must start with the domain tag QWID-P2P-HS-v1")
	}
	if len(tr) != len("QWID-P2P-HS-v1")+32+32+common.AddressLength {
		t.Fatalf("transcript length = %d, want tag+32+32+%d", len(tr), common.AddressLength)
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

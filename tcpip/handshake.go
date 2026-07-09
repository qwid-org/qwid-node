package tcpip

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/wonabru/qwid-node/common"
	"github.com/wonabru/qwid-node/wallet"
)

var handshakeDomainTag = []byte("QWID-P2P-HS-v1")

const (
	handshakeNonceLen = 32
	handshakeTimeout  = 10 * time.Second
	maxHandshakeFrame = 16 * 1024 // a handshake message is <= ~6.6 KB; 16 KB is generous
)

// HandshakeIdentity is this node's signing identity for the handshake.
type HandshakeIdentity struct {
	PubKey  []byte                            // Falcon-512 primary public key bytes
	Address common.Address                    // nodeID = PubKeyToAddress(PubKey, true)
	Sign    func(data []byte) ([]byte, error) // returns scheme-flagged sig bytes wallet.Verify accepts
}

// handshakeTranscript builds the domain-separated, session-bound message signed
// by `addr`'s owner: DomainTag || nonceI || nonceR || addr. Identical on both sides.
func handshakeTranscript(nonceI, nonceR []byte, addr common.Address) []byte {
	b := make([]byte, 0, len(handshakeDomainTag)+2*handshakeNonceLen+common.AddressLength)
	b = append(b, handshakeDomainTag...)
	b = append(b, nonceI...)
	b = append(b, nonceR...)
	b = append(b, addr.GetBytes()...)
	return b
}

func writeFrame(c net.Conn, payload []byte) error {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	if _, err := c.Write(hdr[:]); err != nil {
		return err
	}
	_, err := c.Write(payload)
	return err
}

func readFrame(c net.Conn, maxLen int) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint32(hdr[:]))
	if n < 0 || n > maxLen {
		return nil, fmt.Errorf("handshake: frame length %d exceeds max %d", n, maxLen)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(c, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func randNonce() ([]byte, error) {
	n := make([]byte, handshakeNonceLen)
	_, err := rand.Read(n)
	return n, err
}

func verifyPeer(transcript, sig, peerPubKey []byte) bool {
	return wallet.Verify(transcript, sig, peerPubKey,
		common.SigName(), common.SigName2(), common.IsPaused(), common.IsPaused2())
}

// HandshakeInitiator runs the dialing side and returns the peer's VERIFIED nodeID.
func HandshakeInitiator(c net.Conn, self HandshakeIdentity) (common.Address, error) {
	_ = c.SetDeadline(time.Now().Add(handshakeTimeout))
	defer c.SetDeadline(time.Time{}) // clear for the normal receive loop

	nonceI, err := randNonce()
	if err != nil {
		return common.Address{}, err
	}
	// msg1: pubkeyI || nonceI
	if err := writeFrame(c, append(common.BytesToLenAndBytes(self.PubKey), nonceI...)); err != nil {
		return common.Address{}, err
	}
	// msg2: pubkeyR || nonceR || sigR
	m2, err := readFrame(c, maxHandshakeFrame)
	if err != nil {
		return common.Address{}, err
	}
	peerPub, rest, err := common.BytesWithLenToBytes(m2)
	if err != nil || len(rest) < handshakeNonceLen {
		return common.Address{}, fmt.Errorf("handshake: malformed responder hello")
	}
	nonceR := rest[:handshakeNonceLen]
	sigR, _, err := common.BytesWithLenToBytes(rest[handshakeNonceLen:])
	if err != nil {
		return common.Address{}, fmt.Errorf("handshake: malformed responder sig")
	}
	addrR, err := common.PubKeyToAddress(peerPub, true)
	if err != nil {
		return common.Address{}, err
	}
	if !verifyPeer(handshakeTranscript(nonceI, nonceR, addrR), sigR, peerPub) {
		return common.Address{}, fmt.Errorf("handshake: responder signature invalid")
	}
	// msg3: sigI over transcript(self.Address)
	sigI, err := self.Sign(handshakeTranscript(nonceI, nonceR, self.Address))
	if err != nil {
		return common.Address{}, err
	}
	if err := writeFrame(c, common.BytesToLenAndBytes(sigI)); err != nil {
		return common.Address{}, err
	}
	return addrR, nil
}

// HandshakeResponder runs the accepting side and returns the peer's VERIFIED nodeID.
func HandshakeResponder(c net.Conn, self HandshakeIdentity) (common.Address, error) {
	_ = c.SetDeadline(time.Now().Add(handshakeTimeout))
	defer c.SetDeadline(time.Time{})

	// msg1: pubkeyI || nonceI
	m1, err := readFrame(c, maxHandshakeFrame)
	if err != nil {
		return common.Address{}, err
	}
	peerPub, rest, err := common.BytesWithLenToBytes(m1)
	if err != nil || len(rest) < handshakeNonceLen {
		return common.Address{}, fmt.Errorf("handshake: malformed initiator hello")
	}
	nonceI := rest[:handshakeNonceLen]
	addrI, err := common.PubKeyToAddress(peerPub, true)
	if err != nil {
		return common.Address{}, err
	}
	nonceR, err := randNonce()
	if err != nil {
		return common.Address{}, err
	}
	sigR, err := self.Sign(handshakeTranscript(nonceI, nonceR, self.Address))
	if err != nil {
		return common.Address{}, err
	}
	// msg2: pubkeyR || nonceR || sigR
	m2 := append(common.BytesToLenAndBytes(self.PubKey), nonceR...)
	m2 = append(m2, common.BytesToLenAndBytes(sigR)...)
	if err := writeFrame(c, m2); err != nil {
		return common.Address{}, err
	}
	// msg3: sigI
	m3, err := readFrame(c, maxHandshakeFrame)
	if err != nil {
		return common.Address{}, err
	}
	sigI, _, err := common.BytesWithLenToBytes(m3)
	if err != nil {
		return common.Address{}, fmt.Errorf("handshake: malformed initiator confirm")
	}
	if !verifyPeer(handshakeTranscript(nonceI, nonceR, addrI), sigI, peerPub) {
		return common.Address{}, fmt.Errorf("handshake: initiator signature invalid")
	}
	return addrI, nil
}

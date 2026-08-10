package tcpip

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/wonabru/qwid-node/common"
	"github.com/wonabru/qwid-node/crypto/oqs"
	"github.com/wonabru/qwid-node/logger"
	"github.com/wonabru/qwid-node/wallet"
	"golang.org/x/crypto/hkdf"
)

// isHandshakeProtocolViolation separates authenticated protocol abuse from
// ordinary transport failures. EOF, reset, timeout and broken pipe are normal
// network conditions and must never ban an otherwise valid peer.
func isHandshakeProtocolViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "signature invalid") ||
		strings.Contains(msg, "frame length") && strings.Contains(msg, "exceeds")
}

var handshakeDomainTag = []byte("QWID-P2P-HS-v1")

const (
	handshakeNonceLen = 32
	handshakeTimeout  = 10 * time.Second
	maxHandshakeFrame = 16 * 1024 // a handshake message is <= ~6.6 KB; 16 KB is generous
)

// kemAlg is the ephemeral KEM algorithm used to derive transport session keys.
// Selected once at startup from whatever liboqs build this binary is linked
// against; empty means no supported KEM is available and the handshake fails
// closed (see HandshakeInitiator/HandshakeResponder).
var kemAlg = selectKEMAlg()

func selectKEMAlg() string {
	enabled := oqs.EnabledKEMs()
	for _, want := range []string{"ML-KEM-768", "Kyber768"} {
		for _, k := range enabled {
			if k == want {
				return want
			}
		}
	}
	logger.GetLogger().Println("WARNING: no preferred KEM (ML-KEM-768/Kyber768) enabled in liboqs; encrypted transport unavailable")
	return ""
}

var handshakeEncInfo = []byte("QWID-P2P-ENC-v1")

// deriveSessionKeys turns the KEM shared secret into two directional AEAD keys.
func deriveSessionKeys(ss, nonceI, nonceR []byte, initiator bool) (*SessionKeys, error) {
	salt := append(append([]byte{}, nonceI...), nonceR...)
	r := hkdf.New(sha256.New, ss, salt, handshakeEncInfo)
	okm := make([]byte, 64)
	if _, err := io.ReadFull(r, okm); err != nil {
		return nil, err
	}
	keyI2R, keyR2I := okm[:32], okm[32:]
	if initiator {
		return &SessionKeys{WriteKey: keyI2R, ReadKey: keyR2I}, nil
	}
	return &SessionKeys{WriteKey: keyR2I, ReadKey: keyI2R}, nil
}

// HandshakeIdentity is this node's signing identity for the handshake.
type HandshakeIdentity struct {
	PubKey  []byte                            // Falcon-512 primary public key bytes
	Address common.Address                    // nodeID = PubKeyToAddress(PubKey, true)
	Sign    func(data []byte) ([]byte, error) // returns scheme-flagged sig bytes wallet.Verify accepts
}

// handshakeTranscript builds the domain-separated, session-bound message signed
// by `addr`'s owner: DomainTag || nonceI || nonceR || kemPubI || kemCt || addr.
// Identical on both sides. Binding the KEM public key and ciphertext into the
// signed transcript makes the KEM material authenticated: a MITM that swaps
// either value causes signature verification to fail on both sides.
func handshakeTranscript(nonceI, nonceR, kemPubI, kemCt []byte, addr common.Address) []byte {
	b := make([]byte, 0, len(handshakeDomainTag)+2*handshakeNonceLen+len(kemPubI)+len(kemCt)+common.AddressLength)
	b = append(b, handshakeDomainTag...)
	b = append(b, nonceI...)
	b = append(b, nonceR...)
	b = append(b, kemPubI...)
	b = append(b, kemCt...)
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

// HandshakeInitiator runs the dialing side, returns the peer's VERIFIED nodeID,
// and derives the directional AEAD session keys from an ephemeral KEM exchange
// whose public key and ciphertext are bound into the signed transcript.
func HandshakeInitiator(c net.Conn, self HandshakeIdentity) (common.Address, *SessionKeys, error) {
	_ = c.SetDeadline(time.Now().Add(handshakeTimeout))
	defer c.SetDeadline(time.Time{}) // clear for the normal receive loop
	if kemAlg == "" {
		return common.Address{}, nil, fmt.Errorf("handshake: no KEM available")
	}

	nonceI, err := randNonce()
	if err != nil {
		return common.Address{}, nil, err
	}
	// ephemeral KEM keypair
	var kem oqs.KeyEncapsulation
	if err := kem.Init(kemAlg, nil); err != nil {
		return common.Address{}, nil, err
	}
	defer kem.Clean()
	kemPubI, err := kem.GenerateKeyPair()
	if err != nil {
		return common.Address{}, nil, err
	}

	// msg1: pubkeyI || nonceI || kemPubI
	m1 := append(common.BytesToLenAndBytes(self.PubKey), nonceI...)
	m1 = append(m1, common.BytesToLenAndBytes(kemPubI)...)
	if err := writeFrame(c, m1); err != nil {
		return common.Address{}, nil, err
	}

	// msg2: pubkeyR || nonceR || kemCt || sigR
	m2, err := readFrame(c, maxHandshakeFrame)
	if err != nil {
		return common.Address{}, nil, err
	}
	peerPub, rest, err := common.BytesWithLenToBytes(m2)
	if err != nil || len(rest) < handshakeNonceLen {
		return common.Address{}, nil, fmt.Errorf("handshake: malformed responder hello")
	}
	nonceR := rest[:handshakeNonceLen]
	kemCt, rest2, err := common.BytesWithLenToBytes(rest[handshakeNonceLen:])
	if err != nil {
		return common.Address{}, nil, fmt.Errorf("handshake: malformed responder kem")
	}
	sigR, _, err := common.BytesWithLenToBytes(rest2)
	if err != nil {
		return common.Address{}, nil, fmt.Errorf("handshake: malformed responder sig")
	}
	addrR, err := common.PubKeyToAddress(peerPub, true)
	if err != nil {
		return common.Address{}, nil, err
	}
	if !verifyPeer(handshakeTranscript(nonceI, nonceR, kemPubI, kemCt, addrR), sigR, peerPub) {
		return common.Address{}, nil, fmt.Errorf("handshake: responder signature invalid")
	}
	// decapsulate -> shared secret; derive keys
	ss, err := kem.DecapSecret(kemCt)
	if err != nil {
		return common.Address{}, nil, err
	}
	keys, err := deriveSessionKeys(ss, nonceI, nonceR, true)
	if err != nil {
		return common.Address{}, nil, err
	}

	// msg3: sigI over transcript(self.Address)
	sigI, err := self.Sign(handshakeTranscript(nonceI, nonceR, kemPubI, kemCt, self.Address))
	if err != nil {
		return common.Address{}, nil, err
	}
	if err := writeFrame(c, common.BytesToLenAndBytes(sigI)); err != nil {
		return common.Address{}, nil, err
	}
	return addrR, keys, nil
}

// HandshakeResponder runs the accepting side, returns the peer's VERIFIED
// nodeID, and derives the directional AEAD session keys by encapsulating to
// the initiator's ephemeral KEM public key (also bound into the signed
// transcript).
func HandshakeResponder(c net.Conn, self HandshakeIdentity) (common.Address, *SessionKeys, error) {
	_ = c.SetDeadline(time.Now().Add(handshakeTimeout))
	defer c.SetDeadline(time.Time{})
	if kemAlg == "" {
		return common.Address{}, nil, fmt.Errorf("handshake: no KEM available")
	}

	// msg1: pubkeyI || nonceI || kemPubI
	m1, err := readFrame(c, maxHandshakeFrame)
	if err != nil {
		return common.Address{}, nil, err
	}
	peerPub, rest, err := common.BytesWithLenToBytes(m1)
	if err != nil || len(rest) < handshakeNonceLen {
		return common.Address{}, nil, fmt.Errorf("handshake: malformed initiator hello")
	}
	nonceI := rest[:handshakeNonceLen]
	kemPubI, _, err := common.BytesWithLenToBytes(rest[handshakeNonceLen:])
	if err != nil {
		return common.Address{}, nil, fmt.Errorf("handshake: malformed initiator kem")
	}
	addrI, err := common.PubKeyToAddress(peerPub, true)
	if err != nil {
		return common.Address{}, nil, err
	}

	nonceR, err := randNonce()
	if err != nil {
		return common.Address{}, nil, err
	}
	// encapsulate to the initiator's ephemeral KEM pubkey
	var kem oqs.KeyEncapsulation
	if err := kem.Init(kemAlg, nil); err != nil {
		return common.Address{}, nil, err
	}
	defer kem.Clean()
	kemCt, ss, err := kem.EncapSecret(kemPubI)
	if err != nil {
		return common.Address{}, nil, err
	}
	keys, err := deriveSessionKeys(ss, nonceI, nonceR, false)
	if err != nil {
		return common.Address{}, nil, err
	}

	sigR, err := self.Sign(handshakeTranscript(nonceI, nonceR, kemPubI, kemCt, self.Address))
	if err != nil {
		return common.Address{}, nil, err
	}
	// msg2: pubkeyR || nonceR || kemCt || sigR
	m2 := append(common.BytesToLenAndBytes(self.PubKey), nonceR...)
	m2 = append(m2, common.BytesToLenAndBytes(kemCt)...)
	m2 = append(m2, common.BytesToLenAndBytes(sigR)...)
	if err := writeFrame(c, m2); err != nil {
		return common.Address{}, nil, err
	}

	// msg3: sigI
	m3, err := readFrame(c, maxHandshakeFrame)
	if err != nil {
		return common.Address{}, nil, err
	}
	sigI, _, err := common.BytesWithLenToBytes(m3)
	if err != nil {
		return common.Address{}, nil, fmt.Errorf("handshake: malformed initiator confirm")
	}
	if !verifyPeer(handshakeTranscript(nonceI, nonceR, kemPubI, kemCt, addrI), sigI, peerPub) {
		return common.Address{}, nil, fmt.Errorf("handshake: initiator signature invalid")
	}
	return addrI, keys, nil
}

// activeWalletIdentity builds this node's HandshakeIdentity from the active wallet.
//
// Sign byte-extraction: wallet.Wallet.Sign(data, primary) (wallet/wallet.go)
// prepends a scheme byte (0=primary/Falcon-512, 1=secondary/MAYO-5) to the raw
// signature and stores that combined slice in common.Signature.ByteValue via
// Init(). Signature.GetBytes() (common/types.go) returns ByteValue verbatim —
// i.e. exactly the scheme-flagged bytes wallet.Verify expects at sig[0]. This
// matches how the RPC client signs requests (cmd/sendingTransaction/main.go
// SignMessage: `line = append(line, sign.GetBytes()...)`) and how
// rpc/server/server.go's Listener.Send receives/verifies them
// (`signatureBytes = left; ...; wallet.Verify(..., signatureBytes, ...)`).
// common.Signature has NO GetSignature() method — GetBytes() is the only and
// correct accessor. Confirmed via a throwaway round-trip test (wallet.Sign ->
// GetBytes -> wallet.Verify) during implementation; see hs-task-2-report.md.
func activeWalletIdentity() (HandshakeIdentity, error) {
	w := wallet.GetActiveWallet()
	if w == nil {
		return HandshakeIdentity{}, fmt.Errorf("handshake: no active wallet")
	}
	pub := w.Account1.PublicKey.GetBytes()
	addr, err := common.PubKeyToAddress(pub, true)
	if err != nil {
		return HandshakeIdentity{}, err
	}
	return HandshakeIdentity{
		PubKey:  pub,
		Address: addr,
		Sign: func(d []byte) ([]byte, error) {
			sig, err := w.Sign(d, true)
			if err != nil {
				return nil, err
			}
			return sig.GetBytes(), nil // scheme-flagged bytes wallet.Verify accepts
		},
	}, nil
}

// verifiedNodeIDs stores the handshake-verified nodeID per (topic, ip) — a
// foundation for a future nodeID-keyed ban/allowlist. It is store-and-log only;
// no logic in this codebase currently gates on it (trust model stays OPEN
// peering — any peer that completes the handshake with a valid signature is
// accepted, regardless of which nodeID it presents).
var (
	verifiedNodeIDs      = map[[6]byte]common.Address{} // key = topic || ip
	verifiedNodeIDsMutex sync.Mutex
)

func storeVerifiedNodeID(topic [2]byte, ip [4]byte, id common.Address) {
	var k [6]byte
	copy(k[:2], topic[:])
	copy(k[2:], ip[:])
	verifiedNodeIDsMutex.Lock()
	verifiedNodeIDs[k] = id
	verifiedNodeIDsMutex.Unlock()
	logger.GetLogger().Printf("peer authenticated: topic=%s ip=%v nodeID=%x", string(topic[:]), ip, id.ByteValue)
}

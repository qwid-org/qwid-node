# Networking Peer-Auth Handshake Implementation Plan (sub-project B, NP-C3)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A mutual PQ challenge-response handshake authenticates both peers at connection setup and binds each connection to the peer's pubkey-derived nodeID; connections that fail are rejected.

**Architecture:** A self-contained `tcpip/handshake.go` holds the domain-separated transcript, length-prefixed framing over `net.Conn`, and `HandshakeInitiator`/`HandshakeResponder` (identity dependency-injected, so the whole exchange is testable over `net.Pipe` with two real Falcon keypairs). Then wire the two functions into the outbound dial (`StartNewConnection`) and inbound accept paths, building the local identity from `wallet.GetActiveWallet()`.

**Tech Stack:** Go 1.23.6; `tcpip`, `wallet`, `common`, `crypto/oqs` (Falcon-512 primary).

## Global Constraints

- Build/test with `GOROOT=/home/wonabru/sdk/go1.24.0`. Example: `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./tcpip/`.
- Branch `security-fixes`. Commit `OB-xx` (NOT `(CONSENSUS)` — node-local, though it is a connection-setup wire change; all nodes must run it to interoperate — fine under the coordinated branch). End messages with `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- **Trust model = authenticated OPEN peering.** Any valid key may peer. Do NOT add an allowlist gate. The verified nodeID is stored for a future follow-up; B does not yet ban/whitelist on it.
- **Transcript (security-load-bearing), byte-for-byte identical on both sides:** `DomainTag ‖ nonceI ‖ nonceR ‖ addr(signer)` where `DomainTag = []byte("QWID-P2P-HS-v1")`, nonces are 32 random bytes (`crypto/rand`), and `addr(party) = common.PubKeyToAddress(partyPubKey, true)` (the SAME derivation on signer and verifier — never substitute `wallet.MainAddress`).
- Reuse `wallet.Verify(msg, sig, pubkey []byte, common.SigName(), common.SigName2(), common.IsPaused(), common.IsPaused2()) bool` and `common.PubKeyToAddress(pb []byte, primary bool) (Address, error)`. Falcon-512 primary throughout (`primary=true`, sig scheme flag byte `0`).
- `tcpip` gains a `wallet` import (no cycle — verified). `common.AddressLength == 20`; `Address` has `ByteValue [20]byte` and `GetBytes()`.
- Length-prefix helpers: `common.BytesToLenAndBytes(b) []byte` and `common.BytesWithLenToBytes(b) (val, rest []byte, err error)` (used in tx serialization) for encoding pubkey/sig fields.

---

## File Structure

- `tcpip/handshake.go` (new) — transcript, framing, identity type, the two handshake funcs, and `activeWalletIdentity()`.
- `tcpip/handshake_test.go` (new) — `net.Pipe` mutual-auth + tamper/replay + malformed-frame tests (two real oqs Falcon identities).
- `tcpip/listenerTcpService.go` — call `HandshakeInitiator` in `StartNewConnection` before the receive loop.
- `tcpip/recieverTcpService.go` — call `HandshakeResponder` in the inbound accept path before topic traffic; store the verified nodeID.

---

## Task 1: Handshake core + framing + off-network tests

**Files:**
- Create: `tcpip/handshake.go`
- Test: `tcpip/handshake_test.go`

**Interfaces:**
- Consumes: `wallet.Verify`, `common.PubKeyToAddress`, `common.BytesToLenAndBytes`/`BytesWithLenToBytes`, `common.SigName/SigName2/IsPaused/IsPaused2`, `crypto/rand`, `crypto/oqs` (tests only).
- Produces: `HandshakeIdentity`, `func HandshakeInitiator(c net.Conn, self HandshakeIdentity) (common.Address, error)`, `func HandshakeResponder(c net.Conn, self HandshakeIdentity) (common.Address, error)`, `handshakeTranscript`, `writeFrame`/`readFrame`.

- [ ] **Step 1: Write the failing tests**

Create `tcpip/handshake_test.go`:

```go
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
```

- [ ] **Step 2: Run to verify it fails**

Run: `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./tcpip/ -run TestHandshake`
Expected: FAIL — `HandshakeInitiator`/`handshakeTranscript`/`readFrame`/`HandshakeIdentity` undefined.

- [ ] **Step 3: Implement `tcpip/handshake.go`**

```go
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
```

Confirm `common.BytesWithLenToBytes`'s exact signature/return order against `transactionsDefinition` usage before finalizing; adjust the decode calls if it differs (it peels one length-prefixed slice and returns the remainder).

- [ ] **Step 4: Run tests + build**

Run: `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./tcpip/ -run TestHandshake -v && GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go build ./...`
Expected: PASS (or CGO-skips if liboqs is unavailable — but `TestHandshakeTranscriptDomainSeparated`/`TestReadFrameRejectsOversize` must always run and pass), build OK.

- [ ] **Step 5: Commit**

```bash
git add tcpip/handshake.go tcpip/handshake_test.go
git commit -m "OB-115 net NP-C3: mutual PQ peer-auth handshake core (domain-separated, net.Pipe-tested)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 2: Build local identity from wallet + wire into connection setup

**Files:**
- Modify: `tcpip/handshake.go` (add `activeWalletIdentity()`)
- Modify: `tcpip/listenerTcpService.go` (`StartNewConnection` — initiator)
- Modify: `tcpip/recieverTcpService.go` (inbound accept path — responder; store nodeID)

**Interfaces:**
- Consumes: `wallet.GetActiveWallet()` (fields `Account1.PublicKey common.PubKey`, `w.Sign(data, true)`), `HandshakeInitiator`/`HandshakeResponder` (Task 1).
- Produces: `func activeWalletIdentity() (HandshakeIdentity, error)`; verified-nodeID storage.

- [ ] **Step 1: Add `activeWalletIdentity()`**

In `tcpip/handshake.go`:

```go
// activeWalletIdentity builds this node's HandshakeIdentity from the active wallet.
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
			return sig.GetSignature(), nil // MUST be the scheme-flagged bytes wallet.Verify accepts
		},
	}, nil
}
```

**Confirm the Sign byte-extraction:** `wallet.Verify`'s `sig` parameter is the scheme-flagged signature (`sig[0]` = scheme). Read how `rpc/server/server.go` obtains `signatureBytes` and how the RPC *client* produces them from a signed `common.Signature`, and use the matching accessor here (`GetSignature()` vs `GetBytes()` — pick the one that round-trips through `wallet.Verify`). If unsure, add a tiny unit test: sign a sample with the active/test wallet, extract via the chosen accessor, and assert `wallet.Verify` returns true — do not guess.

- [ ] **Step 2: Wire the initiator into `StartNewConnection`**

In `tcpip/listenerTcpService.go` `StartNewConnection`, after the dial loop succeeds (a live `tcpConn`) and BEFORE the receive loop begins reading (`~:229`), add:

```go
	self, idErr := activeWalletIdentity()
	if idErr != nil {
		logger.GetLogger().Println("handshake: cannot build identity:", idErr)
		tcpConn.Close()
		return
	}
	peerID, hsErr := HandshakeInitiator(tcpConn, self)
	if hsErr != nil {
		logger.GetLogger().Println("outbound handshake failed with", ipport, ":", hsErr)
		tcpConn.Close()
		PeersMutex.Lock()
		ReduceTrustRegisterPeer(ip)
		PeersMutex.Unlock()
		return
	}
	storeVerifiedNodeID(topic, ip, peerID)
```

(Place it after `tcpConn` is established/registered but before the `for { r := Receive(...) }` loop. Read the exact structure to position it so no normal `Send`/`Receive` runs before the handshake.)

- [ ] **Step 3: Wire the responder into the inbound accept path**

Read `tcpip/recieverTcpService.go` `Accept` (`:193`) and how the accepted `tcpConn` reaches its receive loop. Immediately after `RegisterPeer` succeeds and BEFORE any topic `Receive` on that connection, run:

```go
	self, idErr := activeWalletIdentity()
	if idErr != nil {
		logger.GetLogger().Println("handshake: cannot build identity:", idErr)
		tcpConn.Close()
		return nil, fmt.Errorf("handshake identity unavailable")
	}
	peerID, hsErr := HandshakeResponder(tcpConn, self)
	if hsErr != nil {
		logger.GetLogger().Println("inbound handshake failed:", hsErr)
		tcpConn.Close()
		return nil, fmt.Errorf("inbound handshake failed: %w", hsErr)
	}
	// derive the peer IP already parsed in RegisterPeer; store the verified nodeID
	storeVerifiedNodeID(topic, peerIP, peerID)
```

Position it so it runs on the accepting side exactly opposite the initiator — the outbound side runs `HandshakeInitiator`, the inbound side runs `HandshakeResponder`, on the same fresh connection, before either sends topic data. If the accept and the receive-loop start are in different functions/goroutines, place the responder call so it completes before the loop's first `Receive`.

- [ ] **Step 4: Verified-nodeID storage**

In `tcpip/handshake.go` (or `helper.go`), add a guarded map + setter (foundation for the deferred nodeID-ban/allowlist; B stores only):

```go
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
```

- [ ] **Step 5: Build + run the tcpip suite**

Run: `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go build ./... && GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./tcpip/`
Expected: build OK; `tcpip` tests pass (Task 1's crypto tests cover the protocol; the connection wiring needs a live network + two nodes to exercise end-to-end — note this limitation, as the receive/accept wiring cannot be unit-tested here).

- [ ] **Step 6: Commit**

```bash
git add tcpip/handshake.go tcpip/listenerTcpService.go tcpip/recieverTcpService.go
git commit -m "OB-115 net NP-C3: run peer-auth handshake at connection setup, bind + reject on failure

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Final verification

- [ ] `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go build ./...` → exit 0.
- [ ] `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./tcpip/ ./common/` → PASS (handshake crypto tests pass or CGO-skip; domain-separation + oversize tests always pass).
- [ ] Update `SECURITY_AUDIT.md`: mark **NP-C3** addressed — mutual PQ challenge-response handshake at connection setup binds each connection to a pubkey-derived nodeID (domain-separated transcript prevents cross-replay with tx signatures; nonces prevent replay); connections failing auth are rejected. Note that **nodeID-keyed ban/allowlist** and **full MITM resistance (transport encryption, sub-project C)** remain.

## Deferred (not in this plan)
- nodeID-keyed ban/allowlist using `verifiedNodeIDs`.
- Sub-project C — transport encryption / TLS (full MITM resistance; may layer an authenticated key exchange on this handshake).

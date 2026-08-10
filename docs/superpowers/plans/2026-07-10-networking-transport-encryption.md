# Networking Transport-Encryption Implementation Plan (sub-project C)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Encrypt the P2P stream with a post-quantum, authenticated, forward-secret AEAD keyed by a KEM exchange folded into B's handshake.

**Architecture:** (1) an `encryptedConn` AEAD record-layer `net.Conn`; (2) extend `HandshakeInitiator`/`HandshakeResponder` with an ephemeral liboqs KEM whose keys are in the signed transcript, deriving `SessionKeys` via HKDF; (3) wrap the raw conn after the handshake and retype `Send`/`Receive`/`tcpConnections` to `net.Conn` so they run transparently over the encrypted stream.

**Tech Stack:** Go 1.23.6; `tcpip`, `crypto/oqs` (KEM), `golang.org/x/crypto/{chacha20poly1305,hkdf}`, `common`.

## Global Constraints

- Build/test with `GOROOT=/home/wonabru/sdk/go1.24.0`. Example: `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./tcpip/`.
- Branch `security-fixes`. Commit `OB-xx` (NOT `(CONSENSUS)`; it is a wire-protocol change — all nodes must run it, fine under the coordinated branch). End messages with `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- **Nonce-reuse safety is critical:** each direction uses its own key + a monotonic counter nonce, and the counter+`Seal`/`Open` must be serialized by a per-direction mutex (a race → nonce reuse → catastrophic AEAD break).
- **KEM authenticated:** the ephemeral KEM public key AND ciphertext MUST be inside the signed transcript, so a MITM swapping KEM material breaks the PQ signature.
- Do NOT change B's crypto core semantics beyond adding the KEM; do NOT touch the DoS limiters or `MessageInitialization`/marker framing (the encrypted conn sits BELOW the markers).
- KEM alg is a fixed constant selected from `oqs.EnabledKEMs()`: prefer `"ML-KEM-768"`, else `"Kyber768"`, else fail loudly.
- Confirmed APIs: `chacha20poly1305.New(key []byte) (cipher.AEAD, error)` (KeySize 32, NonceSize 12, Overhead 16); `hkdf.New(hash func() hash.Hash, secret, salt, info []byte) io.Reader`; oqs `Init(alg, nil)`, `GenerateKeyPair() ([]byte,error)`, `EncapSecret(pub) (ct, ss []byte, err error)`, `DecapSecret(ct) ([]byte, error)`, `Clean()`, `oqs.EnabledKEMs() []string`; `common.BytesToLenAndBytes`/`BytesWithLenToBytes`.

---

## File Structure
- `tcpip/encryptedconn.go` (new) + `tcpip/encryptedconn_test.go` (new) — Task 1.
- `tcpip/handshake.go` + `tcpip/handshake_test.go` — Task 2 (KEM extension, `SessionKeys`, HKDF, return-type change, `storeSessionKeys`).
- `tcpip/listenerTcpService.go`, `tcpip/recieverTcpService.go` — Task 2 (call-site 3-value capture + store keys) and Task 3 (retype + wrap).

---

## Task 1: `encryptedConn` AEAD record layer + tests

**Files:** Create `tcpip/encryptedconn.go`, `tcpip/encryptedconn_test.go`.
**Interfaces:** Produces `type SessionKeys struct { WriteKey, ReadKey []byte }`, `func newEncryptedConn(raw net.Conn, keys *SessionKeys) (net.Conn, error)`.

- [ ] **Step 1: Write the failing test** — `tcpip/encryptedconn_test.go`:

```go
package tcpip

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"testing"
)

func mirroredPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	k1 := make([]byte, 32)
	k2 := make([]byte, 32)
	rand.Read(k1)
	rand.Read(k2)
	a, b := net.Pipe()
	ea, err := newEncryptedConn(a, &SessionKeys{WriteKey: k1, ReadKey: k2})
	if err != nil { t.Fatal(err) }
	eb, err := newEncryptedConn(b, &SessionKeys{WriteKey: k2, ReadKey: k1}) // mirror
	if err != nil { t.Fatal(err) }
	return ea, eb
}

func TestEncryptedConnRoundTrip(t *testing.T) {
	ea, eb := mirroredPair(t)
	defer ea.Close(); defer eb.Close()
	for _, size := range []int{0, 1, 100, 16 * 1024, 40 * 1024} { // incl. multi-record
		msg := make([]byte, size)
		rand.Read(msg)
		go func() { ea.Write(msg) }()
		got := make([]byte, size)
		if size > 0 {
			if _, err := io.ReadFull(eb, got); err != nil { t.Fatalf("size %d: %v", size, err) }
			if !bytes.Equal(got, msg) { t.Fatalf("size %d: round-trip mismatch", size) }
		}
	}
}

func TestEncryptedConnTamperDetected(t *testing.T) {
	// Wrap only the writer; read raw ciphertext, flip a byte, feed to a decrypting reader.
	k := make([]byte, 32); rand.Read(k)
	a, b := net.Pipe()
	ew, err := newEncryptedConn(a, &SessionKeys{WriteKey: k, ReadKey: k}); if err != nil { t.Fatal(err) }
	er, err := newEncryptedConn(b, &SessionKeys{WriteKey: k, ReadKey: k}); if err != nil { t.Fatal(err) }
	// Man-in-the-middle byte flip: write on a, corrupt in transit is hard over Pipe;
	// instead assert a corrupted record fails Open by writing a bad frame directly.
	go func() {
		defer a.Close()
		// valid-looking length + garbage body -> Open must fail
		a.Write([]byte{0x00, 0x00, 0x00, 0x20})
		a.Write(make([]byte, 0x20))
	}()
	buf := make([]byte, 16)
	if _, err := er.Read(buf); err == nil {
		t.Fatal("decrypt of garbage record must fail")
	}
	_ = ew
}
```

- [ ] **Step 2: Run to verify it fails** — `GOROOT=… go test ./tcpip/ -run TestEncryptedConn` → FAIL (undefined `newEncryptedConn`).

- [ ] **Step 3: Implement `tcpip/encryptedconn.go`**

```go
package tcpip

import (
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

const maxRecordPayload = 16 * 1024

// SessionKeys are the two directional AEAD keys derived from the KEM handshake.
type SessionKeys struct {
	WriteKey []byte // 32 bytes — this side seals with it
	ReadKey  []byte // 32 bytes — this side opens with it
}

type encryptedConn struct {
	raw       net.Conn
	writeAEAD cipher.AEAD
	readAEAD  cipher.AEAD
	writeCtr  uint64
	readCtr   uint64
	writeMu   sync.Mutex
	readMu    sync.Mutex
	readBuf   []byte
}

func newEncryptedConn(raw net.Conn, keys *SessionKeys) (net.Conn, error) {
	wa, err := chacha20poly1305.New(keys.WriteKey)
	if err != nil { return nil, err }
	ra, err := chacha20poly1305.New(keys.ReadKey)
	if err != nil { return nil, err }
	return &encryptedConn{raw: raw, writeAEAD: wa, readAEAD: ra}, nil
}

func recordNonce(ctr uint64) []byte {
	var n [chacha20poly1305.NonceSize]byte // 12 bytes; first 4 zero, last 8 = counter
	binary.BigEndian.PutUint64(n[4:], ctr)
	return n[:]
}

func (e *encryptedConn) Write(p []byte) (int, error) {
	e.writeMu.Lock()
	defer e.writeMu.Unlock()
	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxRecordPayload { chunk = chunk[:maxRecordPayload] }
		nonce := recordNonce(e.writeCtr)
		e.writeCtr++
		ct := e.writeAEAD.Seal(nil, nonce, chunk, nil)
		var hdr [4]byte
		binary.BigEndian.PutUint32(hdr[:], uint32(len(ct)))
		if _, err := e.raw.Write(hdr[:]); err != nil { return total, err }
		if _, err := e.raw.Write(ct); err != nil { return total, err }
		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

func (e *encryptedConn) Read(p []byte) (int, error) {
	e.readMu.Lock()
	defer e.readMu.Unlock()
	if len(e.readBuf) == 0 {
		var hdr [4]byte
		if _, err := io.ReadFull(e.raw, hdr[:]); err != nil { return 0, err }
		n := int(binary.BigEndian.Uint32(hdr[:]))
		if n < e.readAEAD.Overhead() || n > maxRecordPayload+e.readAEAD.Overhead() {
			return 0, fmt.Errorf("encryptedConn: bad record length %d", n)
		}
		ct := make([]byte, n)
		if _, err := io.ReadFull(e.raw, ct); err != nil { return 0, err }
		nonce := recordNonce(e.readCtr)
		e.readCtr++
		pt, err := e.readAEAD.Open(nil, nonce, ct, nil)
		if err != nil { return 0, fmt.Errorf("encryptedConn: decrypt failed: %w", err) }
		e.readBuf = pt
	}
	n := copy(p, e.readBuf)
	e.readBuf = e.readBuf[n:]
	return n, nil
}

func (e *encryptedConn) Close() error                       { return e.raw.Close() }
func (e *encryptedConn) LocalAddr() net.Addr                { return e.raw.LocalAddr() }
func (e *encryptedConn) RemoteAddr() net.Addr               { return e.raw.RemoteAddr() }
func (e *encryptedConn) SetDeadline(t time.Time) error      { return e.raw.SetDeadline(t) }
func (e *encryptedConn) SetReadDeadline(t time.Time) error  { return e.raw.SetReadDeadline(t) }
func (e *encryptedConn) SetWriteDeadline(t time.Time) error { return e.raw.SetWriteDeadline(t) }
```

- [ ] **Step 4: Run + build** — `GOROOT=… go test ./tcpip/ -run TestEncryptedConn -v && GOROOT=… go build ./...` → PASS.
- [ ] **Step 5: Commit** — `OB-116 net enc: encryptedConn AEAD record layer (ChaCha20-Poly1305, net.Pipe-tested)` + Co-Authored-By.

---

## Task 2: KEM key exchange in the handshake + HKDF SessionKeys

**Files:** Modify `tcpip/handshake.go`, `tcpip/handshake_test.go`; minimal call-site updates in `listenerTcpService.go`/`recieverTcpService.go` (capture + store the keys).
**Interfaces:** Changes `HandshakeInitiator`/`HandshakeResponder` to `(common.Address, *SessionKeys, error)`. Produces `storeSessionKeys(topic [2]byte, ip [4]byte, keys *SessionKeys)` + `takeSessionKeys(topic, ip) *SessionKeys` (guarded map, consumed by Task 3).

- [ ] **Step 1: Failing test** — extend `tcpip/handshake_test.go`. Update the existing `TestHandshakeMutualAuth` to the 3-value return and assert MATCHING keys; add a KEM-availability check. (Existing tamper/domain-sep tests that call `handshakeTranscript` directly must be updated to pass the two new `kemPubI,kemCt` args — dummy bytes are fine there.)

```go
func TestHandshakeDerivesMatchingSessionKeys(t *testing.T) {
	a := newTestIdentity(t)
	b := newTestIdentity(t)
	ca, cb := net.Pipe()
	defer ca.Close(); defer cb.Close()
	var rAddr common.Address; var rKeys *SessionKeys; var rErr error
	done := make(chan struct{})
	go func() { rAddr, rKeys, rErr = HandshakeResponder(cb, b); close(done) }()
	iAddr, iKeys, iErr := HandshakeInitiator(ca, a)
	<-done
	if iErr != nil || rErr != nil { t.Fatalf("init=%v resp=%v", iErr, rErr) }
	if iAddr != b.Address || rAddr != a.Address { t.Fatal("wrong peer nodeID") }
	// initiator.Write == responder.Read and vice versa
	if !bytes.Equal(iKeys.WriteKey, rKeys.ReadKey) || !bytes.Equal(iKeys.ReadKey, rKeys.WriteKey) {
		t.Fatal("session keys do not mirror across the two sides")
	}
	if bytes.Equal(iKeys.WriteKey, iKeys.ReadKey) { t.Fatal("the two directional keys must differ") }
}

func TestKEMAlgAvailable(t *testing.T) {
	if kemAlg == "" { t.Skip("no KEM available in this liboqs build") }
	found := false
	for _, k := range oqs.EnabledKEMs() { if k == kemAlg { found = true } }
	if !found { t.Fatalf("selected KEM %q not in EnabledKEMs", kemAlg) }
}
```

- [ ] **Step 2: Run to verify it fails** — FAIL (3-value return undefined / `kemAlg` undefined).

- [ ] **Step 3: Implement in `tcpip/handshake.go`**

Add imports `crypto/sha256`, `hash`, `golang.org/x/crypto/hkdf`, `io`, and `github.com/wonabru/qwid-node/crypto/oqs`.

KEM alg selection + key derivation:
```go
var kemAlg = selectKEMAlg()

func selectKEMAlg() string {
	enabled := oqs.EnabledKEMs()
	for _, want := range []string{"ML-KEM-768", "Kyber768"} {
		for _, k := range enabled {
			if k == want { return want }
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
	if _, err := io.ReadFull(r, okm); err != nil { return nil, err }
	keyI2R, keyR2I := okm[:32], okm[32:]
	if initiator {
		return &SessionKeys{WriteKey: keyI2R, ReadKey: keyR2I}, nil
	}
	return &SessionKeys{WriteKey: keyR2I, ReadKey: keyI2R}, nil
}
```

Extend the transcript to bind the KEM material:
```go
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
```

`HandshakeInitiator` (new body — additions in **bold** comments):
```go
func HandshakeInitiator(c net.Conn, self HandshakeIdentity) (common.Address, *SessionKeys, error) {
	_ = c.SetDeadline(time.Now().Add(handshakeTimeout))
	defer c.SetDeadline(time.Time{})
	if kemAlg == "" { return common.Address{}, nil, fmt.Errorf("handshake: no KEM available") }

	nonceI, err := randNonce()
	if err != nil { return common.Address{}, nil, err }
	// ephemeral KEM keypair
	var kem oqs.KeyEncapsulation
	if err := kem.Init(kemAlg, nil); err != nil { return common.Address{}, nil, err }
	defer kem.Clean()
	kemPubI, err := kem.GenerateKeyPair()
	if err != nil { return common.Address{}, nil, err }

	// msg1: pubkeyI || nonceI || kemPubI
	m1 := append(common.BytesToLenAndBytes(self.PubKey), nonceI...)
	m1 = append(m1, common.BytesToLenAndBytes(kemPubI)...)
	if err := writeFrame(c, m1); err != nil { return common.Address{}, nil, err }

	// msg2: pubkeyR || nonceR || kemCt || sigR
	m2, err := readFrame(c, maxHandshakeFrame)
	if err != nil { return common.Address{}, nil, err }
	peerPub, rest, err := common.BytesWithLenToBytes(m2)
	if err != nil || len(rest) < handshakeNonceLen { return common.Address{}, nil, fmt.Errorf("handshake: malformed responder hello") }
	nonceR := rest[:handshakeNonceLen]
	kemCt, rest2, err := common.BytesWithLenToBytes(rest[handshakeNonceLen:])
	if err != nil { return common.Address{}, nil, fmt.Errorf("handshake: malformed responder kem") }
	sigR, _, err := common.BytesWithLenToBytes(rest2)
	if err != nil { return common.Address{}, nil, fmt.Errorf("handshake: malformed responder sig") }
	addrR, err := common.PubKeyToAddress(peerPub, true)
	if err != nil { return common.Address{}, nil, err }
	if !verifyPeer(handshakeTranscript(nonceI, nonceR, kemPubI, kemCt, addrR), sigR, peerPub) {
		return common.Address{}, nil, fmt.Errorf("handshake: responder signature invalid")
	}
	// decapsulate -> shared secret; derive keys
	ss, err := kem.DecapSecret(kemCt)
	if err != nil { return common.Address{}, nil, err }
	keys, err := deriveSessionKeys(ss, nonceI, nonceR, true)
	if err != nil { return common.Address{}, nil, err }

	// msg3: sigI over transcript(self.Address)
	sigI, err := self.Sign(handshakeTranscript(nonceI, nonceR, kemPubI, kemCt, self.Address))
	if err != nil { return common.Address{}, nil, err }
	if err := writeFrame(c, common.BytesToLenAndBytes(sigI)); err != nil { return common.Address{}, nil, err }
	return addrR, keys, nil
}
```

`HandshakeResponder` (new body):
```go
func HandshakeResponder(c net.Conn, self HandshakeIdentity) (common.Address, *SessionKeys, error) {
	_ = c.SetDeadline(time.Now().Add(handshakeTimeout))
	defer c.SetDeadline(time.Time{})
	if kemAlg == "" { return common.Address{}, nil, fmt.Errorf("handshake: no KEM available") }

	// msg1: pubkeyI || nonceI || kemPubI
	m1, err := readFrame(c, maxHandshakeFrame)
	if err != nil { return common.Address{}, nil, err }
	peerPub, rest, err := common.BytesWithLenToBytes(m1)
	if err != nil || len(rest) < handshakeNonceLen { return common.Address{}, nil, fmt.Errorf("handshake: malformed initiator hello") }
	nonceI := rest[:handshakeNonceLen]
	kemPubI, _, err := common.BytesWithLenToBytes(rest[handshakeNonceLen:])
	if err != nil { return common.Address{}, nil, fmt.Errorf("handshake: malformed initiator kem") }
	addrI, err := common.PubKeyToAddress(peerPub, true)
	if err != nil { return common.Address{}, nil, err }

	nonceR, err := randNonce()
	if err != nil { return common.Address{}, nil, err }
	// encapsulate to the initiator's ephemeral KEM pubkey
	var kem oqs.KeyEncapsulation
	if err := kem.Init(kemAlg, nil); err != nil { return common.Address{}, nil, err }
	defer kem.Clean()
	kemCt, ss, err := kem.EncapSecret(kemPubI)
	if err != nil { return common.Address{}, nil, err }
	keys, err := deriveSessionKeys(ss, nonceI, nonceR, false)
	if err != nil { return common.Address{}, nil, err }

	sigR, err := self.Sign(handshakeTranscript(nonceI, nonceR, kemPubI, kemCt, self.Address))
	if err != nil { return common.Address{}, nil, err }
	// msg2: pubkeyR || nonceR || kemCt || sigR
	m2 := append(common.BytesToLenAndBytes(self.PubKey), nonceR...)
	m2 = append(m2, common.BytesToLenAndBytes(kemCt)...)
	m2 = append(m2, common.BytesToLenAndBytes(sigR)...)
	if err := writeFrame(c, m2); err != nil { return common.Address{}, nil, err }

	// msg3: sigI
	m3, err := readFrame(c, maxHandshakeFrame)
	if err != nil { return common.Address{}, nil, err }
	sigI, _, err := common.BytesWithLenToBytes(m3)
	if err != nil { return common.Address{}, nil, fmt.Errorf("handshake: malformed initiator confirm") }
	if !verifyPeer(handshakeTranscript(nonceI, nonceR, kemPubI, kemCt, addrI), sigI, peerPub) {
		return common.Address{}, nil, fmt.Errorf("handshake: initiator signature invalid")
	}
	return addrI, keys, nil
}
```

Add the session-key store (parallel to `verifiedNodeIDs`):
```go
var (
	sessionKeys      = map[[6]byte]*SessionKeys{}
	sessionKeysMutex sync.Mutex
)
func storeSessionKeys(topic [2]byte, ip [4]byte, keys *SessionKeys) {
	var k [6]byte; copy(k[:2], topic[:]); copy(k[2:], ip[:])
	sessionKeysMutex.Lock(); sessionKeys[k] = keys; sessionKeysMutex.Unlock()
}
func takeSessionKeys(topic [2]byte, ip [4]byte) *SessionKeys {
	var k [6]byte; copy(k[:2], topic[:]); copy(k[2:], ip[:])
	sessionKeysMutex.Lock(); defer sessionKeysMutex.Unlock()
	ks := sessionKeys[k]; delete(sessionKeys, k); return ks
}
```

- [ ] **Step 4: Update the B call sites to the 3-value return (compile).** In `StartNewConnection` (outbound) and the inbound accept path, change `peerID, hsErr := HandshakeInitiator(...)` / `...Responder(...)` to `peerID, sKeys, hsErr := ...`, and on success call `storeSessionKeys(topic, ip, sKeys)`. (Task 3 consumes these to wrap the conn; until then the keys are stored but the stream is not yet encrypted — the build is green and the key-agreement is tested.)

- [ ] **Step 5: Run + build** — `GOROOT=… go test ./tcpip/ -run 'TestHandshake|TestKEMAlg' -v && GOROOT=… go build ./...` → PASS. (If `oqs.EnabledKEMs()` lacks ML-KEM-768/Kyber768 in this env, `kemAlg==""` and the handshake tests will fail-closed — verify liboqs has a supported KEM; if genuinely absent, report it, as the whole feature needs a KEM.)

- [ ] **Step 6: Commit** — `OB-116 net enc: authenticated KEM key exchange in the handshake (HKDF session keys)` + Co-Authored-By.

---

## Task 3: Wrap connections + retype Send/Receive to net.Conn

**Files:** `tcpip/recieverTcpService.go`, `tcpip/listenerTcpService.go`.

- [ ] **Step 1: Retype** `Send(conn net.Conn, ...)` and `Receive(topic [2]byte, conn net.Conn) []byte` (they only use `Write`/`Read`/`SetWriteDeadline`/`SetReadDeadline`). Retype `tcpConnections` to `map[[2]byte]map[[4]byte]net.Conn`. Fix the resulting compile errors: TCP-specific calls (`SetKeepAlive`) must run on the RAW `*net.TCPConn` before wrapping (at accept/dial), not on the stored `net.Conn`. `publishAcceptedConn` and the outbound registration now store a `net.Conn`.

- [ ] **Step 2: Wrap after handshake.** At the point where a successfully-handshaken connection is published (both inbound `publishAcceptedConn` path and outbound registration in `StartNewConnection`), retrieve the keys and wrap:
```go
keys := takeSessionKeys(topic, ip)
if keys == nil { /* handshake didn't store keys */ tcpConn.Close(); return ... }
ec, err := newEncryptedConn(tcpConn, keys)
if err != nil { tcpConn.Close(); return ... }
// store `ec` (net.Conn) in tcpConnections instead of the raw tcpConn
```
The re-dial re-handshake path (added in sub-project B) must ALSO re-wrap: after a successful re-handshake it stores new keys; wrap the re-dialed conn the same way before resuming reads.

- [ ] **Step 3: Decrypt-failure handling.** `Receive` now reads via `ec.Read`; a decryption failure surfaces as a read error → return the existing `<-ERR->`/close sentinel so the receive loop drops the connection (a decrypt failure means tampering or desync — never continue on it).

- [ ] **Step 4: Build + run** — `GOROOT=… go build ./... && GOROOT=… go test ./tcpip/ ./common/`. Expected: build OK; tcpip tests pass. The full encrypted path needs a live 2-node network to exercise end-to-end (Tasks 1–2 unit-test the record layer and key agreement); note this limitation. **If the retype touches a call site whose behavior would change subtly (e.g. a place relying on `*net.TCPConn`-specific behavior), STOP and report rather than guessing.**

- [ ] **Step 5: Commit** — `OB-116 net enc: wrap P2P conns in encryptedConn after handshake; Send/Receive over net.Conn` + Co-Authored-By.

---

## Final verification
- [ ] `GOROOT=… go build ./...` → exit 0.
- [ ] `GOROOT=… go test ./tcpip/ ./common/` → PASS (encryptedConn + handshake-key tests; live-network path is build+review-verified).
- [ ] Update `SECURITY_AUDIT.md`: P2P transport is now **PQ-KEM authenticated encrypted** (ML-KEM-768 + ChaCha20-Poly1305, forward-secret, MITM-resistant) — completing the networking hardening (A DoS + B peer-auth + C encryption). Note deferred: votable KEM, nodeID-ban/allowlist, session/nodeID cleanup on disconnect.

## Deferred (not in this plan)
- Make the KEM votable (like signature schemes); nodeID-keyed ban/allowlist; session-key & `verifiedNodeIDs` cleanup on disconnect; chunk tx-gossip to tighten the DoS TransactionTopic cap.

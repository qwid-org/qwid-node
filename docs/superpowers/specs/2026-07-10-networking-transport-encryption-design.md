# Networking Sub-Project C — Transport Encryption (PQ-KEM Authenticated)

**Date:** 2026-07-10
**Branch:** `security-fixes`
**Source:** Completes NP-C3's "full MITM resistance" — sub-project B authenticated peer identity; C encrypts the stream so an on-path attacker cannot read or inject P2P traffic.
**Parent effort:** Networking-security infrastructure — A (DoS hardening, done), B (peer-auth handshake, done), **C (this: transport encryption)**. Last networking piece.

## Context and decisions

**Approach (chosen): PQ-KEM authenticated encryption, extending B's handshake** — NOT classical `crypto/tls`. B already does a mutual PQ-signature handshake at connection setup; C adds an **ephemeral liboqs KEM key exchange** whose public keys are covered by B's existing signatures (authenticated ⇒ MITM-resistant), derives session keys via HKDF, and wraps the connection in an AEAD `net.Conn` (ChaCha20-Poly1305) so the existing `Send`/`Receive` run transparently over an encrypted, forward-secret stream.

Decisions:
- **KEM algorithm = a fixed constant** (the KEM is not in the signature-scheme voting system). Primary **`ML-KEM-768`** (NIST FIPS 203); the code selects it from `oqs.EnabledKEMs()` at init, falling back to `Kyber768` if that is the built name, and failing loudly if neither is available (a node without the KEM cannot do encrypted transport).
- **AEAD = ChaCha20-Poly1305** (`golang.org/x/crypto/chacha20poly1305`, already in go.mod); **KDF = HKDF** (`golang.org/x/crypto/hkdf`).
- **Forward secrecy** from a per-connection ephemeral KEM keypair (discarded after the handshake).

### Ground truth (from exploration)

- liboqs KEM (`crypto/oqs/oqs.go`): `Init(algName string, secretKey []byte) error`; `GenerateKeyPair() ([]byte, error)` (returns public key, stores secret internally); `EncapSecret(publicKey []byte) (ciphertext, sharedSecret []byte, err error)`; `DecapSecret(ciphertext []byte) ([]byte, error)` (returns shared secret); `Clean()`; `oqs.EnabledKEMs() []string` lists runtime-available names. KEM is currently UNUSED.
- B handshake (`tcpip/handshake.go`): 3 length-prefixed frames; transcript `handshakeDomainTag ‖ nonceI ‖ nonceR ‖ addr`; `HandshakeInitiator/Responder(c net.Conn, self HandshakeIdentity) (common.Address, error)`. Msg1 = `pubkeyI ‖ nonceI`; Msg2 = `pubkeyR ‖ nonceR ‖ sigR`; Msg3 = `sigI`. `writeFrame`/`readFrame` do length-prefixed framing; the handshake reads exactly its frames, leaving the stream clean for the record layer to take over.
- Framing to preserve: `Send(conn *net.TCPConn, msg)` / `Receive(topic, conn *net.TCPConn)` use `[MessageInitialization]…[<-END->]` markers; the receive loop reassembles by `<-END->` and enforces the per-topic DoS caps. Marker-based reassembly is INCOMPATIBLE with raw ciphertext (a `<-END->` byte run can occur by chance) — hence encryption must be a length-prefixed record layer BELOW the markers.
- `tcpConnections map[[2]byte]map[[4]byte]*net.TCPConn` — holds the per-peer conn; `SetKeepAlive` is the only TCP-specific call (done at accept).
- `golang.org/x/crypto v0.33.0` provides `chacha20poly1305` + `hkdf`; wallet already uses AES-GCM (stdlib) — precedent for AEAD.

## Goals

1. Every P2P byte AFTER the handshake is encrypted with an AEAD keyed by a per-connection secret.
2. The key exchange is authenticated by B's signatures (MITM-resistant) and forward-secret (ephemeral KEM).
3. `Send`/`Receive` and the receive-loop reassembly + DoS caps keep working, operating on decrypted plaintext.

## Non-goals

- Making the KEM votable (fixed constant; a future enhancement could add it to voting).
- Classical TLS.
- Encrypting the handshake messages themselves (they are signed, not secret; the KEM makes the *subsequent* stream confidential).

## Design

### 1. KEM key exchange inside the handshake (`tcpip/handshake.go`)

Extend the transcript to bind the KEM material:
```
transcript(signer) = handshakeDomainTag ‖ nonceI ‖ nonceR ‖ kemPubI ‖ kemCt ‖ addr(signer)
```
Message changes (length-prefix each new field with `common.BytesToLenAndBytes`):
- **Msg1 (I→R):** `pubkeyI ‖ nonceI ‖ kemPubI` — initiator generates an ephemeral KEM keypair (`kem.GenerateKeyPair()`), sends the public key, keeps the secret.
- **Msg2 (R→I):** responder runs `kemCt, ss, _ = kem.EncapSecret(kemPubI)`, sends `pubkeyR ‖ nonceR ‖ kemCt ‖ sigR` where `sigR` signs the extended transcript.
- **Msg3 (I→R):** `sigI` over the extended transcript. The initiator runs `ss, _ = kem.DecapSecret(kemCt)` (decap with its ephemeral secret) → the same `ss`.

Both verify the peer's signature over the extended transcript (so a swapped `kemPubI`/`kemCt` breaks verification — the KEM is authenticated). Ephemeral KEM keys are `Clean()`ed after use.

**Return type:** `HandshakeInitiator/Responder` return `(common.Address, *SessionKeys, error)`. All existing callers (from sub-project B) that used the 2-value return get the extra `*SessionKeys`.

### 2. Session-key derivation (HKDF)

```
okm = HKDF-SHA256(secret = ss, salt = nonceI ‖ nonceR, info = "QWID-P2P-ENC-v1", length = 64)
keyI2R = okm[0:32]   // initiator→responder direction
keyR2I = okm[32:64]  // responder→initiator direction
```
`SessionKeys{ writeKey, readKey [32]byte }` — the initiator sets `writeKey=keyI2R, readKey=keyR2I`; the responder swaps. Both derive identical `okm` (same `ss`, `nonceI`, `nonceR`).

### 3. `encryptedConn` — AEAD record layer (`tcpip/encryptedconn.go`, new)

A `net.Conn` wrapping the raw conn, with directional ChaCha20-Poly1305 keys and monotonic per-direction counter nonces (never on the wire, never reused):
```go
type encryptedConn struct {
	raw       net.Conn
	writeAEAD, readAEAD cipher.AEAD // chacha20poly1305 from writeKey/readKey
	writeCtr, readCtr   uint64      // per-direction record counters
	readBuf   []byte                // leftover decrypted plaintext across Read calls
	writeMu, readMu     sync.Mutex  // REQUIRED — see nonce-reuse note
}
```

**Nonce-reuse safety (critical).** `Write` must hold `writeMu` across "increment `writeCtr` → build nonce → `Seal` → write record" as one atomic unit, and `Read` must hold `readMu` across "read record → increment `readCtr` → build nonce → `Open`". A data race on `writeCtr` (e.g. two `LoopSend`/`Send` goroutines writing the same conn) would reuse a ChaCha20-Poly1305 nonce under one key — a catastrophic AEAD failure that voids confidentiality. The two mutexes are separate (write vs read) so opposite-direction traffic never blocks, but each direction's counter+Seal/Open MUST be serialized regardless of how many goroutines call it.
- **Wire record:** `[4B big-endian len][ciphertext ‖ 16B tag]`. Nonce = `direction-fixed-byte ‖ 0-pad ‖ counter(8B)` (12 bytes), incremented per record; a per-direction key + monotonic counter guarantees no nonce reuse.
- **`Write(p)`:** chunk `p` into records ≤ a max record size (e.g. 16 KB), `Seal` each with the next write nonce, `writeFrame`-style length-prefix, write to `raw`.
- **`Read(p)`:** serve from `readBuf` if non-empty; else read one record (`[4B len]`, bounds-check ≤ maxRecord, then the body), `Open` with the next read nonce (fails → return error, drop conn), buffer plaintext, copy into `p` (standard `net.Conn` partial-read semantics).
- **`SetDeadline`/`SetReadDeadline`/`SetWriteDeadline`/`Close`/`LocalAddr`/`RemoteAddr`** delegate to `raw`.
- Constructor: `newEncryptedConn(raw net.Conn, keys *SessionKeys) (net.Conn, error)`.

### 4. Wiring (`tcpip/recieverTcpService.go`, `tcpip/listenerTcpService.go`)

- **Retype `Send`/`Receive`** from `*net.TCPConn` to `net.Conn` (they only use `Write`/`Read`/`SetWriteDeadline`/`SetReadDeadline`). Retype `tcpConnections` to `map[[2]byte]map[[4]byte]net.Conn` and adjust the few call sites (SetKeepAlive stays on the raw conn, called before wrapping at accept/dial).
- **After a successful handshake** (both the inbound responder and outbound initiator paths from B): derive `SessionKeys`, `ec, _ := newEncryptedConn(rawConn, keys)`, and store `ec` (as `net.Conn`) via `publishAcceptedConn`/the outbound registration. Subsequent `Send`/`Receive` on that peer operate on `ec`.
- The receive-loop reassembly (`<-END->`, `MessageInitialization`, per-topic size caps, message-rate limiter) is UNCHANGED — it now reads from `ec.Read` (plaintext), so it sees exactly what it saw before, just decrypted.
- On any `encryptedConn` decrypt failure, treat like a read error (`<-ERR->`/close) — a decryption failure means tampering or desync; drop the connection.

### 5. Security properties

- **Confidentiality + integrity:** ChaCha20-Poly1305 AEAD over every post-handshake byte.
- **MITM resistance:** the KEM public key and ciphertext are inside the signed transcript, so an active attacker cannot substitute its own KEM key without invalidating a PQ signature — the session key is bound to the authenticated identities.
- **Forward secrecy:** the ephemeral KEM secret is per-connection and discarded (`Clean()`), so a later compromise of a node's long-term wallet key does not decrypt past sessions.
- **No nonce reuse:** per-direction key + monotonic counter.
- **Post-quantum end-to-end:** KEM (ML-KEM-768) + PQ signatures (Falcon/MAYO) + symmetric AEAD.

## Error handling / determinism

- Node-local transport security; not consensus. A handshake/KEM failure closes the connection (and, per B, bans on handshake-sig failure).
- A KEM alg unavailable at init is a hard startup error (the node logs and cannot peer encrypted) — surfaced clearly.

## Testing

`encryptedConn` and the KEM handshake are testable off-network:

- **`encryptedConn` round-trip (net.Pipe):** wrap both ends with mirrored keys (A.write=B.read), write various sizes (empty, <record, multi-record, exactly one record), assert `Read` returns identical plaintext; interleaved/partial reads reassemble correctly.
- **Tamper detection:** flip a byte in a record on the wire → `Read` returns an error (AEAD tag fails), connection unusable.
- **Nonce monotonicity:** two records in a row decrypt correctly (counters advance in lockstep); a replayed/reordered record fails.
- **Extended handshake (net.Pipe, two real identities):** both sides return the SAME `SessionKeys` (initiator.writeKey == responder.readKey and vice versa) and the correct peer nodeID; a tampered `kemCt` or `kemPubI` on the wire breaks signature verification (reuse B's tamper harness).
- **KEM availability:** a unit test asserts the chosen KEM constant is in `oqs.EnabledKEMs()` (or documents the skip if liboqs lacks it).

Tests run with `GOROOT=/home/wonabru/sdk/go1.24.0`.

## Files touched

- `tcpip/handshake.go` — ephemeral KEM into msg1/msg2, extended transcript, `SessionKeys` + HKDF, return-type change; the KEM alg constant + `oqs.EnabledKEMs()` selection.
- `tcpip/encryptedconn.go` (new) — the AEAD record-layer `net.Conn`.
- `tcpip/encryptedconn_test.go`, `tcpip/handshake_test.go` (extend) — the tests above.
- `tcpip/recieverTcpService.go`, `tcpip/listenerTcpService.go` — retype `Send`/`Receive`/`tcpConnections` to `net.Conn`; wrap + store the encrypted conn after the handshake; update the B handshake call sites for the new 3-value return.

## Rollout / commit plan (3 tasks)

Node-local (not `(CONSENSUS)`), but a wire-protocol change — all nodes must run it to interoperate (fine under the coordinated branch):
1. **`encryptedConn` record layer + tests** (self-contained; net.Pipe round-trip, tamper, partial reads). No handshake/wiring dependency.
2. **KEM handshake extension + HKDF `SessionKeys` + tests** (ephemeral KEM in the transcript, both sides derive matching keys; KEM-alg selection from `oqs.EnabledKEMs()`). Updates `HandshakeInitiator/Responder` return type — updates B's call sites minimally to compile.
3. **Wiring** — retype `Send`/`Receive`/`tcpConnections` to `net.Conn`; wrap the conn with `encryptedConn` after the handshake on both paths; decrypt-failure → drop. Build + review (needs a live 2-node network to exercise end-to-end).

Not "done" until `tcpip` builds and the encryptedConn + handshake tests pass, and `SECURITY_AUDIT.md` records that P2P transport is now PQ-KEM-authenticated-encrypted (full MITM resistance), completing the networking hardening (A+B+C).

## Deferred (follow-ups)
- Make the KEM algorithm votable (like the signature schemes).
- nodeID-keyed ban/allowlist; `verifiedNodeIDs`/session cleanup on disconnect; chunk tx-gossip to tighten the DoS TransactionTopic cap.

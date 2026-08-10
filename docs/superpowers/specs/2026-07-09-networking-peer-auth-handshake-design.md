# Networking Sub-Project B — Peer-Auth Handshake (NP-C3)

**Date:** 2026-07-09
**Branch:** `security-fixes`
**Source:** `SECURITY_AUDIT.md` NP-C3 (CRITICAL) — "IP identity not cryptographically bound: no handshake/challenge; peer identity taken from TCP RemoteAddr, gated only by a plaintext magic value."
**Parent effort:** Networking-security infrastructure — A (DoS hardening, done), **B (this: peer-auth handshake)**, C (transport encryption / TLS).

## Context and decisions

**Trust model (chosen): authenticated open peering with a persistent nodeID.** Every node's wallet key is its persistent identity; a mutual PQ challenge-response handshake proves each side controls its key and binds the connection to the peer's verified pubkey-derived address (the nodeID). Any valid key may peer (open network) — the handshake authenticates, it does not authorize against an allowlist (there is no on-chain node-key registry). This is the standard model (cf. Ethereum devp2p nodeIDs) and reuses the existing PQ signing.

**Scope boundary.** B delivers the mutual handshake, the connection↔nodeID binding, and rejection of connections that fail authentication. **Deferred:** nodeID-keyed ban/allowlist (a refactor of the currently-IP-keyed ban system) and **transport encryption**. **Honest caveat:** without encryption (sub-project C), the handshake authenticates the *initial* identity but post-handshake plaintext traffic remains injectable by an on-path attacker — **full MITM resistance needs B + C together.** B is the authentication foundation C builds on.

### Ground truth (from exploration)

- **No import cycle:** `tcpip` and `wallet` are independent; `tcpip` can import `wallet`. Node key: `wallet.GetActiveWallet() *Wallet` (fields `Account1.PublicKey common.PubKey`, `MainAddress common.Address`). Sign: `wallet.Sign(data []byte, primary bool) (*common.Signature, error)` (wallet.go:~906) → `Signature.GetBytes()` yields the scheme-flagged sig bytes. Verify: `wallet.Verify(msg, sig, pubkey []byte, sigName, sigName2 string, isPaused, isPaused2 bool) bool` (wallet.go:937). Scheme names/pause flags: `common.SigName()`, `common.SigName2()`, `common.IsPaused()`, `common.IsPaused2()` (as used at `rpc/server/server.go:121`).
- **Address from pubkey:** `common.PubKeyToAddress(pb []byte, primary bool) (Address, error)` (types.go:288) and `PubKey.GetAddress() Address` (types.go:359). `PubKey.GetBytes()`, `Signature.GetBytes()`.
- **Sizes:** Falcon-512 (primary) pub 897 B / sig 752 B; MAYO-5 (secondary) pub 5554 B / sig 964 B. A handshake message (pubkey + nonce + sig) ≈ ≤ 6.6 KB — well within the 64 KB nonce-topic cap.
- **Connections:** 4 separate TCP connections per peer (one per topic). Outbound: `StartNewConnection` (`tcpip/listenerTcpService.go:111`) after `net.DialTCP`, before the receive loop (~:229). Inbound: `Accept`→`RegisterPeer` (`tcpip/recieverTcpService.go:193,296`), then the connection is used by the receive loop. No existing handshake — first bytes are topic data. `crypto/rand` is available.
- `Send(conn *net.TCPConn, msg []byte)` / `Receive(topic, conn *net.TCPConn)` are TCP-typed; the handshake uses its own `net.Conn`-based length-prefixed framing (see below) so it is unit-testable over `net.Pipe`.

## Goals

1. A mutual challenge-response handshake authenticates BOTH peers (each proves control of its wallet key) at connection setup, before any topic traffic.
2. The connection is bound to the peer's verified nodeID (pubkey-derived address).
3. A failed/timed-out/malformed handshake closes the connection and reduces trust — no unauthenticated peer exchanges messages.
4. The signed transcript is domain-separated from transaction signatures and session-bound (replay/reflection-proof).

## Non-goals (deferred)

- nodeID-keyed banning/allowlist (stays IP-keyed for now; the verified nodeID is stored for a future follow-up).
- Transport encryption (sub-project C) — required for full MITM resistance.
- Sharing one identity across a peer's 4 topic connections (each connection handshakes independently — simplest given the architecture).

## Design

### 1. The signed transcript (security-load-bearing)

Both sides compute the same transcript per party and sign their own:
```
DomainTag   = []byte("QWID-P2P-HS-v1")          // fixed ASCII protocol tag
transcript(party) = DomainTag ‖ nonceI ‖ nonceR ‖ addr(party)   // 14 + 32 + 32 + 20 = 98 bytes
```
- **Domain separation:** the `QWID-P2P-HS-v1` prefix cannot be a valid transaction-signing payload (transactions serialize a different fixed binary structure via `GetBytesWithoutSignature`), so a handshake signature can never be cross-replayed as a transaction, nor vice versa. This matters because the SAME wallet key signs both.
- **Session binding / replay:** both fresh 32-byte nonces (`crypto/rand`) are included, so a signature is valid only for this exact session.
- **Reflection resistance:** each party signs its OWN `addr`, so the responder's signature (over `addr_R`) cannot be replayed as the initiator's (which must be over `addr_I`).

### 2. Wire messages (own length-prefixed framing on `net.Conn`)

Independent of the `MessageInitialization`/`<-END->` markers (the handshake is a distinct sub-protocol run first on the raw stream). Framing helper:
- `writeFrame(c net.Conn, payload []byte) error` — write 4-byte big-endian length then payload, under a write deadline.
- `readFrame(c net.Conn, maxLen int) ([]byte, error)` — read 4-byte length, reject if `> maxLen` (cap ~16 KB), `io.ReadFull` exactly that many bytes, under a read deadline. `io.ReadFull` reads exactly the frame so the stream is left clean for subsequent normal traffic.

Three messages (each a frame; fields inside are length-prefixed via a small helper or fixed offsets):
1. **Hello (I→R):** `initiatorPubKeyBytes` ‖ `nonceI(32)`.
2. **Resp (R→I):** `responderPubKeyBytes` ‖ `nonceR(32)` ‖ `sigR`, where `sigR = Sign(transcript(responder), primary=true).GetBytes()`.
3. **Confirm (I→R):** `sigI`, where `sigI = Sign(transcript(initiator), primary=true).GetBytes()`.

### 3. Handshake functions (dependency-injected identity → testable)

```go
// HandshakeIdentity is this node's signing identity for the handshake.
type HandshakeIdentity struct {
	PubKey  []byte                              // Account1.PublicKey.GetBytes() (Falcon-512 primary)
	Address common.Address                      // nodeID = PubKeyToAddress(PubKey, true) — see below
	Sign    func(data []byte) ([]byte, error)   // wraps wallet.Sign(data, true).GetBytes()
}
```

**nodeID derivation must be identical on both sides.** The transcript embeds `addr(party)`, and the verifier reconstructs the peer's transcript by deriving `addr_peer = PubKeyToAddress(peerPubKey, true)`. Therefore the *signer* must use the SAME derivation for its own `Address` — i.e. `self.Address = common.PubKeyToAddress(self.PubKey, true)` — NOT `wallet.MainAddress` unless verified identical. Build `self.Address` via `PubKeyToAddress(self.PubKey, true)` so the signer's and verifier's transcripts match byte-for-byte; if they diverged, every handshake would fail verification.

// HandshakeInitiator runs the dialing side; returns the peer's VERIFIED nodeID.
func HandshakeInitiator(c net.Conn, self HandshakeIdentity) (common.Address, error)

// HandshakeResponder runs the accepting side; returns the peer's VERIFIED nodeID.
func HandshakeResponder(c net.Conn, self HandshakeIdentity) (common.Address, error)
```

Each function: exchanges the three messages with an overall deadline (~10 s via `SetDeadline`); on receiving the peer's pubkey, derives `addr_peer = PubKeyToAddress(peerPubKey, true)`; reconstructs the peer's transcript; and calls `wallet.Verify(transcript, peerSig, peerPubKey, common.SigName(), common.SigName2(), common.IsPaused(), common.IsPaused2())`. Returns `addr_peer` on success, or an error (bad sig, malformed frame, oversize, deadline) on failure. Verification uses the package-level `wallet.Verify` (stateless), so only the local signing side needs the injected identity.

Production callers build `self` from `wallet.GetActiveWallet()` (PubKey = `Account1.PublicKey.GetBytes()`, Address = `MainAddress`, Sign wraps `wallet.Sign(data, true)`). If no active wallet exists, the node cannot peer (handshake fails closed) — acceptable (a keyless node has no identity).

### 4. Insertion into the connection lifecycle

- **Outbound** (`StartNewConnection`, `tcpip/listenerTcpService.go:111`): after `net.DialTCP` succeeds and before the receive loop begins (~:229), call `HandshakeInitiator(tcpConn, self)`. On error → close the conn, apply the existing failure handling (`ReduceTrustRegisterPeer`/ban path), return (do not enter the loop). On success → record the verified nodeID (below), proceed to the loop.
- **Inbound** (`Accept`/`RegisterPeer`, `tcpip/recieverTcpService.go:193,296`): immediately after the connection is accepted and registered, and BEFORE the receive loop reads any topic message from it, call `HandshakeResponder(tcpConn, self)`. On error → close, unregister, return false. On success → record the verified nodeID, proceed.
- The implementer must place these so the handshake completes before ANY normal `Send`/`Receive` topic traffic on that connection, on both sides — read the exact accept→receive wiring to position them (the handshake and the normal loop must not race on the same stream).

### 5. Identity binding & enforcement

- On success, store the verified nodeID for the connection: a `map[[6]byte]common.Address` keyed by `topic‖ip` (mirroring `peersConnected`), guarded by a mutex (reuse `PeersMutex` or a dedicated one), plus a log line. This is the foundation the deferred nodeID-ban/allowlist will use; B stores it and does not yet gate on it.
- On failure, the connection is closed and not used — this is the concrete NP-C3 fix (no peer exchanges messages without proving key control).

### 6. Error handling / determinism

- Node-local security; not consensus. Deterministic verification (pure over the transcript + peer pubkey).
- All new shared state is mutex-guarded (consistent with the NP-C1 discipline).
- The handshake deadline bounds a slow-loris on the handshake itself; the per-topic size caps + `readFrame` maxLen bound handshake-message memory.

## Testing

The handshake is fully testable off-network via `net.Pipe()` with two REAL PQ identities:

- **Happy path (mutual auth):** generate two node wallets/keypairs → two `HandshakeIdentity`; run `HandshakeInitiator` and `HandshakeResponder` on the two `net.Pipe` ends concurrently; assert each returns the OTHER's correct nodeID address, and both succeed.
- **Tampered signature → rejection:** flip a byte in `sigR` (or `sigI`) on the wire (a wrapping `net.Conn` that mutates one frame) → assert the verifying side returns an error and does not accept.
- **Wrong-nonce / replay:** a responder signature computed over a different `nonceI` fails verification (proves session binding).
- **Reflection:** the initiator's signature (over `addr_I`) does not verify as the responder's transcript (over `addr_R`).
- **Domain separation (unit):** assert the signed transcript begins with `QWID-P2P-HS-v1` and that a transaction's `GetBytesWithoutSignature` does not — documenting the two signing domains cannot collide.
- **Malformed/oversize frame:** `readFrame` rejects a length `> maxLen` and a truncated stream (deadline) without panicking.

If generating two real wallets in a unit test is impractical (CGO keygen cost), generate two `crypto/oqs` Falcon keypairs directly for the identities, or fall back to a single-identity self-handshake plus the tamper/oversize tests, and state the limitation — do not skip the tamper-rejection test (it is the security assertion).

Tests run with `GOROOT=/home/wonabru/sdk/go1.24.0`.

## Files touched

- `tcpip/handshake.go` (new) — `DomainTag`, transcript builder, `writeFrame`/`readFrame`, `HandshakeIdentity`, `HandshakeInitiator`/`HandshakeResponder`, and a helper to build `self` from the active wallet.
- `tcpip/listenerTcpService.go` — invoke `HandshakeInitiator` in `StartNewConnection` before the receive loop.
- `tcpip/recieverTcpService.go` — invoke `HandshakeResponder` after accept/register, before topic traffic; store the verified nodeID.
- `tcpip/handshake_test.go` (new) — `net.Pipe` end-to-end + tamper/oversize tests.
- (`tcpip` gains a `wallet` import.)

## Rollout / commit plan

Node-local (not `(CONSENSUS)`), but it IS a wire-protocol change to the connection setup — all nodes must run it to interoperate (fine under the coordinated branch):
1. `handshake.go`: transcript + framing + `HandshakeInitiator`/`Responder` + `HandshakeIdentity` + the `net.Pipe` end-to-end and tamper tests. (The whole crypto core, fully tested off-network.)
2. Wire into `StartNewConnection` (outbound) and the inbound accept path; store the verified nodeID; reject-on-failure. (Integration — build + review; the receive/accept wiring needs a live network to exercise.)

Not "done" until `tcpip` builds and the handshake tests pass, and `SECURITY_AUDIT.md` marks NP-C3 addressed (mutual PQ handshake + nodeID binding; note nodeID-ban/allowlist and full MITM/encryption remain — the latter in sub-project C).

## Deferred (follow-ups / other sub-projects)
- nodeID-keyed ban/allowlist (use the stored verified identity).
- Sub-project C — transport encryption / TLS (full MITM resistance; can layer an authenticated key exchange on this handshake).

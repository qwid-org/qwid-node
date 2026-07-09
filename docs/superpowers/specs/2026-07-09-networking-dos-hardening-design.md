# Networking Sub-Project A — DoS / Rate-Limit Hardening

**Date:** 2026-07-09
**Branch:** `security-fixes`
**Source:** `SECURITY_AUDIT.md` networking DoS surface — the single global ~151 MB message cap, and the absence of per-IP message-rate and reconnection-burst limits.
**Parent effort:** Networking-security infrastructure, decomposed into **A (this: DoS/rate hardening)**, **B (peer-auth handshake, NP-C3)**, **C (transport encryption / TLS)**. This spec is sub-project A only.

## Context and decisions

All four changes are **transport-layer only** — no wire/frame-format change, no wallet plumbing, no consensus change. Whitelisted IPs (own node, `WHITELIST_IP` peers, the `0.0.0.0` broadcast entry) remain exempt from every new limit, exactly as they already are for bans.

### Ground truth (from exploration)

- One global cap `common.MaxMessageSizeBytes = 151126018` (~151 MB) is enforced for **every** topic in the receive loop at `tcpip/listenerTcpService.go:270` (`if int32(len(r)) > common.MaxMessageSizeBytes`). The `topic [2]byte` is in scope there.
- `common.MessageInitialization` is a 4-byte **frame marker** derived from `MaxMessageSizeBytes` and validated at init (`common/const.go:144-148`); it is used as a fixed magic prefix on the wire, NOT to read a size. **This spec does not change it** (keeping the wire format identical).
- Real max legitimate message sizes: Nonce/SelfNonce ~6.5 KB (single fixed tx); Transaction ~6.7 KB **plus unbounded `OptData`** (contract-deploy init code — no `MaxCodeSize` constant exists); Sync ~3.2 MB (up to `NumberOfHashesInBucket = 20` blocks × ~160 KB of tx-hash lists — full blocks carry tx *hashes*, not tx bodies).
- Existing abuse response: `ReduceTrustRegisterPeer(ip)` decrements a per-IP trust counter (`validPeersConnected[ip]`, init `ConnectionMaxTries = 10`); at `trust <= 0` the IP is `BanIP`'d. Ban duration `common.BannedTimeSeconds = 2` is added to a **seconds** timestamp (`bannedIP[ip] = GetCurrentTimeStampInSecond() + BannedTimeSeconds`) — i.e. a **2-second** ban.
- Ban/whitelist state lives in `tcpip/helper.go` (`bannedIP`, `whiteListIPs`, `bannedIPMutex`, `IsIPBanned`, `isWhitelisted`, `BanIP`). Inbound accept path: `RegisterPeer` (`recieverTcpService.go:296`). Outbound dial path: `StartNewConnection` (`listenerTcpService.go:111`).

## Goals

1. Replace the single 151 MB enforcement cap with **per-topic caps** sized to each topic's real maximum (generous, so no legit traffic breaks).
2. Add a **per-IP message-rate limiter** (sliding window) on established connections.
3. Add a **per-IP reconnection-burst limiter** on connection attempts.
4. Increase the **ban duration** from 2 s to a moderate value.

## Non-goals (out of scope)

- Any change to the wire frame (`MessageInitialization`), the global `MaxMessageSizeBytes` marker seed, or message framing.
- A `MaxCodeSize`/`MaxOptData` consensus bound on transactions (cleaner long-term, but a validity/consensus change — noted as a follow-up, not done here).
- Peer authentication (sub-project B) and transport encryption (sub-project C).

## Design

### 1. Per-topic message-size caps

Add per-topic cap constants and a lookup helper (co-located with the topic definitions — `tcpip`, where `Ports`/topic constants live; if the topic constants are in `common`, place them there instead). Values:

| Topic | Real max | Cap |
|---|---|---|
| `NonceTopic` / `SelfNonceTopic` | ~6.5 KB | **65536** (64 KB) |
| `TransactionTopic` | ~6.7 KB + OptData | **1048576** (1 MB) |
| `SyncTopic` | ~3.2 MB | **16777216** (16 MB) |
| `RPCTopic` | — | **1048576** (1 MB) |

```go
// MaxMessageSizeForTopic returns the per-topic inbound message-size cap (bytes).
// Unknown topics fall back to the tightest cap. Replaces the single 151 MB
// global cap in the receive loop, drastically shrinking the buffering DoS
// surface on the small-message topics without breaking large contract-deploy
// txs (TransactionTopic) or block-header sync batches (SyncTopic).
func MaxMessageSizeForTopic(topic [2]byte) int32 { ... } // returns the value from the table; default 65536
```

Enforcement: in `tcpip/listenerTcpService.go:270`, replace `common.MaxMessageSizeBytes` with `MaxMessageSizeForTopic(topic)`. The existing over-size handling (`ReduceTrustRegisterPeer` → `BanIP` at trust ≤ 0) is unchanged. The global `common.MaxMessageSizeBytes` and `MessageInitialization` remain as-is (the wire marker is untouched; the per-topic cap does the real rejection, so a 151 MB payload is now rejected after at most one over-cap read).

### 2. Per-IP message-rate limiter

In `tcpip/helper.go`, add a per-IP sliding-window counter guarded by a dedicated mutex:

```go
type rateWindow struct {
	windowStart int64 // unix seconds
	count       int
}
var msgRate = map[[4]byte]*rateWindow{}
var msgRateMutex sync.Mutex

// allowInWindow is the pure, testable core: given the current window state and
// `now`, it records one event and reports whether the count is within `limit`
// over `windowSecs`. Resets the window when it has elapsed.
func allowInWindow(w *rateWindow, now int64, limit int, windowSecs int64) bool {
	if now-w.windowStart >= windowSecs {
		w.windowStart = now
		w.count = 0
	}
	w.count++
	return w.count <= limit
}

// AllowMessageFromIP returns false when `ip` has exceeded MessageRateLimit
// messages within MessageRateWindowSeconds. Whitelisted IPs always return true
// and are not counted.
func AllowMessageFromIP(ip [4]byte) bool { ... } // isWhitelisted bypass; lock; lookup/create rateWindow; allowInWindow
```

Constants (`common/const.go`): `MessageRateLimit = 100`, `MessageRateWindowSeconds = 10`.

> **Tuning caveat:** `MessageRateLimit` is the value most likely to need field adjustment — a busy tx-gossip peer or a fast-syncing peer could legitimately exceed a too-tight rate. It is node-local and changeable without a fork, and configured peers listed in `WHITELIST_IP` bypass it entirely (the operator's safety valve). 100 msgs / 10 s (10/s) is a conservative starting point that still blocks the thousands-per-second flood this limit targets; raise it if legitimate peers are being throttled. Because it is transport-only (never affects tx/block validity), a mismatch between nodes only affects local connectivity, never consensus.

Call site: in the receive loop, **after** a complete message is assembled and **before** dispatching it to `receiveChan` (around `listenerTcpService.go:265`, the `<-END->`-complete branch). If `!AllowMessageFromIP(ip)`: `ReduceTrustRegisterPeer(ip)` and `BanIP(ip)` when trust ≤ 0 — the SAME response as the size-violation path — then drop the message (do not dispatch it).

### 3. Per-IP reconnection-burst limiter

In `tcpip/helper.go`, a second per-IP window (same `allowInWindow` core, separate map/mutex):

```go
var connRate = map[[4]byte]*rateWindow{}
var connRateMutex sync.Mutex

// AllowConnectionFromIP returns false when `ip` has exceeded ConnectionRateLimit
// connection attempts within ConnectionRateWindowSeconds. Whitelisted IPs bypass.
func AllowConnectionFromIP(ip [4]byte) bool { ... }
```

Constants: `ConnectionRateLimit = 5`, `ConnectionRateWindowSeconds = 60`.

Call sites:
- **Inbound** — in `RegisterPeer` (`recieverTcpService.go:296`), after parsing the IP and the existing `IsIPBanned` check: if `!AllowConnectionFromIP(ip)` → `BanIP(ip)` and return `false` (reject the connection).
- **Outbound** — in `StartNewConnection` (`listenerTcpService.go:111`), before the dial loop: if `!AllowConnectionFromIP(ip)` for a non-whitelisted target, skip/return (don't hammer). (Outbound targets are normally peers we chose; the whitelist bypass means our own peers are never throttled — this mainly bounds retry storms against a flaky/hostile address.)

### 4. Ban-duration tuning

Change `common.BannedTimeSeconds` from `2` to **`60`** (a 1-minute ban ≈ 6 block intervals). Kept moderate deliberately: whitelisted peers are exempt, and in a 6-peer network an over-long ban could partition legitimate peers that trip a transient limit. No other logic changes (bans still expire via the existing timestamp check in `IsIPBanned`).

### Map growth / cleanup

`msgRate`/`connRate` hold one entry per distinct connecting IP. In this network that set is small (established TCP connections only — spoofed source IPs cannot complete the handshake; `MaxPeersConnected = 6`). Entries reset in place on window elapse, so they don't grow per-window. To bound long-run growth, prune an IP's entry opportunistically when it is banned (delete from both maps in `BanIP`, under the respective mutexes) and/or when its window is stale on access. Document that the maps are bounded by real connecting IPs.

## Error handling / determinism

- These are node-local defensive limits; they do not affect block/tx validity or consensus, so nodes need not agree on them. A node may tune the constants without forking.
- All new state is mutex-guarded (`msgRateMutex`, `connRateMutex`), consistent with the NP-C1 fix discipline.
- Whitelisted IPs bypass all four limits — a misconfigured limit can never partition an operator's declared peers.

## Testing

Pure-unit-testable core (no network):

- **`MaxMessageSizeForTopic`:** returns the correct cap for each of the 5 topics and the fallback for an unknown topic.
- **`allowInWindow`:** returns true up to `limit`, false on the `(limit+1)`-th call within the window; after advancing `now` past `windowSecs`, the count resets and calls succeed again. Table-driven with an injected `now` (no real clock).
- **`AllowMessageFromIP` / `AllowConnectionFromIP`:** a non-whitelisted IP is throttled at its limit; a **whitelisted** IP is never throttled (add it via `AddWhiteListIPs`, hammer past the limit, assert always true); banning an IP prunes its entries.
- **`BannedTimeSeconds`:** assert the constant is 60 (guards against accidental revert) — or assert an IP banned now is still banned < 60 s later and expired after (using the existing timestamp logic if a clock can be injected; otherwise assert the constant).

Tests run with `GOROOT=/home/wonabru/sdk/go1.24.0`.

## Files touched

- `common/const.go` — new constants (per-topic caps if topics live here; `MessageRateLimit`, `MessageRateWindowSeconds`, `ConnectionRateLimit`, `ConnectionRateWindowSeconds`); change `BannedTimeSeconds` 2 → 60.
- `tcpip/helper.go` — `rateWindow`, `allowInWindow`, `AllowMessageFromIP`, `AllowConnectionFromIP`, the two maps+mutexes, prune-on-ban; `MaxMessageSizeForTopic` (here or with the topic constants).
- `tcpip/listenerTcpService.go` — per-topic cap at the size check (`:270`); message-rate check before dispatch (`~:265`); reconnection check in `StartNewConnection` (`:111`).
- `tcpip/recieverTcpService.go` — reconnection check in `RegisterPeer` (`:296`).
- Tests: `tcpip/ratelimit_test.go` (new).

## Rollout / commit plan

Section-sized commits (no `(CONSENSUS)` label — node-local, not consensus):
1. `allowInWindow` core + rate/reconnection limiter functions + maps + tests.
2. Per-topic size caps (`MaxMessageSizeForTopic`) + wire into the receive-loop size check + tests.
3. Wire the message-rate check into the receive loop and the reconnection check into `RegisterPeer`/`StartNewConnection`; bump `BannedTimeSeconds`; prune-on-ban.

Not "done" until `tcpip` and `common` build and the new tests pass.

## Deferred (follow-ups, not this sub-project)
- A `MaxCodeSize`/`MaxOptData` transaction-validity bound (consensus change) to tighten the TransactionTopic cap further.
- Sub-project B (peer-auth handshake, NP-C3) and C (transport encryption / TLS).

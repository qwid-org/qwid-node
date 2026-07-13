# NP Mediums Cluster — NP-M1/M2/M4/M6/M7/M10/M13/M14

**Date:** 2026-07-13
**Branch:** `security-fixes`
**Source:** `SECURITY_AUDIT.md` reconciliation — the eight OPEN networking MEDIUM findings (cluster A of the mediums sweep).

## Context

Eight node-local networking mediums remain: resource leaks, missing backpressure/backoff, an unbounded sync request, and a topology leak. All are node-local reliability/DoS/hygiene fixes — no consensus, block/tx validity, or wire-format change. They reuse patterns already validated in the NP DoS-resilience cluster (OB-120).

## Decisions (confirmed)
- **NP-M14:** the `hi` message's peer-IP list (`PP`) is also consumed by receivers for peer discovery, so instead of removing it, send a **bounded random subset** of up to `MaxPeersSharedInHi = 3` connected IPs. Preserves discovery; no single message reveals the full topology.
- All other seven: the fixes below (sensible defaults, no further options).

## Design

Each finding is independent. Where a pure helper can be extracted, it is (for socket-free unit tests); loop/log/alloc-only changes are verified by build + inspection (noted per item).

### NP-M1 — bannedIP map unbounded growth (`tcpip/helper.go`)
Bans carry a TTL (`bannedIP[ip] = now + BannedTimeSeconds`) and `IsIPBanned` already checks expiry, but **expired entries are never deleted**, so the map grows without bound. Fix:
- In `IsIPBanned`, when an entry is found expired, delete it (lazy eviction). This requires the write lock, so change `IsIPBanned` to take `bannedIPMutex.Lock()` (it currently takes `RLock`) — or split into a fast RLock read + a rare Lock-delete. Chosen: promote to `Lock()` for simplicity (the ban check is not on the hottest path; the map is small).
- In `BanIP`, before inserting, opportunistically sweep and delete any already-expired entries (bounded amortized cleanup) so the map self-trims even for IPs never re-checked.
- **Test (pure-ish, package `tcpip`):** seed `bannedIP[ip] = past` directly, call `IsIPBanned(ip)` → returns false AND the entry is gone from the map; a future-dated entry stays and returns true.

### NP-M2 — ChanPeer blocking sends (`tcpip/listenerTcpService.go`)
The three sends `ChanPeer <- x` (`:100`, `:239`, `:247`) block if the consumer stalls, which can wedge the sending goroutines. Convert each to a non-blocking send with a warning log on drop:
```go
select {
case ChanPeer <- x:
default:
	logger.GetLogger().Println("NP-M2: ChanPeer full, dropping peer notification")
}
```
The periodic peer-discovery loop re-establishes any dropped notification, so a rare drop under extreme load is safe. **Verification:** build + inspection (channel-send change; no isolated unit test).

### NP-M4 — reconnection counter reset cadence (`tcpip/listenerTcpService.go`)
`resetNumber++; if resetNumber%100==0 { reconnectionTries = 0 }` (`:263-265`) zeroes the consecutive-read-error counter every 100 loop iterations regardless of connection health, undermining `ConnectionMaxTries`. Fix:
- Remove `resetNumber := 0` (`:228`) and the `resetNumber++`/`%100` reset block (`:263-265`).
- Reset `reconnectionTries = 0` on a **genuine successful frame receipt** — after the `<-ERR->`/`<-CLS->` special-case checks, when `r` is real payload (right before the `rTopic` assembly, `~:350`). So the counter reflects *consecutive* errors and `reconnectionTries > ConnectionMaxTries` triggers reconnect as intended. (The existing `reconnectionTries = 0` after a successful re-dial and `reconnectionTries++` on error are unchanged.)
- **Verification:** build + inspection (intricate receive-loop change; integration-level behavior, no isolated unit test).

### NP-M6 — RPC client fixed retry interval, no backoff (`rpc/client/client.go`)
Both dial-retry loops `time.Sleep(retryInterval)` (fixed 5s). Add exponential backoff via a pure helper and use it in both loops:
```go
const (
	initialBackoff = 1 * time.Second
	maxBackoff     = 30 * time.Second
)
// nextBackoff doubles cur, capped at maxBackoff. Pure/deterministic.
func nextBackoff(cur time.Duration) time.Duration {
	next := cur * 2
	if next > maxBackoff {
		return maxBackoff
	}
	return next
}
```
Each loop starts at `initialBackoff`, sleeps, then `backoff = nextBackoff(backoff)`; reset to `initialBackoff` on a successful dial. Keep `retryInterval` only if still referenced elsewhere; otherwise remove it. **Test:** `nextBackoff` sequence 1s→2s→4s→…→30s (cap holds).

### NP-M7 — fixed 1MB reply buffer per RPC call (`rpc/client/client.go`)
`reply := make([]byte, bufferSize)` (1MB) is allocated per call then **discarded** — `net/rpc`'s gob decoder allocates and sizes the `[]byte` reply itself. Change to `var reply []byte`. No cap is removed (none existed; gob decodes the full server response either way). Remove the now-unused `bufferSize` const if nothing else references it. **Verification:** build + inspection (the existing RPC round-trip tests, `rpc/client/client_test.go` `TestCallPairs*`, still pass).

### NP-M10 — silent drop on full tx send channel (`services/transactionServices/serviceTransaction.go`)
`Send` uses `select { case SendChanTx <- nb: return true; default: return false }` — a full channel drops silently (best-effort gossip by design). Keep the non-blocking semantics (blocking would push backpressure into callers) but make the drop **observable**: log a warning in the `default` branch before `return false`. Propagation is already covered by on-arrival `BroadcastTxn` + the periodic delta loop, so a dropped best-effort send is not a correctness loss. **Verification:** build + inspection (log addition).

### NP-M13 — unbounded block-header range request (`services/syncService/onmessage.go`)
The `gh` handler reads attacker-controlled `bHeight`/`eHeight` and calls `SendHeaders(addr, bHeight, eHeight)` with no span cap, so a peer can request an enormous range and force a huge response (DoS). Legitimate sync already bounds its span to `common.NumberOfHashesInBucket` (= 20). Fix: clamp the requested span to that same bound via a pure helper, before `SendHeaders`:
```go
// clampHeaderSpan bounds [bHeight, eHeight] so eHeight-bHeight <= NumberOfHashesInBucket
// and bHeight <= eHeight, matching the legitimate sync batch size. NP-M13.
func clampHeaderSpan(bHeight, eHeight int64) (int64, int64) {
	if eHeight < bHeight {
		eHeight = bHeight
	}
	if eHeight-bHeight > common.NumberOfHashesInBucket {
		eHeight = bHeight + common.NumberOfHashesInBucket
	}
	return bHeight, eHeight
}
```
The `gh` handler applies it: `bHeight, eHeight = clampHeaderSpan(bHeight, eHeight)` before `SendHeaders`. Honest peers (span ≤ 20) are unaffected. **Test:** a span of 10 is unchanged; a span of 10000 clamps to 20; `eHeight < bHeight` normalizes to `bHeight`.

### NP-M14 — peer-topology leak in `hi` (`services/syncService/serviceSync.go`)
`generateSyncMsgHeight` sets `PP = tcpip.GetIPsConnected()` (the full connected-peer list). Replace with a bounded random subset via a pure helper, and add `MaxPeersSharedInHi` to `common/const.go`:
```go
// (common/const.go)
MaxPeersSharedInHi int = 3 // NP-M14: cap peer IPs shared per 'hi' message (topology-leak reduction)

// (serviceSync.go) sampleIPs returns up to n distinct entries of ips chosen at
// random (all of ips if len(ips) <= n). Preserves discovery without revealing
// the full peer set in any single message. NP-M14.
func sampleIPs(ips [][]byte, n int) [][]byte {
	if len(ips) <= n {
		return ips
	}
	idx := rand.Perm(len(ips))[:n]
	out := make([][]byte, 0, n)
	for _, i := range idx {
		out = append(out, ips[i])
	}
	return out
}
```
Usage: `n.TransactionsBytes[[2]byte{'P','P'}] = sampleIPs(tcpip.GetIPsConnected(), common.MaxPeersSharedInHi)`. Uses `math/rand` (add the import to `serviceSync.go`). **Test:** `len(sampleIPs(ips, 3)) == min(3, len(ips))`; every returned entry is an element of the input; entries are distinct; `len(ips) <= n` returns all.

## Non-goals
- Changing the tx-gossip design (NP-M10 stays best-effort), the RPC single-connection model (pooling is a separate deferred item), or any wire/consensus surface.
- Cryptographically-strong topology hiding (NP-M14 is leak *reduction*, not elimination — repeated sampling still gradually reveals neighbors on an open-peering network; this is the accepted tradeoff to keep discovery working).
- Perfect backpressure (NP-M2/M10 remain drop-with-log; the network tolerates rare drops via re-discovery / re-gossip).

## Error handling / determinism
- All node-local; no consensus/tx/block/wire impact. Commits are `OB-124` (not `(CONSENSUS)`).
- NP-M1 makes ban storage self-trimming; NP-M13 makes a malicious header request a no-op-beyond-20; NP-M14 reduces per-message disclosure. None changes the validity of any block/tx.

## Testing
Pure helpers give socket-free unit tests: `IsIPBanned` expired-eviction (NP-M1), `nextBackoff` sequence (NP-M6), `clampHeaderSpan` (NP-M13), `sampleIPs` invariants (NP-M14). NP-M2/M4/M7/M10 are channel/loop/alloc/log changes verified by build + inspection + the existing `rpc/client` round-trip tests (NP-M7); this limitation is stated per-item above. Tests run with `GOROOT=/home/wonabru/sdk/go1.24.0`; build `GOROOT=… go build ./...`.

## Files touched
- `common/const.go` — add `MaxPeersSharedInHi = 3`.
- `tcpip/helper.go` — NP-M1 ban-map eviction.
- `tcpip/listenerTcpService.go` — NP-M2 non-blocking ChanPeer sends; NP-M4 reconnect-counter reset.
- `rpc/client/client.go` — NP-M6 backoff; NP-M7 reply-buffer.
- `services/transactionServices/serviceTransaction.go` — NP-M10 drop-logging.
- `services/syncService/onmessage.go` — NP-M13 header-span clamp (+ `clampHeaderSpan`).
- `services/syncService/serviceSync.go` — NP-M14 `sampleIPs` + usage.
- New tests: `tcpip/ban_evict_test.go`, `rpc/client/backoff_test.go`, `services/syncService/sync_bounds_test.go` (covers `clampHeaderSpan` + `sampleIPs`).

## Rollout / commit plan
`OB-124` commits (node-local, not `(CONSENSUS)`), grouped by file/theme:
1. NP-M1 — ban-map eviction (+ test).
2. NP-M2 + NP-M4 — `listenerTcpService.go` non-blocking sends + reconnect-reset.
3. NP-M6 + NP-M7 — `rpc/client` backoff + reply-buffer (+ backoff test).
4. NP-M10 — tx-send drop logging.
5. NP-M13 — header-span clamp (+ test).
6. NP-M14 — bounded peer sampling (+ test).

Not "done" until the touched packages build and the new tests pass, and `SECURITY_AUDIT.md` reconciliation moves NP-M1/M2/M4/M6/M7/M10/M13/M14 to FIXED (with NP-M14's leak-reduction residual noted).

## Deferred (follow-ups)
- RPC connection pooling / correlation IDs (removes the single-connection serialization; NP-M7's sibling).
- The EVM/DB mediums (cluster B) and wallet mediums (cluster C).
- Remaining deferred-by-design partials (DB-C4, NP-C4/C5, etc.).

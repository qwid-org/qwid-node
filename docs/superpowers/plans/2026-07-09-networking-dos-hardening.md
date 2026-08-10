# Networking DoS-Hardening Implementation Plan (sub-project A)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the single ~151 MB message cap with per-topic caps, add per-IP message-rate and reconnection-burst limiters, and lengthen the ban duration — all transport-layer, no wire/consensus change.

**Architecture:** Add pure, unit-testable limiter primitives (`allowInWindow`, per-IP sliding-window maps) and a `MaxMessageSizeForTopic` lookup in `tcpip/helper.go`, backed by new constants in `common/const.go`; then wire them into the receive loop and the inbound/outbound connection paths. Whitelisted IPs (own node, `WHITELIST_IP` peers) bypass every limit.

**Tech Stack:** Go 1.23.6; `tcpip` + `common` packages.

## Global Constraints

- Build/test with `GOROOT=/home/wonabru/sdk/go1.24.0`. Example: `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./tcpip/`.
- Branch `security-fixes`. Commit `OB-xx` (NOT `(CONSENSUS)` — these are node-local, not consensus). End messages with `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- **No wire-format change.** Do NOT touch `common.MessageInitialization` or `common.MaxMessageSizeBytes` (the frame marker + its init check at `common/const.go:144-148` stay as-is). The per-topic caps are a SEPARATE enforcement value.
- **Whitelisted IPs bypass all limits** — `isWhitelisted(ip)` short-circuits the rate/reconnection checks (already the pattern for bans).
- **Reuse the existing abuse response** — `ReduceTrustRegisterPeer(ip)` then `BanIP(ip)` when trust ≤ 0. Do not invent a new ban path.
- Topics are `tcpip` package-level: `TransactionTopic={'T','T'}`, `NonceTopic={'N','N'}`, `SelfNonceTopic={'S','S'}`, `SyncTopic={'B','B'}`, `RPCTopic={'R','P'}` (`tcpip/recieverTcpService.go:31-35`). The cap *values* live in `common` (no import cycle); the topic→cap *lookup* lives in `tcpip`.
- `common/const.go` uses a `var (...)` block (values include a `[4]byte` array, so not `const`). Add the new values there.

---

## File Structure

- `common/const.go` — new vars: per-topic cap sizes, rate/reconnection limits+windows; change `BannedTimeSeconds` 2 → 60.
- `tcpip/helper.go` — `MaxMessageSizeForTopic`; `rateWindow` + `allowInWindow`; `AllowMessageFromIP`/`AllowConnectionFromIP` + maps/mutexes; `pruneRateLimits` + call in `BanIP`.
- `tcpip/listenerTcpService.go` — per-topic cap at the size check (`:269`); message-rate check before dispatch (`~:286`); reconnection check in `StartNewConnection` (`:111`).
- `tcpip/recieverTcpService.go` — reconnection check in `RegisterPeer` (`:311`).
- `tcpip/ratelimit_test.go` (new) — pure unit tests.

---

## Task 1: Limiter primitives + per-topic caps + constants (all unit-tested)

**Files:**
- Modify: `common/const.go` (new vars; `BannedTimeSeconds` 2 → 60)
- Modify: `tcpip/helper.go` (add functions/maps; prune in `BanIP`)
- Test: `tcpip/ratelimit_test.go` (new)

**Interfaces:**
- Consumes: `common.GetCurrentTimeStampInSecond() int64`, `isWhitelisted(ip [4]byte) bool`, topic constants.
- Produces: `MaxMessageSizeForTopic(topic [2]byte) int32`, `allowInWindow(w *rateWindow, now int64, limit int, windowSecs int64) bool`, `AllowMessageFromIP(ip [4]byte) bool`, `AllowConnectionFromIP(ip [4]byte) bool`, `pruneRateLimits(ip [4]byte)`.

- [ ] **Step 1: Add the constants**

In `common/const.go`, inside the existing `var (...)` block, add (and change `BannedTimeSeconds int64 = 2` to `= 60`):

```go
	BannedTimeSeconds int64 = 60 // DoS hardening: was 2s; ~6 block intervals

	// Per-topic inbound message-size caps (bytes) — DoS hardening (sub-project A).
	// Replace the single 151MB MaxMessageSizeBytes ENFORCEMENT (the wire marker
	// MessageInitialization/MaxMessageSizeBytes are unchanged). Sized generously
	// per topic so no legit traffic breaks.
	MaxMsgSizeSmall int32 = 65536    // 64KB  — Nonce/SelfNonce (tiny fixed messages)
	MaxMsgSizeTx    int32 = 1048576  // 1MB   — Transaction (unbounded OptData / contract deploys)
	MaxMsgSizeSync  int32 = 16777216 // 16MB  — Sync (block-header batches, ~3.2MB real max)
	MaxMsgSizeRPC   int32 = 1048576  // 1MB   — RPC (localhost-bound)

	// Per-IP rate limits — DoS hardening.
	MessageRateLimit                  int   = 100 // max messages per window per IP
	MessageRateWindowSeconds          int64 = 10
	ConnectionRateLimit               int   = 5   // max connection attempts per window per IP
	ConnectionRateWindowSeconds       int64 = 60
```

(Keep `MessageInitialization` and `MaxMessageSizeBytes` exactly as they are.)

- [ ] **Step 2: Write the failing tests**

Create `tcpip/ratelimit_test.go`:

```go
package tcpip

import (
	"testing"

	"github.com/qwid-org/qwid-node/common"
)

func TestMaxMessageSizeForTopic(t *testing.T) {
	cases := []struct {
		topic [2]byte
		want  int32
	}{
		{NonceTopic, common.MaxMsgSizeSmall},
		{SelfNonceTopic, common.MaxMsgSizeSmall},
		{TransactionTopic, common.MaxMsgSizeTx},
		{SyncTopic, common.MaxMsgSizeSync},
		{RPCTopic, common.MaxMsgSizeRPC},
		{[2]byte{'?', '?'}, common.MaxMsgSizeSmall}, // unknown -> tightest
	}
	for _, c := range cases {
		if got := MaxMessageSizeForTopic(c.topic); got != c.want {
			t.Errorf("topic %v: got %d want %d", c.topic, got, c.want)
		}
	}
}

func TestAllowInWindow(t *testing.T) {
	w := &rateWindow{}
	const limit, window = 3, 10
	base := int64(1000)
	// First `limit` events in the window are allowed; the next is not.
	for i := 0; i < limit; i++ {
		if !allowInWindow(w, base, limit, window) {
			t.Fatalf("event %d within limit should be allowed", i)
		}
	}
	if allowInWindow(w, base, limit, window) {
		t.Fatal("event over limit within window must be denied")
	}
	// Advancing past the window resets the count.
	if !allowInWindow(w, base+window, limit, window) {
		t.Fatal("first event in a new window must be allowed")
	}
}

func TestAllowMessageFromIPWhitelistBypass(t *testing.T) {
	wl := [4]byte{9, 9, 9, 9}
	AddWhiteListIPs(wl)
	// Hammer well past the limit; a whitelisted IP is never throttled.
	for i := 0; i < common.MessageRateLimit+50; i++ {
		if !AllowMessageFromIP(wl) {
			t.Fatal("whitelisted IP must never be message-rate-limited")
		}
	}
}

func TestAllowMessageFromIPThrottles(t *testing.T) {
	ip := [4]byte{7, 0, 0, 1} // not whitelisted, not banned
	// This test uses the real clock, so tolerate at most ONE window reset: the
	// loop runs in microseconds, so it can straddle at most one 1-second
	// boundary => at most 2 windows => at most 2*limit allowed. Doing 2*limit+1
	// calls therefore GUARANTEES at least one denial. (The exact per-window
	// count is covered deterministically by TestAllowInWindow with an injected
	// clock.)
	n := 2*common.MessageRateLimit + 1
	allowed := 0
	for i := 0; i < n; i++ {
		if AllowMessageFromIP(ip) {
			allowed++
		}
	}
	if allowed >= n {
		t.Fatalf("AllowMessageFromIP never throttled: %d/%d allowed", allowed, n)
	}
}

func TestPruneRateLimitsOnBan(t *testing.T) {
	ip := [4]byte{7, 0, 0, 2}
	AllowMessageFromIP(ip)
	AllowConnectionFromIP(ip)
	pruneRateLimits(ip)
	msgRateMutex.Lock()
	_, m := msgRate[ip]
	msgRateMutex.Unlock()
	connRateMutex.Lock()
	_, c := connRate[ip]
	connRateMutex.Unlock()
	if m || c {
		t.Fatal("pruneRateLimits must delete both rate entries")
	}
}

func TestBannedTimeSecondsLengthened(t *testing.T) {
	if common.BannedTimeSeconds != 60 {
		t.Fatalf("BannedTimeSeconds = %d, want 60", common.BannedTimeSeconds)
	}
}
```

- [ ] **Step 3: Run to verify it fails**

Run: `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./tcpip/ -run 'TestMaxMessageSizeForTopic|TestAllowInWindow|TestAllow|TestPrune|TestBannedTime'`
Expected: FAIL — `MaxMessageSizeForTopic`/`rateWindow`/`allowInWindow`/`AllowMessageFromIP`/etc. undefined.

- [ ] **Step 4: Implement the primitives in `tcpip/helper.go`**

Add (`sync` and `common` are already imported):

```go
// MaxMessageSizeForTopic returns the per-topic inbound message-size cap in bytes,
// replacing the single global MaxMessageSizeBytes at the receive-loop check.
// Unknown topics get the tightest cap. Shrinks the buffering DoS surface without
// breaking large contract-deploy txs (TransactionTopic) or block sync batches.
func MaxMessageSizeForTopic(topic [2]byte) int32 {
	switch topic {
	case NonceTopic, SelfNonceTopic:
		return common.MaxMsgSizeSmall
	case TransactionTopic:
		return common.MaxMsgSizeTx
	case SyncTopic:
		return common.MaxMsgSizeSync
	case RPCTopic:
		return common.MaxMsgSizeRPC
	default:
		return common.MaxMsgSizeSmall
	}
}

type rateWindow struct {
	windowStart int64 // unix seconds
	count       int
}

var (
	msgRate       = map[[4]byte]*rateWindow{}
	msgRateMutex  sync.Mutex
	connRate      = map[[4]byte]*rateWindow{}
	connRateMutex sync.Mutex
)

// allowInWindow records one event at `now` and reports whether the running count
// stays within `limit` over a `windowSecs` sliding window (reset when the window
// elapses). Pure/deterministic given its inputs.
func allowInWindow(w *rateWindow, now int64, limit int, windowSecs int64) bool {
	if now-w.windowStart >= windowSecs {
		w.windowStart = now
		w.count = 0
	}
	w.count++
	return w.count <= limit
}

// AllowMessageFromIP reports whether ip may send another message now, throttling
// at MessageRateLimit per MessageRateWindowSeconds. Whitelisted IPs always pass
// and are not counted.
func AllowMessageFromIP(ip [4]byte) bool {
	if isWhitelisted(ip) {
		return true
	}
	now := common.GetCurrentTimeStampInSecond()
	msgRateMutex.Lock()
	defer msgRateMutex.Unlock()
	w, ok := msgRate[ip]
	if !ok {
		w = &rateWindow{windowStart: now}
		msgRate[ip] = w
	}
	return allowInWindow(w, now, common.MessageRateLimit, common.MessageRateWindowSeconds)
}

// AllowConnectionFromIP reports whether ip may make another connection attempt
// now, throttling at ConnectionRateLimit per ConnectionRateWindowSeconds.
// Whitelisted IPs always pass.
func AllowConnectionFromIP(ip [4]byte) bool {
	if isWhitelisted(ip) {
		return true
	}
	now := common.GetCurrentTimeStampInSecond()
	connRateMutex.Lock()
	defer connRateMutex.Unlock()
	w, ok := connRate[ip]
	if !ok {
		w = &rateWindow{windowStart: now}
		connRate[ip] = w
	}
	return allowInWindow(w, now, common.ConnectionRateLimit, common.ConnectionRateWindowSeconds)
}

// pruneRateLimits drops an IP's rate/reconnection state — called when it is banned,
// to bound long-run map growth.
func pruneRateLimits(ip [4]byte) {
	msgRateMutex.Lock()
	delete(msgRate, ip)
	msgRateMutex.Unlock()
	connRateMutex.Lock()
	delete(connRate, ip)
	connRateMutex.Unlock()
}
```

Then in `BanIP` (`tcpip/helper.go`), after the `bannedIPMutex.Unlock()` line (the one right after setting `bannedIP[ip] = ...`), add a call so a banned IP's rate state is dropped:

```go
	pruneRateLimits(ip)
```

(Place it AFTER `bannedIPMutex.Unlock()` and outside any `PeersMutex` section — `pruneRateLimits` takes only `msgRateMutex`/`connRateMutex`, which are held nowhere else in `BanIP`, so no lock-ordering issue.)

- [ ] **Step 5: Run tests + build**

Run: `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./tcpip/ -run 'TestMaxMessageSizeForTopic|TestAllowInWindow|TestAllow|TestPrune|TestBannedTime' -v && GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go build ./...`
Expected: PASS, build OK.

- [ ] **Step 6: Commit**

```bash
git add common/const.go tcpip/helper.go tcpip/ratelimit_test.go
git commit -m "OB-114 net DoS: per-topic size caps + per-IP rate/reconnection limiter primitives

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 2: Wire the primitives into the receive loop and connection paths

**Files:**
- Modify: `tcpip/listenerTcpService.go` (size check `:269`; message-rate check `~:286`; reconnection check in `StartNewConnection` `:111`)
- Modify: `tcpip/recieverTcpService.go` (reconnection check in `RegisterPeer` `:311`)

**Interfaces:**
- Consumes: `MaxMessageSizeForTopic`, `AllowMessageFromIP`, `AllowConnectionFromIP` (Task 1), existing `ReduceTrustRegisterPeer`, `BanIP`, `validPeersConnected`, `PeersMutex`.

- [ ] **Step 1: Per-topic size cap**

In `tcpip/listenerTcpService.go` (~`:269`), replace:
```go
			if int32(len(r)) > common.MaxMessageSizeBytes {
```
with:
```go
			if int32(len(r)) > MaxMessageSizeForTopic(topic) {
```
(Everything inside the block — the `ReduceTrustRegisterPeer`/`BanIP` handling — is unchanged.)

- [ ] **Step 2: Message-rate check before dispatch**

In the same file, the complete-message dispatch (~`:284-287`) currently reads:
```go
					if bytes.Equal(r[:4], common.MessageInitialization[:]) {
						receiveChan <- append(ip[:], r[4:]...)
					} else {
```
Change the matched branch to rate-check before dispatching (mirroring `StartNewConnection`'s in-lock trust read):
```go
					if bytes.Equal(r[:4], common.MessageInitialization[:]) {
						if !AllowMessageFromIP(ip) {
							logger.GetLogger().Println("message rate limit exceeded for", ip)
							PeersMutex.Lock()
							ReduceTrustRegisterPeer(ip)
							trust, ok := validPeersConnected[ip]
							PeersMutex.Unlock()
							if ok && trust <= 0 {
								BanIP(ip)
								receiveChan <- []byte("EXIT")
								return
							}
							continue // drop this message; do not dispatch
						}
						receiveChan <- append(ip[:], r[4:]...)
					} else {
```
(Leave the `else` wrong-`MessageInitialization` branch exactly as-is.)

- [ ] **Step 3: Reconnection check on inbound accept (`RegisterPeer`)**

In `tcpip/recieverTcpService.go` `RegisterPeer` (`:311`), right after the existing ban check:
```go
	if IsIPBanned(ip) {
		logger.GetLogger().Println("IP is BANNED", ip)
		return false
	}
```
add:
```go
	if !AllowConnectionFromIP(ip) {
		logger.GetLogger().Println("connection rate limit exceeded for", ip)
		BanIP(ip)
		return false
	}
```

- [ ] **Step 4: Reconnection check on outbound dial (`StartNewConnection`)**

In `tcpip/listenerTcpService.go` `StartNewConnection` (`:111`), after resolving `tcpAddr` and before the `for i := 0; i < maxRetries` dial loop, add:
```go
	if !AllowConnectionFromIP(ip) {
		logger.GetLogger().Printf("connection rate limit exceeded for %s; skipping dial", ipport)
		return
	}
```
(Whitelisted peers — including operator-configured `WHITELIST_IP` peers — bypass this, so our own peers are never throttled.)

- [ ] **Step 5: Build + run the tcpip suite**

Run: `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go build ./... && GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./tcpip/ ./common/`
Expected: build OK; tcpip tests PASS (the Task 1 unit tests cover the limiter logic; this wiring is verified by build + review, as the receive loop needs a live network to exercise directly — note this limitation in the report).

- [ ] **Step 6: Commit**

```bash
git add tcpip/listenerTcpService.go tcpip/recieverTcpService.go
git commit -m "OB-114 net DoS: enforce per-topic caps + message-rate + reconnection limits in the P2P loops

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Final verification

- [ ] `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go build ./...` → exit 0.
- [ ] `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./tcpip/ ./common/` → PASS.
- [ ] Update `SECURITY_AUDIT.md`: note the DoS hardening — per-topic message-size caps replacing the 151 MB global, per-IP message-rate + reconnection-burst limiters (whitelist-exempt), and the 2 s → 60 s ban. Note peer-auth (NP-C3, sub-project B) and transport encryption (sub-project C) remain.

## Deferred (not in this plan)
- `MaxCodeSize`/`MaxOptData` transaction-validity bound (consensus change) to tighten the TransactionTopic cap.
- Sub-project B (peer-auth handshake, NP-C3) and C (transport encryption / TLS).

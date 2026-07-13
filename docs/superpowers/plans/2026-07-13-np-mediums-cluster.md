# NP Mediums Cluster Implementation Plan (NP-M1/M2/M4/M6/M7/M10/M13/M14)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the eight OPEN networking MEDIUM findings — ban-map eviction, ChanPeer backpressure, reconnect-counter correctness, RPC backoff + reply-buffer, tx-drop logging, header-range clamp, and bounded peer sampling.

**Architecture:** Eight independent, node-local networking fixes across six files. Pure helpers (`nextBackoff`, `clampHeaderSpan`, `sampleIPs`, ban-eviction) get socket-free unit tests; loop/channel/alloc/log changes are verified by build + inspection. No consensus/wire/format change.

**Tech Stack:** Go 1.23.6 (build with the `sdk/go1.24.0` toolchain), CGO (RocksDB + liboqs), `math/rand`.

## Global Constraints
- Build/test with `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go`. This repo uses CGO; export before building:
  ```
  export GOROOT=/home/wonabru/sdk/go1.24.0
  export PATH=$GOROOT/bin:$PATH
  export CGO_CFLAGS="-isystem $HOME/local/include"
  export CGO_LDFLAGS="-L$HOME/local/lib -L/usr/local/intelpython3/lib -lrocksdb -lstdc++ -lm -lz -lsnappy -llz4 -lzstd -lbz2 -lpthread -ldl"
  ```
- Branch `security-fixes`. Commit `OB-124` (NOT `(CONSENSUS)` — node-local networking). End every commit message with a blank line then `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- Node-local only: do not change consensus, tx/block validity, or the wire format. NP-M10 stays best-effort (drop-with-log, not blocking). NP-M14 is leak *reduction* (bounded random subset), not elimination.
- Reuse existing constants: NP-M13 clamps to `common.NumberOfHashesInBucket` (= 20). New constant: `common.MaxPeersSharedInHi = 3` (NP-M14).

---

## Task 1: NP-M1 — evict expired entries from the bannedIP map

**Files:**
- Modify: `tcpip/helper.go` (`IsIPBanned`, `BanIP`)
- Test: `tcpip/ban_evict_test.go` (new)

**Interfaces:**
- Consumes (existing): package vars `bannedIP map[[4]byte]int64`, `bannedIPMutex sync.RWMutex`, `whiteListIPs`; `common.GetCurrentTimeStampInSecond()`, `common.BannedTimeSeconds`.

- [ ] **Step 1: Write the failing test** — create `tcpip/ban_evict_test.go`:
```go
package tcpip

import (
	"testing"

	"github.com/wonabru/qwid-node/common"
)

func TestIsIPBannedEvictsExpired(t *testing.T) {
	ip := [4]byte{10, 0, 0, 1}
	now := common.GetCurrentTimeStampInSecond()
	bannedIPMutex.Lock()
	bannedIP[ip] = now - 1 // already expired
	bannedIPMutex.Unlock()

	if IsIPBanned(ip) {
		t.Fatal("expired ban should report not banned")
	}
	bannedIPMutex.RLock()
	_, present := bannedIP[ip]
	bannedIPMutex.RUnlock()
	if present {
		t.Fatal("expired ban entry should have been evicted from the map")
	}
}

func TestBanIPSweepsExpired(t *testing.T) {
	stale := [4]byte{10, 0, 0, 2}
	fresh := [4]byte{10, 0, 0, 3}
	now := common.GetCurrentTimeStampInSecond()
	bannedIPMutex.Lock()
	bannedIP[stale] = now - 1 // expired
	bannedIPMutex.Unlock()

	BanIP(fresh) // triggers the opportunistic sweep + records the new ban

	bannedIPMutex.RLock()
	_, staleP := bannedIP[stale]
	_, freshP := bannedIP[fresh]
	bannedIPMutex.RUnlock()
	if staleP {
		t.Fatal("BanIP should have swept the expired entry")
	}
	if !freshP {
		t.Fatal("BanIP should have recorded the new ban")
	}
	bannedIPMutex.Lock()
	delete(bannedIP, fresh)
	bannedIPMutex.Unlock()
}
```

- [ ] **Step 2: Run to verify it fails** — `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./tcpip/ -run 'TestIsIPBannedEvictsExpired|TestBanIPSweepsExpired' -v` → FAIL (the expired entry is not evicted).

- [ ] **Step 3: Lazy-evict in `IsIPBanned`** — in `tcpip/helper.go`, replace:
```go
func IsIPBanned(ip [4]byte) bool {
	bannedIPMutex.RLock()
	defer bannedIPMutex.RUnlock()
	if whiteListIPs[ip] {
		return false
	}
	if hbanned, ok := bannedIP[ip]; ok {
		if hbanned > common.GetCurrentTimeStampInSecond() {
			return true
		}
	}
	return false
}
```
with (promote to the write lock so an expired entry can be deleted):
```go
func IsIPBanned(ip [4]byte) bool {
	bannedIPMutex.Lock()
	defer bannedIPMutex.Unlock()
	if whiteListIPs[ip] {
		return false
	}
	if hbanned, ok := bannedIP[ip]; ok {
		if hbanned > common.GetCurrentTimeStampInSecond() {
			return true
		}
		delete(bannedIP, ip) // NP-M1: evict the expired ban so the map does not grow unboundedly
	}
	return false
}
```

- [ ] **Step 4: Opportunistic sweep in `BanIP`** — in `BanIP`, immediately after `bannedIPMutex.Lock()` and before the `logger.GetLogger().Println("BANNING ", ip)` line, insert:
```go
	// NP-M1: opportunistically evict already-expired bans so the map self-trims
	// even for IPs that are never re-checked.
	nowTs := common.GetCurrentTimeStampInSecond()
	for k, exp := range bannedIP {
		if exp <= nowTs {
			delete(bannedIP, k)
		}
	}
```
(Leave the rest of `BanIP` unchanged.)

- [ ] **Step 5: Run + build** — `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./tcpip/ -run 'TestIsIPBannedEvictsExpired|TestBanIPSweepsExpired' -v && GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go build ./...` → tests PASS, build exit 0.

- [ ] **Step 6: Commit**
```bash
git add tcpip/helper.go tcpip/ban_evict_test.go
git commit -m "$(printf 'OB-124 NP-M1: evict expired bannedIP entries (bound map growth)\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Task 2: NP-M2 + NP-M4 — ChanPeer non-blocking sends + reconnect-counter reset

**Files:**
- Modify: `tcpip/listenerTcpService.go` (three `ChanPeer <- …` sends; the `resetNumber` reconnect logic)

**Interfaces:**
- Consumes (existing): `ChanPeer chan []byte`, `logger`, `reconnectionTries`/`common.ConnectionMaxTries` in the receive loop.
- Note: this task has no isolated unit test (channel-send + receive-loop changes are integration-level); verified by build + inspection. This is stated in the spec.

- [ ] **Step 1: NP-M2 — make the three ChanPeer sends non-blocking** — in `tcpip/listenerTcpService.go`, wrap each of the three blocking sends. Find them with `grep -n "ChanPeer <-" tcpip/listenerTcpService.go` (currently at ~`:100` `ChanPeer <- deletedIP`, ~`:239` `ChanPeer <- d`, ~`:247` `ChanPeer <- append(topic[:], ip[:]...)`). Replace each `ChanPeer <- <EXPR>` with:
```go
			select {
			case ChanPeer <- <EXPR>:
			default:
				logger.GetLogger().Println("NP-M2: ChanPeer full, dropping peer notification")
			}
```
(Substitute the site's exact `<EXPR>`: `deletedIP`, `d`, and `append(topic[:], ip[:]...)` respectively. Preserve each site's surrounding loop/indentation.)

- [ ] **Step 2: NP-M4 — remove the iteration-cadence reset** — delete the `resetNumber` counter and its periodic reset. Remove the line `resetNumber := 0` (currently `:228`, right after `reconnectionTries := 0`), and remove the block at the top of the `for {` loop (currently `:263-265`):
```go
		resetNumber++
		if resetNumber%100 == 0 {
			reconnectionTries = 0
		}
```
(Delete those three lines entirely; the `for {` loop body now starts at the `select`.)

- [ ] **Step 3: NP-M4 — reset the counter on a genuine successful receive** — in the same receive loop, on the successful-data path (after the `<-ERR->` and `<-CLS->` special-case checks, where `r` is real payload), reset the counter. Immediately AFTER the `if bytes.Equal(r, []byte("<-CLS->")) { … return }` block and BEFORE the `rt, ok := rTopic[topic]` line (currently ~`:351`), insert:
```go
			reconnectionTries = 0 // NP-M4: a real frame arrived — the connection is healthy, so reset the consecutive-error counter (was reset on a fixed iteration cadence)
```
(The existing `reconnectionTries = 0` after a successful re-dial and `reconnectionTries++` on a read error are unchanged.)

- [ ] **Step 4: Build + vet + grep-verify** —
```
GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go build ./...
GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go vet ./tcpip/
grep -n "resetNumber\|ChanPeer <-" tcpip/listenerTcpService.go
```
Expected: build exit 0, vet clean, `grep` shows NO remaining `resetNumber` references and NO bare `ChanPeer <-` outside a `select` (each send now inside a `select`/`default`).

- [ ] **Step 5: Commit**
```bash
git add tcpip/listenerTcpService.go
git commit -m "$(printf 'OB-124 NP-M2/M4: non-blocking ChanPeer sends + reset reconnect counter on real receive\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Task 3: NP-M6 + NP-M7 — RPC client exponential backoff + reply-buffer

**Files:**
- Modify: `rpc/client/client.go` (`ConnectRPC`; add backoff consts + helper; drop the 1MB reply pre-alloc)
- Test: `rpc/client/backoff_test.go` (new)

**Interfaces:**
- Produces: `nextBackoff(cur time.Duration) time.Duration`; consts `initialBackoff`, `maxBackoff`.
- Consumes (existing): `ConnectRPC(ip string)`, the two `rpc.Dial` retry loops.

- [ ] **Step 1: Write the failing test** — create `rpc/client/backoff_test.go`:
```go
package clientrpc

import (
	"testing"
	"time"
)

func TestNextBackoff(t *testing.T) {
	got := initialBackoff // 1s
	want := []time.Duration{
		2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second,
		30 * time.Second, 30 * time.Second, // capped at maxBackoff
	}
	for i, w := range want {
		got = nextBackoff(got)
		if got != w {
			t.Fatalf("step %d: got %v, want %v", i, got, w)
		}
	}
}
```

- [ ] **Step 2: Run to verify it fails** — `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./rpc/client/ -run TestNextBackoff -v` → FAIL to compile (`nextBackoff`/`initialBackoff`/`maxBackoff` undefined).

- [ ] **Step 3: Add backoff consts + helper; update the const block** — in `rpc/client/client.go`, replace the const block:
```go
const (
	retryInterval = 5 * time.Second
	bufferSize    = 1024 * 1024
)
```
with:
```go
const (
	initialBackoff = 1 * time.Second  // NP-M6
	maxBackoff     = 30 * time.Second // NP-M6
)

// nextBackoff doubles cur, capped at maxBackoff. Pure/deterministic. NP-M6.
func nextBackoff(cur time.Duration) time.Duration {
	next := cur * 2
	if next > maxBackoff {
		return maxBackoff
	}
	return next
}
```
(This removes `retryInterval` and `bufferSize`, which are replaced below.)

- [ ] **Step 4: NP-M6 — back off in both dial-retry loops; NP-M7 — drop the 1MB pre-alloc** — replace the body of `ConnectRPC` (from `func ConnectRPC(ip string) {` through its closing `}`) with:
```go
func ConnectRPC(ip string) {
	address := ip + ":" + strconv.Itoa(tcpip.Ports[tcpip.RPCTopic])
	var client *rpc.Client
	var err error
	backoff := initialBackoff
	for {
		client, err = rpc.Dial("tcp", address)
		if err == nil {
			break
		}
		logger.GetLogger().Printf("Failed to connect to RPC server at %s: %v. Retrying in %v...", address, err, backoff)
		time.Sleep(backoff)
		backoff = nextBackoff(backoff) // NP-M6: exponential backoff
	}

	// WH-C6: block on InRPC instead of polling with a 100ms sleep, which added
	// latency to every RPC and burned a wakeup 10x/second while idle.
	for {
		line := <-InRPC
		muRPC.Lock()
		var reply []byte // NP-M7: net/rpc gob sizes the reply slice itself; no fixed pre-alloc
		err = client.Call("Listener.Send", line, &reply)
		if err != nil {
			logger.GetLogger().Printf("RPC call failed: %v. Reconnecting...", err)
			OutRPC <- []byte("Timeout")
			reconnectBackoff := initialBackoff
			for {
				client, err = rpc.Dial("tcp", address)
				if err == nil {
					break
				}
				logger.GetLogger().Printf("Failed to reconnect to RPC server at %s: %v. Retrying in %v...", address, err, reconnectBackoff)
				time.Sleep(reconnectBackoff)
				reconnectBackoff = nextBackoff(reconnectBackoff) // NP-M6
			}
		} else {
			OutRPC <- reply
		}
		muRPC.Unlock()
	}
}
```

- [ ] **Step 5: Run tests + build** —
```
GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./rpc/client/ -run 'TestNextBackoff|TestCallPairs' -v
GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go build ./...
```
Expected: `TestNextBackoff` PASS, the existing `TestCallPairsResponsesUnderConcurrency` still PASS (Call round-trip unaffected), build exit 0.

- [ ] **Step 6: Commit**
```bash
git add rpc/client/client.go rpc/client/backoff_test.go
git commit -m "$(printf 'OB-124 NP-M6/M7: exponential RPC dial backoff + drop fixed 1MB reply buffer\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Task 4: NP-M10 — log dropped tx sends on a full channel

**Files:**
- Modify: `services/transactionServices/serviceTransaction.go` (`Send`)

**Interfaces:**
- Consumes (existing): `Send(addr [4]byte, nb []byte) bool`, `services.SendMutexTx`, `services.SendChanTx`, `logger`.
- Note: no isolated unit test (adds a log line to a best-effort drop path); verified by build + inspection. Stated in the spec.

- [ ] **Step 1: Add the drop log** — in `services/transactionServices/serviceTransaction.go`, replace:
```go
func Send(addr [4]byte, nb []byte) bool {

	nb = append(addr[:], nb...)
	if services.SendMutexTx.TryLock() {
		defer services.SendMutexTx.Unlock()
		select {
		case services.SendChanTx <- nb:
			return true
		default:
			return false
		}
	}
	return false
}
```
with:
```go
func Send(addr [4]byte, nb []byte) bool {

	nb = append(addr[:], nb...)
	if services.SendMutexTx.TryLock() {
		defer services.SendMutexTx.Unlock()
		select {
		case services.SendChanTx <- nb:
			return true
		default:
			// NP-M10: best-effort gossip — the send channel is full, so drop this
			// message but log it (propagation is still covered by on-arrival
			// BroadcastTxn and the periodic delta loop). Blocking here would push
			// backpressure into the caller.
			logger.GetLogger().Println("NP-M10: tx send channel full, dropping outbound message")
			return false
		}
	}
	return false
}
```
(`logger` is already imported in this file.)

- [ ] **Step 2: Build + vet** —
```
GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go build ./... && GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go vet ./services/transactionServices/
```
Expected: build exit 0, vet clean.

- [ ] **Step 3: Commit**
```bash
git add services/transactionServices/serviceTransaction.go
git commit -m "$(printf 'OB-124 NP-M10: log dropped tx sends when the send channel is full\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Task 5: NP-M13 — clamp attacker-controlled block-header range requests

**Files:**
- Modify: `services/syncService/onmessage.go` (add `clampHeaderSpan`; apply it in the `gh` handler)
- Test: `services/syncService/sync_bounds_test.go` (new — the NP-M14 test is APPENDED to this file in Task 6)

**Interfaces:**
- Produces: `clampHeaderSpan(bHeight, eHeight int64) (int64, int64)` (package `syncService`).
- Consumes (existing): the `case "gh":` handler; `common.NumberOfHashesInBucket`; `SendHeaders(addr, bHeight, eHeight)`.

- [ ] **Step 1: Write the failing test** — create `services/syncService/sync_bounds_test.go`:
```go
package syncService

import (
	"testing"

	"github.com/wonabru/qwid-node/common"
)

func TestClampHeaderSpan(t *testing.T) {
	// span within the bucket is unchanged
	if b, e := clampHeaderSpan(100, 110); b != 100 || e != 110 {
		t.Fatalf("small span changed: %d..%d", b, e)
	}
	// oversized span is clamped to NumberOfHashesInBucket
	if b, e := clampHeaderSpan(100, 100000); b != 100 || e != 100+common.NumberOfHashesInBucket {
		t.Fatalf("huge span not clamped: %d..%d (bucket=%d)", b, e, common.NumberOfHashesInBucket)
	}
	// inverted range normalizes eHeight up to bHeight
	if b, e := clampHeaderSpan(200, 100); b != 200 || e != 200 {
		t.Fatalf("inverted not normalized: %d..%d", b, e)
	}
}
```

- [ ] **Step 2: Run to verify it fails** — `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./services/syncService/ -run TestClampHeaderSpan -v` → FAIL to compile (`clampHeaderSpan` undefined).

- [ ] **Step 3: Add the helper** — in `services/syncService/onmessage.go`, add (e.g. just above the `onMessage`/handler function, package-level):
```go
// clampHeaderSpan bounds [bHeight, eHeight] so eHeight-bHeight <= NumberOfHashesInBucket
// and bHeight <= eHeight, matching the legitimate sync batch size, so a malicious peer
// cannot request an enormous header range. NP-M13.
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

- [ ] **Step 4: Apply it in the `gh` handler** — in the `case "gh":` block, immediately AFTER the two lines that read `bHeight`/`eHeight` from the message and BEFORE `SendHeaders(addr, bHeight, eHeight)`, insert:
```go
		bHeight, eHeight = clampHeaderSpan(bHeight, eHeight) // NP-M13: bound the requested span
```
So the handler reads the peer's `bHeight`/`eHeight`, clamps, then calls `SendHeaders`.

- [ ] **Step 5: Run + build** — `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./services/syncService/ -run TestClampHeaderSpan -v && GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go build ./...` → test PASS, build exit 0.

- [ ] **Step 6: Commit**
```bash
git add services/syncService/onmessage.go services/syncService/sync_bounds_test.go
git commit -m "$(printf 'OB-124 NP-M13: clamp block-header range requests to NumberOfHashesInBucket\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Task 6: NP-M14 — share only a bounded random subset of peer IPs in `hi`

**Files:**
- Modify: `common/const.go` (add `MaxPeersSharedInHi`); `services/syncService/serviceSync.go` (add `sampleIPs`; use it in `generateSyncMsgHeight`; add `math/rand` import)
- Test: `services/syncService/sync_bounds_test.go` (APPEND the `sampleIPs` test to the file created in Task 5)

**Interfaces:**
- Consumes (existing): `generateSyncMsgHeight`, `tcpip.GetIPsConnected() [][]byte`; from Task 5 the test file `sync_bounds_test.go` already exists (append to it).
- Produces: `sampleIPs(ips [][]byte, n int) [][]byte`; `common.MaxPeersSharedInHi int = 3`.

- [ ] **Step 1: Add the constant** — in `common/const.go`, add to a suitable const block (e.g. near the networking/rate-limit constants):
```go
	MaxPeersSharedInHi int = 3 // NP-M14: cap peer IPs shared per 'hi' message (topology-leak reduction)
```

- [ ] **Step 2: Append the failing test** — add to `services/syncService/sync_bounds_test.go` (add `"bytes"` to its import block):
```go
func TestSampleIPs(t *testing.T) {
	ips := [][]byte{{1}, {2}, {3}, {4}, {5}}

	got := sampleIPs(ips, 3)
	if len(got) != 3 {
		t.Fatalf("len(sampleIPs(5,3)) = %d, want 3", len(got))
	}
	seen := map[string]bool{}
	for _, g := range got {
		if seen[string(g)] {
			t.Fatalf("duplicate entry in sample: %v", g)
		}
		seen[string(g)] = true
		found := false
		for _, in := range ips {
			if bytes.Equal(in, g) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("sample element %v not from input", g)
		}
	}

	// n >= len(ips) returns all of them
	if all := sampleIPs(ips, 10); len(all) != len(ips) {
		t.Fatalf("n>=len should return all: got %d, want %d", len(all), len(ips))
	}
	// empty input is safe
	if e := sampleIPs(nil, 3); len(e) != 0 {
		t.Fatalf("nil input should return empty, got %d", len(e))
	}
}
```

- [ ] **Step 3: Run to verify it fails** — `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./services/syncService/ -run TestSampleIPs -v` → FAIL to compile (`sampleIPs` undefined).

- [ ] **Step 4: Add the helper + `math/rand` import** — in `services/syncService/serviceSync.go`, add `"math/rand"` to the import block, and add:
```go
// sampleIPs returns up to n distinct entries of ips chosen at random (all of ips
// if len(ips) <= n). Preserves peer discovery without revealing the full peer set
// in any single 'hi' message. NP-M14.
func sampleIPs(ips [][]byte, n int) [][]byte {
	if len(ips) <= n {
		return ips
	}
	perm := rand.Perm(len(ips))[:n]
	out := make([][]byte, 0, n)
	for _, i := range perm {
		out = append(out, ips[i])
	}
	return out
}
```

- [ ] **Step 5: Use it in `generateSyncMsgHeight`** — in `services/syncService/serviceSync.go`, replace:
```go
	peers := tcpip.GetIPsConnected()

	n.TransactionsBytes[[2]byte{'P', 'P'}] = peers
```
with:
```go
	// NP-M14: share only a bounded random subset of connected peers, so no single
	// 'hi' message discloses the full topology, while peer discovery still works.
	peers := sampleIPs(tcpip.GetIPsConnected(), common.MaxPeersSharedInHi)

	n.TransactionsBytes[[2]byte{'P', 'P'}] = peers
```

- [ ] **Step 6: Run + build** — `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./services/syncService/ -run 'TestClampHeaderSpan|TestSampleIPs' -v && GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go build ./...` → tests PASS, build exit 0.

- [ ] **Step 7: Commit**
```bash
git add common/const.go services/syncService/serviceSync.go services/syncService/sync_bounds_test.go
git commit -m "$(printf 'OB-124 NP-M14: share only a bounded random subset of peer IPs in hi\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Final verification
- [ ] `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go build ./...` → exit 0.
- [ ] `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./tcpip/ ./rpc/client/ ./services/syncService/` → PASS (new NP tests green; pre-existing tests unaffected).
- [ ] Update `SECURITY_AUDIT.md` reconciliation: move **NP-M1, NP-M2, NP-M4, NP-M6, NP-M7, NP-M10, NP-M13, NP-M14** from OPEN to FIXED; Medium FIXED +8, OPEN −8; note NP-M14's leak-reduction residual (repeated sampling still gradually reveals neighbors on open-peering). (Controller handles this doc edit after the final review, mirroring prior clusters.)

## Deferred (not in this plan)
- RPC connection pooling / correlation IDs (NP-M7's sibling; removes single-connection serialization).
- The EVM/DB mediums (cluster B: DB-M1/M3/M4/M9/M10) and wallet mediums (cluster C: CW-M2/M3).
- Remaining deferred-by-design partials (DB-C4, NP-C4/C5, etc.).

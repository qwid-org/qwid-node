# NP DoS-Resilience Cluster Implementation Plan (NP-H2, NP-H6, NP-H10)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close three HIGH networking resource-exhaustion findings — cap concurrent inbound TCP connections (NP-H2), cap concurrent RPC connections (NP-H6), and make the periodic tx re-broadcast delta-only (NP-H10).

**Architecture:** Three independent, node-local DoS-resilience fixes. Each extracts a pure/testable helper (`inboundCapReached`, `tryAcquireRPCSlot`/`releaseRPCSlot`, `selectNewTransactions`/`pruneSeen`) so tests need no real sockets or CGO. No consensus/wire/format change.

**Tech Stack:** Go 1.23.6 (build with the `sdk/go1.24.0` toolchain), standard library (`sync/atomic`).

## Global Constraints
- Build/test with `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go`. This repo uses CGO (RocksDB + liboqs); export before building:
  ```
  export GOROOT=/home/wonabru/sdk/go1.24.0
  export PATH=$GOROOT/bin:$PATH
  export CGO_CFLAGS="-isystem $HOME/local/include"
  export CGO_LDFLAGS="-L$HOME/local/lib -L/usr/local/intelpython3/lib -lrocksdb -lstdc++ -lm -lz -lsnappy -llz4 -lzstd -lbz2 -lpthread -ldl"
  ```
- Branch `security-fixes`. Commit `OB-120` (NOT `(CONSENSUS)` — these are node-local resource guards). End every commit message with a blank line then `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- Cap values are FIXED constants (not env-configurable): `MaxInboundConnectionsPerTopic = 64`, `MaxConcurrentRPCConnections = 64`.
- Do NOT change the on-arrival tx gossip (`BroadcastTxn`), the mempool, message formats, or any consensus/wire/validity surface.
- `common.Hash` is `[32]byte` (usable as a map key). `tx.GetHash()` returns the stored `Hash` field. `PeersMutex = &sync.RWMutex{}` guards `tcpConnections map[[2]byte]map[[4]byte]net.Conn` in `tcpip/recieverTcpService.go`.

---

## Task 1: NP-H2 — per-topic concurrent inbound-connection cap

**Files:**
- Modify: `common/const.go` (add constant in the rate-limit block near line 71)
- Modify: `tcpip/recieverTcpService.go` (add `inboundCapReached` helper; add cap check in `Accept` after `admitPeer`)
- Test: `tcpip/inbound_cap_test.go` (new)

**Interfaces:**
- Produces: `inboundCapReached(topic [2]byte) bool` (package `tcpip`); constant `common.MaxInboundConnectionsPerTopic int = 64`.
- Consumes: existing `PeersMutex`, `tcpConnections`, `isWhitelisted(ip [4]byte) bool`, `admitPeer`, `Accept`.

- [ ] **Step 1: Add the constant** — in `common/const.go`, inside the rate-limit `const` block (immediately after `ConnectionRateWindowSeconds int64 = 60` at line ~70, before the closing `)`):
```go
	MaxInboundConnectionsPerTopic int = 64 // NP-H2: cap concurrent inbound conns per topic (~10x the ~6 legit peers) to bound fd exhaustion / slow-loris
```

- [ ] **Step 2: Write the failing test** — create `tcpip/inbound_cap_test.go`:
```go
package tcpip

import (
	"net"
	"testing"

	"github.com/wonabru/qwid-node/common"
)

func TestInboundCapReached(t *testing.T) {
	topic := [2]byte{'Z', 'Z'} // a test-only topic, not a real one
	PeersMutex.Lock()
	tcpConnections[topic] = make(map[[4]byte]net.Conn)
	PeersMutex.Unlock()
	defer func() {
		PeersMutex.Lock()
		delete(tcpConnections, topic)
		PeersMutex.Unlock()
	}()

	if inboundCapReached(topic) {
		t.Fatal("empty topic must not be at cap")
	}

	// Fill to cap-1 distinct fake connections (nil net.Conn is fine — only the count matters).
	PeersMutex.Lock()
	for i := 0; i < common.MaxInboundConnectionsPerTopic-1; i++ {
		ip := [4]byte{byte(i / 256), byte(i % 256), 0, 0}
		tcpConnections[topic][ip] = nil
	}
	PeersMutex.Unlock()
	if inboundCapReached(topic) {
		t.Fatalf("cap-1 (%d) connections must not be at cap", common.MaxInboundConnectionsPerTopic-1)
	}

	// One more reaches the cap.
	PeersMutex.Lock()
	tcpConnections[topic][[4]byte{255, 255, 255, 255}] = nil
	PeersMutex.Unlock()
	if !inboundCapReached(topic) {
		t.Fatalf("%d connections must be at cap", common.MaxInboundConnectionsPerTopic)
	}
}
```

- [ ] **Step 3: Run to verify it fails** — `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./tcpip/ -run TestInboundCapReached -v` → FAIL to compile (`inboundCapReached` undefined).

- [ ] **Step 4: Add the helper** — in `tcpip/recieverTcpService.go`, near `GetPeersCount` (around line 491), add:
```go
// inboundCapReached reports whether the number of concurrent inbound connections
// already registered for topic has reached MaxInboundConnectionsPerTopic. NP-H2.
func inboundCapReached(topic [2]byte) bool {
	PeersMutex.RLock()
	defer PeersMutex.RUnlock()
	return len(tcpConnections[topic]) >= common.MaxInboundConnectionsPerTopic
}
```
(`common` is already imported in this file.)

- [ ] **Step 5: Enforce the cap in `Accept`** — in `tcpip/recieverTcpService.go` `Accept` (line ~204), immediately AFTER the existing `admitPeer` block:
```go
	if !admitPeer(ip) {
		tcpConn.Close()
		return nil, fmt.Errorf("registration failed for connection")
	}
	// NP-H2: bound concurrent inbound connections per topic. Whitelisted operators bypass.
	if !isWhitelisted(ip) && inboundCapReached(topic) {
		tcpConn.Close()
		return nil, fmt.Errorf("inbound connection cap reached for topic")
	}
```
Leave the rest of `Accept` (the NP-C3 handshake, `publishAcceptedConn`) unchanged.

- [ ] **Step 6: Run + build** — `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./tcpip/ -run TestInboundCapReached -v && GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go build ./...` → test PASS, build exit 0.

- [ ] **Step 7: Commit**
```bash
git add common/const.go tcpip/recieverTcpService.go tcpip/inbound_cap_test.go
git commit -m "$(printf 'OB-120 NP-H2: cap concurrent inbound connections per topic\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Task 2: NP-H6 — concurrent RPC-connection cap

**Files:**
- Modify: `common/const.go` (add constant in the rate-limit block)
- Modify: `rpc/server/server.go` (add atomic counter + `tryAcquireRPCSlot`/`releaseRPCSlot`; enforce in `ListenRPC`; add `sync/atomic` import)
- Test: `rpc/server/rpc_cap_test.go` (new)

**Interfaces:**
- Produces: `tryAcquireRPCSlot() bool`, `releaseRPCSlot()`, package var `rpcConnCount int64` (package `server`); constant `common.MaxConcurrentRPCConnections int = 64`.
- Consumes: existing `ListenRPC`, `extractRemoteIP`.

- [ ] **Step 1: Add the constant** — in `common/const.go`, in the same rate-limit `const` block, after the Task 1 constant:
```go
	MaxConcurrentRPCConnections int = 64 // NP-H6: cap concurrent RPC conns (HTTP servers hold ~1 persistent conn each) to bound fd exhaustion
```

- [ ] **Step 2: Write the failing tests** — create `rpc/server/rpc_cap_test.go`:
```go
package server

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/wonabru/qwid-node/common"
)

func TestRPCSlotAcquireReleaseBounded(t *testing.T) {
	atomic.StoreInt64(&rpcConnCount, 0)
	defer atomic.StoreInt64(&rpcConnCount, 0)

	for i := 0; i < common.MaxConcurrentRPCConnections; i++ {
		if !tryAcquireRPCSlot() {
			t.Fatalf("acquire %d/%d should succeed", i+1, common.MaxConcurrentRPCConnections)
		}
	}
	if tryAcquireRPCSlot() {
		t.Fatal("acquire beyond cap must fail")
	}
	// A rejected acquire must roll back — the counter stays exactly at the cap.
	if c := atomic.LoadInt64(&rpcConnCount); c != int64(common.MaxConcurrentRPCConnections) {
		t.Fatalf("rpcConnCount = %d, want %d (rejected acquire must roll back)", c, common.MaxConcurrentRPCConnections)
	}
	releaseRPCSlot()
	if !tryAcquireRPCSlot() {
		t.Fatal("acquire after release should succeed")
	}
}

// TestRPCSlotConcurrentNeverExceedsCap runs many racing acquire/release pairs and
// asserts the number of simultaneously-HELD (successful) slots never exceeds the
// cap, and the counter returns to 0 with no leak. Run under -race.
func TestRPCSlotConcurrentNeverExceedsCap(t *testing.T) {
	atomic.StoreInt64(&rpcConnCount, 0)
	defer atomic.StoreInt64(&rpcConnCount, 0)

	var live int64  // successfully-held slots
	var maxLive int64
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < 500; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if tryAcquireRPCSlot() {
				n := atomic.AddInt64(&live, 1)
				mu.Lock()
				if n > maxLive {
					maxLive = n
				}
				mu.Unlock()
				atomic.AddInt64(&live, -1)
				releaseRPCSlot()
			}
		}()
	}
	wg.Wait()
	if maxLive > int64(common.MaxConcurrentRPCConnections) {
		t.Fatalf("held %d slots simultaneously, cap is %d", maxLive, common.MaxConcurrentRPCConnections)
	}
	if c := atomic.LoadInt64(&rpcConnCount); c != 0 {
		t.Fatalf("rpcConnCount leaked: got %d, want 0", c)
	}
}
```

- [ ] **Step 3: Run to verify it fails** — `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./rpc/server/ -run TestRPCSlot -v` → FAIL to compile (`rpcConnCount`, `tryAcquireRPCSlot`, `releaseRPCSlot` undefined).

- [ ] **Step 4: Add `sync/atomic` to the imports** — in `rpc/server/server.go`, add `"sync/atomic"` to the standard-library import group (e.g. after `"strconv"`).

- [ ] **Step 5: Add the counter + helpers** — in `rpc/server/server.go`, add near the top of the file (package level, e.g. just above `func ListenRPC()`):
```go
var rpcConnCount int64 // NP-H6: current in-flight RPC connections

// tryAcquireRPCSlot atomically reserves a connection slot if under the cap,
// returning true on success (a rejected acquire rolls the counter back). NP-H6.
func tryAcquireRPCSlot() bool {
	if atomic.AddInt64(&rpcConnCount, 1) > int64(common.MaxConcurrentRPCConnections) {
		atomic.AddInt64(&rpcConnCount, -1)
		return false
	}
	return true
}

func releaseRPCSlot() { atomic.AddInt64(&rpcConnCount, -1) }
```

- [ ] **Step 6: Enforce in the accept loop** — in `ListenRPC` (`rpc/server/server.go`), replace the body of the `for` loop that currently reads:
```go
		conn, err := listener.Accept()
		if err != nil {
			logger.GetLogger().Printf("RPC accept error: %v", err)
			continue
		}
		remoteIP := extractRemoteIP(conn.RemoteAddr().String())
		go func(c net.Conn, ip string) {
			srv := rpc.NewServer()
			srv.Register(&Listener{remoteIP: ip})
			srv.ServeConn(c)
		}(conn, remoteIP)
```
with:
```go
		conn, err := listener.Accept()
		if err != nil {
			logger.GetLogger().Printf("RPC accept error: %v", err)
			continue
		}
		// NP-H6: bound concurrent RPC connections.
		if !tryAcquireRPCSlot() {
			logger.GetLogger().Printf("RPC connection cap (%d) reached; rejecting %s", common.MaxConcurrentRPCConnections, conn.RemoteAddr())
			conn.Close()
			continue
		}
		remoteIP := extractRemoteIP(conn.RemoteAddr().String())
		go func(c net.Conn, ip string) {
			defer releaseRPCSlot()
			srv := rpc.NewServer()
			srv.Register(&Listener{remoteIP: ip})
			srv.ServeConn(c)
		}(conn, remoteIP)
```

- [ ] **Step 7: Run + build** — `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./rpc/server/ -run TestRPCSlot -race -v && GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go build ./...` → tests PASS (no race), build exit 0.

- [ ] **Step 8: Commit**
```bash
git add common/const.go rpc/server/server.go rpc/server/rpc_cap_test.go
git commit -m "$(printf 'OB-120 NP-H6: cap concurrent RPC connections\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Task 3: NP-H10 — delta-only periodic re-broadcast

**Files:**
- Modify: `services/transactionServices/serviceTransaction.go` (add `selectNewTransactions`/`pruneSeen`; rewrite `broadcastTransactionsMsgInLoop` to delta-only)
- Test: `services/transactionServices/broadcast_delta_test.go` (new)

**Interfaces:**
- Produces: `selectNewTransactions(txs []transactionsDefinition.Transaction, seen map[common.Hash]struct{}) []transactionsDefinition.Transaction`; `pruneSeen(seen map[common.Hash]struct{}, txs []transactionsDefinition.Transaction)` (package `transactionServices`).
- Consumes: existing `transactionsPool.PoolsTx.PeekTransactions`, `GenerateTransactionMsg`, `tcpip.GetPeersConnected`, `Send`, `tcpip.MyIP`, `tcpip.Quit`. (`common` and `transactionsDefinition` are already imported.)

- [ ] **Step 1: Write the failing tests** — create `services/transactionServices/broadcast_delta_test.go`:
```go
package transactionServices

import (
	"testing"

	"github.com/wonabru/qwid-node/common"
	"github.com/wonabru/qwid-node/transactionsDefinition"
)

// mkTx builds a Transaction whose GetHash() returns a hash tagged by b.
func mkTx(b byte) transactionsDefinition.Transaction {
	var h common.Hash
	h[0] = b
	return transactionsDefinition.Transaction{Hash: h}
}

func hashSet(bs ...byte) map[common.Hash]struct{} {
	s := make(map[common.Hash]struct{})
	for _, b := range bs {
		var h common.Hash
		h[0] = b
		s[h] = struct{}{}
	}
	return s
}

func TestSelectNewTransactions(t *testing.T) {
	txs := []transactionsDefinition.Transaction{mkTx(1), mkTx(2), mkTx(3)}

	// empty seen -> all are new
	got := selectNewTransactions(txs, hashSet())
	if len(got) != 3 {
		t.Fatalf("empty seen: got %d new, want 3", len(got))
	}
	// all seen -> none new
	got = selectNewTransactions(txs, hashSet(1, 2, 3))
	if len(got) != 0 {
		t.Fatalf("all seen: got %d new, want 0", len(got))
	}
	// partial -> only the complement, order preserved
	got = selectNewTransactions(txs, hashSet(2))
	if len(got) != 2 || got[0].GetHash() != mkTx(1).GetHash() || got[1].GetHash() != mkTx(3).GetHash() {
		t.Fatalf("partial seen: got %v, want [tx1 tx3]", got)
	}
}

func TestPruneSeen(t *testing.T) {
	// seen has 1,2,3,4; current pool has only 2,3 -> prune 1 and 4.
	seen := hashSet(1, 2, 3, 4)
	pruneSeen(seen, []transactionsDefinition.Transaction{mkTx(2), mkTx(3)})
	if len(seen) != 2 {
		t.Fatalf("after prune: %d entries, want 2", len(seen))
	}
	if _, ok := seen[mkTx(2).GetHash()]; !ok {
		t.Fatal("hash 2 should be kept")
	}
	if _, ok := seen[mkTx(3).GetHash()]; !ok {
		t.Fatal("hash 3 should be kept")
	}
	if _, ok := seen[mkTx(1).GetHash()]; ok {
		t.Fatal("hash 1 (mined/dropped) should be pruned")
	}

	// pruning against an empty pool clears everything.
	seen2 := hashSet(1, 2)
	pruneSeen(seen2, nil)
	if len(seen2) != 0 {
		t.Fatalf("prune vs empty pool: %d entries, want 0", len(seen2))
	}
}
```

- [ ] **Step 2: Run to verify it fails** — `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./services/transactionServices/ -run 'TestSelectNewTransactions|TestPruneSeen' -v` → FAIL to compile (`selectNewTransactions`, `pruneSeen` undefined).

- [ ] **Step 3: Add the pure helpers** — in `services/transactionServices/serviceTransaction.go`, add (e.g. just above `broadcastTransactionsMsgInLoop`):
```go
// selectNewTransactions returns the subset of txs whose hash is not already in
// seen (i.e. not yet re-broadcast by the periodic loop). Pure; does not mutate seen. NP-H10.
func selectNewTransactions(txs []transactionsDefinition.Transaction, seen map[common.Hash]struct{}) []transactionsDefinition.Transaction {
	out := make([]transactionsDefinition.Transaction, 0, len(txs))
	for _, tx := range txs {
		if _, ok := seen[tx.GetHash()]; !ok {
			out = append(out, tx)
		}
	}
	return out
}

// pruneSeen removes from seen every hash not present in txs, so entries for
// mined/dropped transactions do not accumulate. Mutates seen. NP-H10.
func pruneSeen(seen map[common.Hash]struct{}, txs []transactionsDefinition.Transaction) {
	if len(seen) == 0 {
		return
	}
	present := make(map[common.Hash]struct{}, len(txs))
	for _, tx := range txs {
		present[tx.GetHash()] = struct{}{}
	}
	for h := range seen {
		if _, ok := present[h]; !ok {
			delete(seen, h)
		}
	}
}
```

- [ ] **Step 4: Rewrite the loop to delta-only** — in `services/transactionServices/serviceTransaction.go`, replace the entire body of `broadcastTransactionsMsgInLoop` with:
```go
func broadcastTransactionsMsgInLoop() {
	seen := make(map[common.Hash]struct{}) // NP-H10: hashes already re-broadcast by this loop (single-goroutine, no mutex)
	for {
		select {
		case <-tcpip.Quit:
			logger.GetLogger().Println("broadcastTransactionsMsgInLoop: EXIT")
			return
		default:
		}

		txs := transactionsPool.PoolsTx.PeekTransactions(int(common.MaxTransactionsPerBlock), 0)
		pruneSeen(seen, txs)                       // NP-H10: drop mined/expired entries
		newTxs := selectNewTransactions(txs, seen) // NP-H10: send only the delta
		if len(newTxs) > 0 {
			topic := [2]byte{'T', 'T'}
			n, err := GenerateTransactionMsg(newTxs, []byte("tx"), topic)
			if err == nil {
				peers := tcpip.GetPeersConnected(tcpip.TransactionTopic)
				for topicip := range peers {
					var ip [4]byte
					copy(ip[:], topicip[2:])
					if !bytes.Equal(ip[:], tcpip.MyIP[:]) {
						Send(ip, n.GetBytes())
					}
				}
				for _, tx := range newTxs {
					seen[tx.GetHash()] = struct{}{}
				}
			}
		}

		time.Sleep(time.Second)
	}
}
```
Leave all other functions in the file (`BroadcastTxn`, `SendTransactionMsg`, `GenerateTransactionMsg`, etc.) unchanged.

- [ ] **Step 5: Run + build** — `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./services/transactionServices/ -run 'TestSelectNewTransactions|TestPruneSeen' -v && GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go build ./...` → tests PASS, build exit 0.

- [ ] **Step 6: Commit**
```bash
git add services/transactionServices/serviceTransaction.go services/transactionServices/broadcast_delta_test.go
git commit -m "$(printf 'OB-120 NP-H10: delta-only periodic tx re-broadcast (was full-pool every second)\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Final verification
- [ ] `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go build ./...` → exit 0.
- [ ] `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./tcpip/ ./rpc/server/ ./services/transactionServices/` → PASS (some pre-existing tests in these packages may need network/CGO; the new tests are pure and must pass).
- [ ] Update `SECURITY_AUDIT.md` reconciliation: move **NP-H2, NP-H6, NP-H10** from the OPEN list to FIXED; update the High FIXED/OPEN counts (FIXED +3, OPEN −3). (Controller handles this doc edit after the final review, mirroring the DB cluster.)

## Deferred (not in this plan)
- Per-IP RPC ban/rate-limiting for operator-overridden non-loopback RPC binds.
- Remaining OPEN reconciliation items (CW-H2, WH-H3, the mediums; deferred-by-design DB-C4 / NP-C4/C5 / RPC pooling; the `database.MainDB` shutdown-race pointer guard).

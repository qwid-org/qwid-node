# NP DoS-Resilience Cluster — NP-H2, NP-H6, NP-H10

**Date:** 2026-07-12
**Branch:** `security-fixes`
**Source:** `SECURITY_AUDIT.md` reconciliation — three OPEN HIGH networking DoS-resilience findings.

## Context

The node already has solid per-IP DoS primitives in `tcpip/helper.go` — a sliding-window rate limiter (`rateWindow` + `allowInWindow`), `AllowConnectionFromIP` / `AllowMessageFromIP`, and `IsIPBanned` / `BanIP` / `isWhitelisted`. The earlier networking sub-projects (A/B/C) wired those into the inbound TCP path (`admitPeer`) and per-topic message-size caps. Three HIGH findings remain — all *resource-exhaustion* gaps that the existing rate limiter does not cover:

- **NP-H2** [HIGH] — no cap on **total concurrent** inbound TCP connections. `admitPeer` (`tcpip/recieverTcpService.go:393`) checks ban + per-IP connection *rate* only; nothing bounds how many connections are held open concurrently, so many distributed IPs (or slow-loris holds that never send) can exhaust file descriptors.
- **NP-H6** [HIGH] — the RPC accept loop (`rpc/server/server.go:43` `ListenRPC`) spawns a `ServeConn` goroutine per accepted connection with **no limit** of any kind. RPC is loopback-only by default (NP-C4), so per-IP limiting is moot (one IP); the meaningful missing control is a concurrent-connection cap.
- **NP-H10** [HIGH] — `broadcastTransactionsMsgInLoop` (`services/transactionServices/serviceTransaction.go:58`) re-sends the **entire** mempool (up to `MaxTransactionsPerBlock` = 5000 txs) to **every** connected peer **every second**, forever. Because transactions are already gossiped on arrival (`BroadcastTxn`, `onmessage.go:113`), this periodic full-pool re-broadcast is redundant and is the amplification vector.

### Ground truth (from exploration)
- `tcpConnections map[[2]byte]map[[4]byte]net.Conn` is guarded by `PeersMutex = &sync.RWMutex{}` (`recieverTcpService.go:28-29`). Per-topic concurrent count = `len(tcpConnections[topic])`.
- `Accept(topic [2]byte, conn *net.TCPListener)` (`recieverTcpService.go:193`) runs synchronously in the listener loop: it parses the peer IP, calls `admitPeer(ip)`, then runs the NP-C3 handshake, then `publishAcceptedConn` registers the conn into `tcpConnections`. The new connection is NOT in `tcpConnections` at `admitPeer` time.
- `ListenRPC` binds `127.0.0.1` by default (`RPC_BIND_ADDRESS` override), then `for { conn := listener.Accept(); go func(){ srv.ServeConn(c) }() }`.
- Transactions gossip on arrival: `onmessage.go:113` calls `BroadcastTxn(addr, m)` for each accepted tx. A newly-subscribing peer gets the full pool on demand via `SendTransactionMsg(ip, topic)`.
- `tx.GetHash() common.Hash` (`transactionsDefinition/transaction.go:70`); `common.Hash` is a 32-byte array usable directly as a map key.
- `GenerateTransactionMsg(txs []transactionsDefinition.Transaction, mesgHead []byte, topic [2]byte)` builds the wire message.
- Rate-limit constants live in a block in `common/const.go:67-71` (`MessageRateLimit`, `ConnectionRateLimit`, …).

## Decisions (confirmed)
1. **NP-H10 fix = delta-only re-broadcast** (not throttle, not drop). Each round sends only txs not already broadcast; amplification becomes O(new txs).
2. **Cap values are fixed constants (not env-configurable):** `MaxInboundConnectionsPerTopic = 64`, `MaxConcurrentRPCConnections = 64`. Legit load is ~`MaxPeersConnected` (6) per topic and ~one persistent RPC conn per HTTP server, so 64 is ~10× headroom.

## Design

### NP-H2 — per-topic concurrent inbound-connection cap

Add a constant to `common/const.go` (in the rate-limit block):
```go
	MaxInboundConnectionsPerTopic int = 64 // NP-H2: cap concurrent inbound conns per topic (~10x the ~6 legit peers) to bound fd exhaustion / slow-loris
```

Add a pure-ish helper in `tcpip/recieverTcpService.go` that reports whether the topic is at capacity, taking the read lock:
```go
// inboundCapReached reports whether the number of concurrent inbound connections
// already registered for topic has reached MaxInboundConnectionsPerTopic. NP-H2.
func inboundCapReached(topic [2]byte) bool {
	PeersMutex.RLock()
	defer PeersMutex.RUnlock()
	return len(tcpConnections[topic]) >= common.MaxInboundConnectionsPerTopic
}
```

Enforce it in `Accept`, immediately after `admitPeer(ip)` succeeds and before the NP-C3 handshake (so an over-cap connection wastes no handshake CPU). Whitelisted IPs bypass the cap (consistent with `admitPeer`'s other gates):
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
(`isWhitelisted` is package-local in `tcpip/helper.go`.)

**Note on the check→publish race:** `Accept` runs synchronously in a single per-topic listener goroutine (`StartNewListener`), so two accepts on the same topic cannot interleave between the cap check and `publishAcceptedConn`. The cap is therefore effectively serialized per topic; a small transient overshoot across topics is harmless (the cap is a coarse resource bound, not an exact quota).

### NP-H6 — concurrent RPC-connection cap

Add a constant to `common/const.go`:
```go
	MaxConcurrentRPCConnections int = 64 // NP-H6: cap concurrent RPC conns (HTTP servers hold ~1 persistent conn each) to bound fd exhaustion
```

In `rpc/server/server.go`, add a package-level atomic counter and enforce it in the `ListenRPC` accept loop. Extract the acquire/release decision into a testable helper:
```go
var rpcConnCount int64 // NP-H6: current in-flight RPC connections

// tryAcquireRPCSlot atomically reserves a connection slot if under the cap,
// returning true on success. Pure given the counter; unit-tested directly.
func tryAcquireRPCSlot() bool {
	if atomic.AddInt64(&rpcConnCount, 1) > int64(common.MaxConcurrentRPCConnections) {
		atomic.AddInt64(&rpcConnCount, -1)
		return false
	}
	return true
}

func releaseRPCSlot() { atomic.AddInt64(&rpcConnCount, -1) }
```
Accept loop becomes:
```go
		conn, err := listener.Accept()
		if err != nil {
			logger.GetLogger().Printf("RPC accept error: %v", err)
			continue
		}
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
The `AddInt64`-then-compare-then-decrement pattern is a standard lock-free bounded semaphore: the counter may momentarily exceed the cap during a rejected acquire, but the slot is immediately returned, so the number of *live* served connections never exceeds the cap.

### NP-H10 — delta-only periodic re-broadcast

Two pure helpers in `services/transactionServices/serviceTransaction.go`:
```go
// selectNewTransactions returns the subset of txs whose hash is not already in
// seen (i.e. not yet broadcast by the periodic loop). Pure; does not mutate seen. NP-H10.
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
The loop keeps a package-level `seen` set touched only by this single goroutine (no mutex needed):
```go
func broadcastTransactionsMsgInLoop() {
	seen := make(map[common.Hash]struct{}) // NP-H10: hashes already re-broadcast by this loop
	for {
		select {
		case <-tcpip.Quit:
			logger.GetLogger().Println("broadcastTransactionsMsgInLoop: EXIT")
			return
		default:
		}

		txs := transactionsPool.PoolsTx.PeekTransactions(int(common.MaxTransactionsPerBlock), 0)
		pruneSeen(seen, txs)                       // drop mined/expired entries
		newTxs := selectNewTransactions(txs, seen) // NP-H10: delta only
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
Correctness: a tx is re-broadcast by the periodic loop exactly once (the first round it appears in the peeked set), on top of its immediate on-arrival `BroadcastTxn`. Mined/dropped txs leave `seen` via `pruneSeen`, so a tx that legitimately re-enters the pool later is re-broadcast again. New-peer catch-up is unaffected (the on-demand full-pool `SendTransactionMsg` on subscribe is unchanged). `seen` is bounded by the pool size (≤ `MaxTransactionInPool`).

## Non-goals
- Per-IP RPC ban/rate-limiting (redundant under the loopback-only default bind; if an operator overrides `RPC_BIND_ADDRESS`, that is a documented exposure — a follow-up, not this cluster).
- Making the caps env-configurable (confirmed: fixed constants).
- A global (cross-topic) inbound cap or an exact concurrent quota (the per-topic coarse bound is sufficient; exactness is unnecessary for a resource guard).
- Changing the on-arrival gossip, the mempool, message formats, or any consensus/wire/validity surface. All three fixes are node-local resource guards.

## Error handling / determinism
- Node-local; no consensus, block/tx validity, tx-hash, or wire-format impact. Transactions still fully propagate (on-arrival gossip + on-demand full-pool for new peers); NP-H10 only removes redundant re-sends.
- Over-cap inbound/RPC connections are closed immediately with a logged reason; legitimate peers/clients are far under the 64 caps.

## Testing

Pure helpers make every fix unit-testable without real sockets or CGO:
- **NP-H2:** `inboundCapReached(topic)` — seed `tcpConnections[topic]` with < cap and ≥ cap fake entries (nil `net.Conn` values under `PeersMutex`), assert false/true respectively; assert a whitelisted IP is not blocked (the `isWhitelisted` bypass is in `Accept`, so test the helper's count behavior + document the bypass).
- **NP-H6:** `tryAcquireRPCSlot`/`releaseRPCSlot` — acquire exactly `MaxConcurrentRPCConnections` slots (all succeed), the next fails, after one `releaseRPCSlot` the next succeeds; reset `rpcConnCount` to 0 in the test. Optionally a concurrent `-race` variant with N goroutines asserting live count never exceeds the cap.
- **NP-H10:** `selectNewTransactions` returns only txs whose hash ∉ seen (empty seen → all; full seen → none; partial → the complement); `pruneSeen` deletes exactly the hashes absent from the current tx slice and keeps the present ones. Build small `Transaction` values with distinct `Hash` fields (set `tx.Hash` directly; no signing/CGO needed).

Tests run with `GOROOT=/home/wonabru/sdk/go1.24.0`. Build: `GOROOT=… go build ./...`.

## Files touched
- `common/const.go` — add `MaxInboundConnectionsPerTopic`, `MaxConcurrentRPCConnections`.
- `tcpip/recieverTcpService.go` — `inboundCapReached` helper + the cap check in `Accept`.
- `rpc/server/server.go` — `rpcConnCount` + `tryAcquireRPCSlot`/`releaseRPCSlot` + accept-loop enforcement (add `sync/atomic` import).
- `services/transactionServices/serviceTransaction.go` — `selectNewTransactions`/`pruneSeen` helpers + delta loop.
- New tests: `tcpip/inbound_cap_test.go`, `rpc/server/rpc_cap_test.go`, `services/transactionServices/broadcast_delta_test.go`.

## Rollout / commit plan
`OB-120` commits (node-local, not `(CONSENSUS)`), one per finding:
1. NP-H2 — per-topic inbound-connection cap (+ helper test).
2. NP-H6 — concurrent RPC-connection cap (+ semaphore test).
3. NP-H10 — delta-only re-broadcast (+ delta/prune tests).

Not "done" until the touched packages build and the new tests pass, and `SECURITY_AUDIT.md` reconciliation moves NP-H2, NP-H6, NP-H10 to FIXED.

## Deferred (follow-ups)
- Per-IP RPC ban/rate-limiting for operator-overridden non-loopback RPC binds.
- Remaining OPEN reconciliation items (CW-H2, WH-H3, the mediums; deferred-by-design DB-C4 / NP-C4/C5 / RPC pooling; the `database.MainDB` shutdown-race pointer guard noted in the DB-cluster review).

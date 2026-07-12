# QWID-Node Comprehensive Security Audit Report

**Date:** 2026-07-02 (supersedes 2026-05-01 audit)
**Scope:** Full codebase -- 284 Go source files, 45 packages
**Methodology:** Static analysis, line-by-line code review of every file

---

## Executive Summary

| Severity | Count |
|----------|-------|
| **CRITICAL** | 27 |
| **HIGH** | 42 |
| **MEDIUM** | 52 |
| **LOW** | 37 |
| **TOTAL** | **158** |

> **Note:** Counts revised after code re-verification (2026-07-02). Findings AC-H4, NP-H1 (both HIGH) and WH-M7 (MEDIUM) were removed as NOT CONFIRMED — the cited code is already correct or already fixed. Several other findings were re-scoped; see inline **[Verified]** annotations.

The QWID-Node codebase contains **27 critical vulnerabilities** across all layers. The most severe:

- **Crypto/Wallet:** AES-CTR without authentication, IV reuse, no KDF for passwords
- **Consensus:** Double-spend via race condition, integer overflow in fees, staking history erasure
- **Networking:** RPC on 0.0.0.0 with unauthenticated tx submission, sync bypasses signature verification
- **Web:** Command injection via solc, wildcard CORS enabling wallet theft, zero auth on WebUI
- **EVM/StateDB:** Balance operations are no-ops, ecrecover is broken, access lists always return true
- **Test coverage** is critically low -- most security-sensitive packages have zero tests

---

---

## Reconciliation status (2026-07-12) — code-verified

> The severity tables below describe findings as originally reported and were **not** kept in sync with remediation. This section is the authoritative status: each finding was re-verified against the current code (branch `security-fixes`). LOW severity was not individually enumerated in this audit and is not tracked here.


| Severity | FIXED | PARTIAL | OPEN |
|---|---|---|---|
| Critical | 24 | 2 | 1 |
| High | 28 | 5 | 8 |
| Medium | 29 | 7 | 16 |


> **Update 2026-07-12 (OB-118 incomplete-fixes pass):** **CW-M1** (empty-msg/sig panic guard), **CW-H3** (wallet dir 0700 at all entry points), **NP-M12** (EncryptionOptData read under the writers' `encryptionMutex`), and **WH-C6** (all 76 website/webui/explorer RPC handler sites now use the mutex-safe `clientrpc.Call()`) are now **FIXED** — move them from the OPEN/PARTIAL lists below. Residual WH-C6 single-connection serialization-DoS (needs connection pooling) remains a follow-up.

### OPEN — still to be tackled (25)

- **NP-C5** [CRITICAL] — handleWALL still serializes the entire wallet struct; audit's own re-scoping (requires localhost+signature, so downgraded from remote-exposure CRITICAL) is accurate, but the underlying over-broad serialization is unchanged in code. _(rpc/server/server.go:178-186 handleWALL still does `r, err := json.Marshal(w)` on the full `wallet.GetActiveWallet()` struct and returns it verbatim — no field redaction added.)_
- **CW-H2** [HIGH] — Decrypted secret-key byte slices are still never zeroed after use in wallet.go, unlike the password (CW-C4) which was fixed. _(wallet/wallet.go: decrypted secret-key bytes ('ds') obtained from w.decrypt() at lines 629, 661, 769, 784, 795, 847, 865, 879 are never zeroed/cleansed after use (no MemCleanse or manual zero loop on 'ds' anywhere in the file). oqs.MemCleanse exists (crypto/oqs/oqs.go:30) but is )_
- **DB-H4** [HIGH] — Close() still has an unprotected fallback path that mutates d.db without holding the mutex when the lock isn't acquired within the timeout, racing with concurrent DB operations. _(database/DbRocksDB.go:98-164 — Close() still spawns a goroutine to acquire d.mutex.Lock() with a 1s timeout, and on timeout does `if d.db != nil { d.db.Close(); d.db = nil }` outside the mutex (lines 141-149), racing with the goroutine that may still be running under the lock; a )_
- **DB-H5** [HIGH] — Delete still acquires only a read lock (RLock) for a mutating operation, allowing concurrent readers/writers to race with a delete. _(database/DbRocksDB.go:299-311 — Delete() still calls `db.mutex.RLock()`/`defer db.mutex.RUnlock()` (a read lock) while performing db.db.Delete (a write/mutation).)_
- **DB-H6** [HIGH] — The RocksDB LOCK file is still unconditionally removed on startup, still allowing a second process instance to corrupt the DB by opening it concurrently. _(database/DbRocksDB.go:41-53 — InitPermanent still unconditionally os.Remove()s the LOCK file whenever it's present, with only a logged warning on failure, before opening the DB; no check for an actively-running owning process.)_
- **NP-H10** [HIGH] — Broadcast amplification (up to 5000 txs to all peers each second) is unchanged; audit's own remediation note confirms this is still open. _(services/transactionServices/serviceTransaction.go:57-88 broadcastTransactionsMsgInLoop still peeks up to common.MaxTransactionsPerBlock (5000) txs every 1 second and sends them to every connected peer via tcpip.GetPeersConnected/Send with no batching/throttling reduction; SECURI)_
- **NP-H2** [HIGH] — No limit on total concurrent inbound TCP connections still exists; only a new per-IP connection-rate limiter (attempts/window) was added, which is a different control. _(tcpip/recieverTcpService.go:193-260 Accept() — admitPeer() only checks IsIPBanned and AllowConnectionFromIP (a per-IP connection-attempt rate limiter over a rolling window); there is no cap anywhere on total concurrent accepted connections (no MaxConnections/len(tcpConnections) c)_
- **NP-H6** [HIGH] — No RPC-specific rate limiting was added; severity is mitigated in practice by the new loopback-only default bind (NP-C4) but the finding as stated is still true in code. _(rpc/server/server.go:42-71 ListenRPC's Accept loop has no call to AllowConnectionFromIP/AllowMessageFromIP or any other rate limiter before dispatching to srv.ServeConn; no rate-limiting code exists anywhere in rpc/server/server.go.)_
- **WH-H3** [HIGH] — Registration still directly discloses whether a username is taken, enabling enumeration. _(cmd/website/handlers/auth.go:202-204 still returns a distinct "Username already taken" 409 response when Users.Exists(req.Username) is true, with no comment/tag indicating remediation.)_
- **CW-M2** [MEDIUM] — Mnemonic generation/restore is still hard-capped at 64 bytes, so Falcon-512 keys still cannot use the mnemonic feature -- unchanged from the audit. _(wallet/wallet.go:429-431 - GetMnemonicWords() still rejects any secretLength > 64 with 'return "", fmt.Errorf("secret must be less than 64 bytes")'. No CW-M2 tag or alternate encoding scheme found anywhere in the file. Falcon-512's secret key remains far larger than 64 bytes, so )_
- **CW-M3** [MEDIUM] — The in-place password-byte toggling race is unchanged; globalMutex serializes only the two password-change functions against each other, not against other wallet methods that read passwordBytes. _(wallet/wallet.go:825-861 - ChangePasswordInPlace still repeatedly toggles the shared w.passwordBytes field in place ('w.passwordBytes = newPasswordBytes' ... 'w.passwordBytes = oldPasswordBytes') inside a loop, guarded only by globalMutex (:836-837). That mutex is acquired by Cha)_
- **DB-M1** [MEDIUM] — EIP activation still mutates cfg.ExtraEips while iterating over it, which can skip or mis-process subsequent entries on activation failure. _(core/evm/interpreter.go:93-101 — `for i, eip := range cfg.ExtraEips { ... cfg.ExtraEips = append(cfg.ExtraEips[:i], cfg.ExtraEips[i+1:]...) ... }` still mutates cfg.ExtraEips (the slice being ranged over) inside the loop body on EIP activation failure; no fix comment found.)_
- **DB-M10** [MEDIUM] — bigModExp still derives base/exp/mod lengths via raw Uint64() truncation with no explicit length ceiling in Run itself; only indirectly bounded by the gas cost computed in RequiredGas, matching the audit's original description. _(core/evm/contracts.go:342-368 bigModExp.Run still does `baseLen := ...Uint64()`, `expLen := ...Uint64()`, `modLen := ...Uint64()` from attacker-controlled 32-byte fields and uses them directly in getData/big.Int construction with no explicit check against a sane maximum; Required)_
- **DB-M3** [MEDIUM] — GVMLogger.ToString still concatenates the wrong field (ResultTxCall) for the SC-state/fault section instead of ResultSCCall. _(core/evm/logger.go:126 — `restxt += "Capture SC State and Fault: \n\n" + log.ResultTxCall` still uses log.ResultTxCall instead of log.ResultSCCall.)_
- **DB-M4** [MEDIUM] — GVMLogger still accumulates trace output via unbounded string concatenation, risking OOM on large/long-running contract executions. _(core/evm/logger.go:67-119 — every Capture* method still does unbounded `(*log).ResultXxx += fmt.Sprintf(...)` per opcode/frame with no length cap or ring buffer, for the lifetime of a tx/block trace.)_
- **DB-M8** [MEDIUM] — CloseDB still double-acquires the same non-reentrant mutex (outer Lock + Close()'s internal Lock), causing Close() to always hit its timeout/forced-cleanup path rather than closing cleanly under the lock. _(database/blockchaindb.go:35-47 — CloseDB() does `MainDB.mutex.Lock()` then calls `(*MainDB).Close()` (line 41), which internally (DbRocksDB.go:98-164) spawns a goroutine that also calls `d.mutex.Lock()` on the same sync.RWMutex — the inner lock attempt blocks until the outer 1s/5)_
- **DB-M9** [MEDIUM] — ForEachStorage's `dirty` variable is still just the map-existence bool (always true for keys from the same range), not real dirty-state tracking; misleading but functionally harmless. _(core/stateDB/methods.go:423-439 — ForEachStorage still does `for h := range shs { if value, dirty := shs[h]; dirty { cb(h,value) } }`; `dirty` is just the map-lookup "ok" bool for a key just obtained from ranging the same map, so it is always true and conveys no actual dirty-trac)_
- **NP-M1** [MEDIUM] — bannedIP map still grows unboundedly over time; only the newer rate-limit maps get pruned on ban, not the ban map itself. _(tcpip/helper.go:52-88 BanIP writes to bannedIP[ip] and calls pruneRateLimits(ip), but pruneRateLimits (lines 283-291) only deletes from msgRate/connRate maps, never from bannedIP itself; no eviction/expiry sweep of the bannedIP map exists anywhere in the file.)_
- **NP-M10** [MEDIUM] — Channel send still silently drops messages when the send channel is full; unchanged from the finding. _(services/transactionServices/serviceTransaction.go:117-129 Send(): `select { case services.SendChanTx <- nb: return true; default: return false }` — still silently drops the message on a full channel with only a caller-side log line, no retry/backpressure.)_
- **NP-M13** [MEDIUM] — A malicious peer can still request an unbounded range of block headers in a single sync response; no span cap was added to the gh handler or generateSyncMsgSendHeaders. _(services/syncService/onmessage.go:536-543 'gh' handler takes bHeight/eHeight directly from the requesting peer's message and calls SendHeaders(addr,bHeight,eHeight) with no span/size validation; services/syncService/serviceSync.go:85-121 generateSyncMsgSendHeaders clamps height t)_
- **NP-M14** [MEDIUM] — Peer topology (full connected-IP list) is still leaked to any peer via the 'hi' sync broadcast; unchanged from the finding. _(services/syncService/serviceSync.go:26-45 generateSyncMsgHeight still sets `n.TransactionsBytes[[2]byte{'P','P'}] = peers` where peers = tcpip.GetIPsConnected(), broadcasting this node's full connected-peer IP list in every 'hi' sync message with no restriction/opt-out.)_
- **NP-M2** [MEDIUM] — ChanPeer remains a fixed 50-buffer channel with blocking sends; unchanged from the finding. _(tcpip/listenerTcpService.go:14 `var ChanPeer = make(chan []byte, 50)`; sends at lines 100, 239, 247 are plain blocking sends (`ChanPeer <- ...`) with no select/default/timeout.)_
- **NP-M4** [MEDIUM] — Reconnection counter still resets on a fixed iteration cadence rather than being tied to genuine reconnection events, undermining ConnectionMaxTries; citation moved from recieverTcpService.go to listenerTcpService.go but logic is unchanged. _(tcpip/listenerTcpService.go:227-228,263-265: `resetNumber++` on every loop iteration and `if resetNumber%100==0 { reconnectionTries = 0 }` unconditionally resets the reconnection counter every 100 iterations regardless of whether errors occurred, independent of actual reconnectio)_
- **NP-M6** [MEDIUM] — RPC client still reconnects infinitely with a constant fixed interval, not backoff, as originally described. _(rpc/client/client.go:12-13,42-49,61-68 ConnectRPC retries `rpc.Dial` forever with a fixed `retryInterval = 5 * time.Second` sleep between attempts — no exponential backoff or attempt cap.)_
- **NP-M7** [MEDIUM] — Fixed 1MB reply buffer per RPC call is unchanged. _(rpc/client/client.go:14,56: `bufferSize = 1024 * 1024` and `reply := make([]byte, bufferSize)` per call — unchanged fixed 1MB allocation per RPC call.)_

### PARTIAL / deferred — what remains (14)

- **DB-C4** [CRITICAL] — Refund bookkeeping now works correctly, but refunds/gas price are still never applied to the actual fee charged (audit's own Phase 3a note says this half is deferred). _(core/stateDB/methods.go:196-208 — AddRefund/SubRefund/GetRefund are real (accumulate/clamp a refund counter), tagged "DB-C4 accounting-only"; but blocks/evaluate.go:515,524,611,622,669,677 hardcode GasPrice=0 and GetRefund() is never consumed to reduce a charged fee (grep shows G)_
- **NP-C4** [CRITICAL] — Remote exposure fixed via loopback-only default bind, but TRAN itself is still unauthenticated at the RPC layer by design. _(rpc/server/server.go:43-54 binds to 127.0.0.1 by default (RPC_BIND_ADDRESS override) fixing remote exposure; but common/const.go:50 ConnectionsWithoutVerification still lists TRAN, so handleTRAN (server.go:505-509) remains reachable without any RPC-level signature check for any p)_
- **NP-H12** [HIGH] — Height-claim eclipse (fabricated chain height) is now mitigated by multi-peer consensus, but arbitrary peer-IP injection from 'hi' messages still drives unvalidated outbound connection attempts — the topology-poisoning vector itself is not filtered. _(services/syncService/onmessage.go:148-198 still ingests an arbitrary peer IP list from a peer's 'hi' message (txn[[2]byte{'P','P'}]) and dials each one (StartSubscribingNonceMsg/StartSubscribingSyncMsg/StartSubscribingTransactionMsg) with no validation beyond ban-check/dedup; sep)_
- **NP-H5** [HIGH] — The large constant itself is unchanged and still governs the Transaction topic; other topics were tightened, so this is a partial mitigation, not a removal of the large cap. _(common/const.go:47 MaxMessageSizeBytes is still 151126018 (~144MB) and is still the effective cap for TransactionTopic (tcpip/helper.go:209-210), by documented design tradeoff (un-chunked tx-gossip/sync batches); all other topics now use much smaller MaxMessageSizeForTopic caps.)_
- **NP-H9** [HIGH] — A generic per-IP message-rate limiter now throttles TCP messages on the transaction connection, but there is still no dedicated per-peer transaction-count limiter, and one message can carry up to 5000 txs. _(services/transactionServices/onmessage.go:1-45 has no per-peer transaction-rate logic (only a global pool-size cap at line 39, MaxTransactionInPool); however tcpip/listenerTcpService.go:379 now calls AllowMessageFromIP (100 msgs/10s per IP, tcpip/helper.go:245-259) generically fo)_
- **WH-H5** [HIGH] — Two basic headers were added to JSON API responses in webui/website, but no CSP/HSTS anywhere and the actual served HTML pages remain unheadered. _(cmd/webui/main.go:185-186 and cmd/website/handlers/handlers.go:180-181 set X-Content-Type-Options: nosniff and X-Frame-Options: DENY (tagged WH-H5) inside the CORS middleware used only for /api/* JSON routes. No Content-Security-Policy or HSTS anywhere; the static HTML pages serv)_
- **WH-H9** [HIGH] — Request body size is bounded on the wallet-holding apps (webui, website); explorer's POST endpoint is not. _(cmd/webui/main.go:177 and cmd/website/handlers/handlers.go:171 apply http.MaxBytesReader (2 MiB cap, tagged WH-H9) inside their CORS middleware, covering all wallet-holding endpoints. cmd/explorer/main.go's corsMiddleware (lines ~101-112) has no MaxBytesReader, so /api/contact (t)_
- **CW-M7** [MEDIUM] — Minimum password length (8 chars) is enforced on password-change flows and the website registration flow, but the CLI wallet-generator and webui wallet-creation endpoint still accept 1-character passwords. _(wallet/wallet.go:145-157 defines MinPasswordLength=8 and ValidatePasswordStrength(), enforced in ChangePassword (:743) and ChangePasswordInPlace (:829), and in cmd/website/handlers/auth.go:189. However it is NOT enforced on initial wallet creation in cmd/generateNewWallet/main.go)_
- **WH-M1** [MEDIUM] — Website registration now enforces an 8-char minimum, but website password-change (6 chars) and all of WebUI (1 char) remain weak exactly as described. _(cmd/website/handlers/auth.go:172 Register() calls wallet.ValidatePasswordStrength (8+ chars, tagged WH-M1). However cmd/website/handlers/wallet_handlers.go:193 ChangePassword still only requires `len(req.NewPassword) < 6`, and cmd/webui/handlers/handlers.go:208 (CreateWallet) and)_
- **WH-M12** [MEDIUM] — Bind address is now configurable, but the explorer still defaults to binding 0.0.0.0 with no authentication. _(cmd/explorer/main.go:68-72 makes BIND_ADDRESS configurable (tagged WH-M12) but defaults to "0.0.0.0" when unset, unchanged from the audited behavior; the explorer still has no authentication of any kind (by design, since it is read-only), so it remains reachable and unauthenticat)_
- **WH-M3** [MEDIUM] — Rate limiting was added to the public multi-user website's financial endpoints; WebUI (now local-only + authenticated) still has none. _(cmd/website/main.go:137,140,143-145 wrap send/staking/dex/token endpoints in handlers.FinancialRateLimit (auth.go:44-52, 20 req/min per IP). cmd/webui has no rate limiter at all on its equivalent endpoints (grep for RateLimit/Limiter in cmd/webui/handlers and main.go returns noth)_
- **WH-M4** [MEDIUM] — Rounding fixes the common off-by-one truncation bug, but amounts remain float64-typed and still lose precision at large values. _(common/amount.go:12-14 CoinToBaseUnits uses math.Round (tagged WH-M4, fixing the truncation-toward-zero off-by-one) and is used consistently by all financial handlers (e.g. transaction_handlers.go:265, staking_handlers.go:78, dex_handlers.go:127). The function's own comment ackno)_
- **WH-M6** [MEDIUM] — Bind address is now configurable for a reverse-proxy/TLS deployment, but the out-of-the-box default is unchanged (binds all interfaces on plain HTTP). _(cmd/website/main.go:159-163 makes bind address configurable via BIND_ADDRESS env var (tagged WH-M6) so operators can restrict to 127.0.0.1 behind a TLS proxy, but the default (empty env var) still resolves to binding all interfaces on plain HTTP, matching the audit's original beh)_
- **WH-M9** [MEDIUM] — Session wallets are wiped at logout/expiry/replacement, but during an active session (up to 30 min) the usable private keys still sit decrypted in memory exactly as described. _(cmd/website/handlers/session.go:15-17 sessionTimeout is still 30*time.Minute, matching the audit's citation exactly. wipeSessionWallet()/Wallet.Wipe() (session.go:96, wallet/wallet.go:123-132, tagged CW-C4/CW-H2) only zeroes the password and derived KDF key on Delete/DeleteByUser)_

### FIXED (81) — verified remediated

- **Critical:** AC-C1, AC-C2, AC-C3, AC-C4, CW-C1, CW-C2, CW-C3, CW-C4, DB-C1, DB-C2, DB-C3, DB-C5, DB-C6, NP-C1, NP-C2, NP-C3, NP-C6, NP-C7, WH-C1, WH-C2, WH-C3, WH-C4, WH-C5, WH-C6
- **High:** AC-H1, AC-H2, AC-H3, AC-H5, AC-H6, AC-H7, CW-H1, CW-H3, CW-H4, CW-H5, CW-H6, DB-H1, DB-H2, DB-H3, DB-H7, DB-H8, NP-H11, NP-H13, NP-H14, NP-H4, NP-H7, NP-H8, WH-H1, WH-H2, WH-H4, WH-H6, WH-H7, WH-H8
- **Medium:** AC-M1, AC-M2, AC-M3, AC-M4, AC-M5, AC-M6, AC-M7, AC-M8, AC-M9, CW-M1, CW-M4, CW-M5, CW-M6, CW-M8, DB-M2, DB-M5, DB-M6, DB-M7, NP-M3, NP-M5, NP-M8, NP-M9, NP-M11, NP-M12, WH-M10, WH-M11, WH-M2, WH-M5, WH-M8

**WH-C6 note:** fixed in the concurrent HTTP servers (`cmd/website`, `cmd/webui`, `cmd/explorer` — all 76 handler call sites now use the mutex-safe `clientrpc.Call()`). Residual: all RPC still funnels through one shared connection, so a slow call still delays others — that needs connection pooling / correlation IDs as a follow-up (tracked as action item 18 below), not a correctness bug.

## 1. Crypto & Wallet

### CRITICAL

| ID | Finding | File:Lines |
|----|---------|-----------|
| CW-C1 | **AES-CTR without authentication (malleable ciphertext)** -- Wallet uses AES-CTR providing no integrity. Attacker with wallet file access can modify private keys undetected. Must use AES-GCM. | `wallet/wallet.go:265-292` |
| CW-C2 | **Static IV reuse for all encryptions** -- Same IV for Account1, Account2, and all additional accounts. XOR of two ciphertexts = XOR of plaintext keys. Destroys confidentiality. | `wallet/wallet.go:273,286,386-411` |
| CW-C3 | **No KDF for password** -- Single SHAKE-256 hash, no salt, no iterations. Brute-forceable at billions/sec on GPU. Must use Argon2id. | `wallet/wallet.go:121-125` |
| CW-C4 | **Password stored as plaintext Go string** -- Immutable, cannot be zeroed. Survives in memory until GC. Visible in core dumps/swap. | `wallet/wallet.go:38-39` |

### HIGH

| ID | Finding | File:Lines |
|----|---------|-----------|
| CW-H1 | **C.CString memory leaks** -- `C.CString()` allocates C heap never freed. Leaks on every KEM/Signature init. | `crypto/oqs/oqs.go:46,146,264,366` |
| CW-H2 | **Secret keys not zeroed** -- Raw key bytes from `ExportSecretKey()` and `decrypt()` never zeroed after use. | `wallet/wallet.go:166-205,508-540` |
| CW-H3 | **Wallet directory 0755** -- World-readable. Should be 0700. | `wallet/wallet.go:420` |
| CW-H4 | **ShowInfo logs key lengths** -- Metadata leakage to stdout. | `wallet/wallet.go:104-119` |
| CW-H5 | **Verify() never calls verifier.Clean()** -- C memory leak per signature verification. | `wallet/wallet.go:804-853` |
| CW-H6 | **Private key length validation commented out** -- Malformed keys accepted. | `common/types.go:371-378` |

### MEDIUM

| ID | Finding | File:Lines |
|----|---------|-----------|
| CW-M1 | Empty sig/msg causes panic in Verify (reachable from network) | `wallet/wallet.go:807,825` |
| CW-M2 | Mnemonic limited to 64B keys -- Falcon-512 (1281B) cannot use mnemonic | `wallet/wallet.go:294-325` |
| CW-M3 | ChangePasswordInPlace race condition on passwordBytes | `wallet/wallet.go:699-771` |
| CW-M4 | SigName silently truncated at 20 chars -- could select wrong algorithm | `crypto/oqs/encryptSchemes.go:192-194` |
| CW-M5 | liboqs version printed at startup -- reveals library version | `crypto/oqs/oqs.go:17` |
| CW-M6 | encrypt() produces unused 16-byte zero prefix (CBC vestige) | `wallet/wallet.go:272-274` |
| CW-M7 | No minimum password strength -- 1-char passwords accepted | `wallet/wallet.go:167,434,454` |
| CW-M8 | File copy uses default 0666 permissions -- wallet copies world-readable | `wallet/helperWallet.go:68` |

---

## 2. Account, Consensus & Staking

### CRITICAL

| ID | Finding | File:Lines |
|----|---------|-----------|
| AC-C1 | **TOCTOU race in AddBalance enables double-spend** -- Unlocks mutex between check and SetBalance. Concurrent txs drain more than balance. | `blocks/blockAccountState.go:29-36` |
| AC-C2 | **Integer overflow in fee: GasPrice*GasUsage** -- Both int64, no overflow check. Overflows to negative, bypasses fee check. | `blocks/processBlock.go:242`, `blocks/processTransaction.go:18` |
| AC-C3 | **StakingDetails map erased each operation** -- Every new-height stake/unstake/reward replaces entire map, destroying all history. | `account/stakeAccount.go:101-104,161-164,191-194,223-226` |
| AC-C4 | **Oracle verification bypassed during sync** -- Malicious sync peer injects blocks with fabricated oracle values permanently. | `blocks/processBlock.go:82-90` |

### HIGH

| ID | Finding | File:Lines |
|----|---------|-----------|
| AC-H1 | **Unstake index removal bug** -- Removing from slices shifts indices; wrong entries removed or panic. | `account/stakeAccount.go:147-151` |
| AC-H2 | **Nonce is int16 (32,768 values)** -- No nonce uniqueness check. Weak replay protection. | `transactionsDefinition/baseTransaction.go:15` |
| AC-H3 | **No chain ID validation** -- Cross-chain replay: testnet txs replayable on mainnet. | `transactionsDefinition/transaction.go:232-395` |
| AC-H5 | **Float64 for reward distribution** -- Precision loss above 2^53. Creates/destroys value. | `blocks/processBlock.go:365-391` |
| AC-H6 | **DEX price manipulation** -- Denominator approaches zero. No slippage protection. Sandwich attacks. | `blocks/evaluate.go:93-110` |
| AC-H7 | **Supply invariant inconsistency** -- Two code paths use different formulas. Consensus divergence. | `blocks/processBlock.go:464,509` |

### MEDIUM

| ID | Finding | File:Lines |
|----|---------|-----------|
| AC-M1 | GetCoinLiquidityInDex missing lock -- map iteration without mutex | `account/accountsDexStates.go:127-133` |
| AC-M2 | delegatedAccount not bounds-checked -- panic on invalid index | `account/accountsStakingStates.go:118` |
| AC-M3 | RemoveStakingAccountsFromDB prefix accumulation bug | `account/accountsStakingStates.go:121-133` |
| AC-M4 | Voting allows vote overwriting at same height | `voting/votingEncryptionSchemes.go:40-42` |
| AC-M5 | ResetLastVoting skips index 255 (uint8 loop) | `voting/votingEncryptionSchemes.go:83-95` |
| AC-M6 | GetSigNames error silently discarded (fmt.Errorf not returned) | `blocks/processBlock.go:474-477` |
| AC-M7 | Escrow returns early on first delegated account match | `blocks/processTransaction.go:440-441` |
| AC-M8 | LastHeightStoredInAccounts O(n) linear scan | `account/accountsStates.go:183-198` |
| AC-M9 | Float reward calculation -- non-deterministic across architectures | `account/reward.go:12-16` |

---

## 3. Networking & P2P

> **DoS-hardening remediation (2026-07-09, branch `security-fixes`, OB-114/OB-114b):** Per-topic inbound message-size caps replace the single 151 MB global `MaxMessageSizeBytes` enforcement at the receive-loop check (`MaxMessageSizeForTopic`, `tcpip/helper.go`): Nonce/SelfNonce → 64 KB, Sync → 16 MB, RPC (localhost-bound) → 1 MB. **The TransactionTopic cap is intentionally kept at the full global 151 MB** because tx-gossip (up to `MaxTransactionsPerBlock` = 5000 txs, `services/transactionServices/serviceTransaction.go:69,94`) and sync "bx" recovery (up to `MaxNumberTransactionInChunk` = 100 txs) are sent as **un-chunked batches** — an earlier draft that capped this topic at 1 MB would reject legitimate batched traffic and trip `ReduceTrustRegisterPeer` → `BanIP` against honest peers, breaking sync recovery; tightening it requires chunking those send paths (a documented follow-up). Also added: a per-IP message-rate limiter (100 messages / 10 s, `AllowMessageFromIP`) and a reconnection-rate limiter (20 connection attempts / 60 s, `AllowConnectionFromIP`, raised from an initial 5 since a single legitimate node restart opens ~4 inbound connections across the Transaction/Nonce/SelfNonce/Sync topics) — both whitelist-exempt (`isWhitelisted`) — plus a lengthened ban duration (2 s → 60 s, `BannedTimeSeconds`). Peer identity/authentication (**NP-C3**, sub-project B) and transport encryption (**NP-H14**, sub-project C) remain open.
>
> **NP-C3 peer-auth handshake remediation (2026-07-09, branch `security-fixes`, OB-115, sub-project B, final task):** Every P2P connection now runs a mutual post-quantum challenge-response handshake (`tcpip/handshake.go`, `HandshakeInitiator`/`HandshakeResponder`) immediately at connection setup, before any topic traffic. Each side signs a domain-separated, session-bound transcript (`"QWID-P2P-HS-v1" || nonceI || nonceR || claimedAddr`, `handshakeTranscript`) with its real wallet identity (`activeWalletIdentity()`, built from `wallet.GetActiveWallet().Account1`) using the same Falcon-512/MAYO-5 dual-signature scheme and `wallet.Verify` used for transactions; fresh random nonces on both sides and the domain tag prevent replay and cross-protocol signature reuse. This cryptographically binds the connection to a pubkey-derived nodeID — closing the original NP-C3 gap ("peer identity taken from TCP `RemoteAddr()`, gated only by a plaintext magic value"). Wiring: outbound (`tcpip/listenerTcpService.go`, `StartNewConnection`) runs `HandshakeInitiator` on the freshly dialed connection right after `net.DialTCP` succeeds; inbound (`tcpip/recieverTcpService.go`, `Accept`) runs `HandshakeResponder` on the freshly accepted connection right after the existing ban/rate-limit admission check (`admitPeer`, split out of the former `RegisterPeer`). On **either** side, the connection is published into `tcpConnections` (making it visible to `LoopSend`/the receive loop) **only after the handshake succeeds** — `RegisterPeer`/`Accept` were restructured (`admitPeer` + `publishAcceptedConn`) and the outbound dial path was reordered specifically so no topic `Send`/`Receive` can interleave on the wire with the handshake's own framed messages; a handshake failure closes the connection and calls `ReduceTrustRegisterPeer` under `PeersMutex`, rejecting the peer, without ever registering it. Verified-nodeID storage (`storeVerifiedNodeID`, `verifiedNodeIDs` map) is added as a store-and-log-only foundation for a future nodeID-keyed ban/allowlist — **no code gates on it**; the trust model remains OPEN peering (any peer presenting a valid signature over the transcript is accepted, regardless of which nodeID it authenticates as). **Deferred:** nodeID-keyed ban/allowlist using `verifiedNodeIDs`, and full MITM resistance / transport encryption (sub-project C, **NP-H14** — an authenticated key exchange could layer on top of this handshake). Not covered: the mid-loop reconnect-on-`<-ERR->` path inside `StartNewConnection`'s receive loop (`net.DialTCP` re-dial on read error) does not re-run the handshake — pre-existing behavior for that path already does not re-publish into `tcpConnections` either, so it is not a new gap, but it means a reconnected stream after a read error is not re-authenticated; noted as a follow-up.
>
> **NP-H14 transport-encryption remediation (2026-07-10, branch `security-fixes`, OB-116, sub-project C):** P2P transport is now **PQ-KEM authenticated encrypted** — sub-project C extends the peer-auth handshake with an ephemeral ML-KEM-768 KEM (public key + ciphertext bound in the signed transcript ⇒ MITM-resistant), derives per-direction ChaCha20-Poly1305 session keys via HKDF, and wraps every post-handshake connection so all P2P traffic is encrypted and forward-secret; a decrypt failure or missing KEM fails closed (no plaintext fallback). This completes the networking hardening: **A (DoS/rate limits) + B (peer-auth handshake, NP-C3) + C (transport encryption)**.

### CRITICAL

| ID | Finding | File:Lines |
|----|---------|-----------|
| NP-C1 | **Data race on whiteListIPs map** -- Read/written without mutex. Crash. | `tcpip/helper.go:16,23-25,30,45,179` |
| NP-C2 | **LoopSend busy-spins (100% CPU)** -- default case with no sleep. | `tcpip/listenerTcpService.go:55-108` |
| NP-C3 | ~~**IP identity not cryptographically bound**~~ -- No handshake/challenge; peer identity taken from TCP `RemoteAddr()`, gated only by a plaintext magic value. **[FIXED 2026-07-09, OB-115: mutual PQ challenge-response handshake at connection setup binds every connection to a pubkey-derived nodeID; see remediation note above. nodeID-keyed ban/allowlist and transport encryption remain deferred.]** | `tcpip/handshake.go`, `tcpip/recieverTcpService.go` (`Accept`), `tcpip/listenerTcpService.go` (`StartNewConnection`) |
| NP-C4 | **RPC on 0.0.0.0, TRAN unauthenticated** -- Anyone submits txs via port 19009. [x] partially fixed in prior audit | `rpc/server/server.go:43,482-486` |
| NP-C5 | **handleWALL serializes full wallet data** -- Entire wallet struct (`json.Marshal(wallet.GetActiveWallet())`) is returned. *(Downgraded from remote-exposure: `WALL` is NOT in the no-verification list, so it still requires a localhost source AND a valid signature — not remotely reachable. Risk is defense-in-depth / local exposure.)* **[Verified: re-scoped, effectively HIGH not CRITICAL]** | `rpc/server/server.go:169-178` |
| NP-C6 | **`bx` sync skips signature verification** -- Txs stored to DB without any check. | `services/transactionServices/onmessage.go:117-147` |
| NP-C7 | **Unsafe OptData slice access** -- No length validation. Crafted nonce tx crashes node. | `services/nonceService/onmessage.go:92` |

### HIGH

| ID | Finding | File:Lines |
|----|---------|-----------|
| NP-H2 | No connection limit on TCP Accept | `tcpip/recieverTcpService.go:193-205` |
| NP-H3 | ~~No peer authentication -- any IP gets full trust~~ **[FIXED 2026-07-09, OB-115 -- see NP-C3 remediation note above; note the trust model is intentionally still OPEN peering post-fix -- any peer that completes the handshake with a valid signature is accepted]** | `tcpip/recieverTcpService.go` (`Accept`) |
| NP-H4 | Message reassembly buffer large-allocation DoS -- bounded at `MaxMessageSizeBytes` (~144 MB), not truly unbounded, but that per-topic cap is huge. **[Verified: re-scoped + citation corrected]** | `tcpip/listenerTcpService.go:262-267` |
| NP-H5 | MaxMessageSizeBytes = 144 MB per peer | common const |
| NP-H6 | No RPC rate limiting | `rpc/server/server.go:42-63` |
| NP-H7 | handleSTAK out-of-bounds access | `rpc/server/server.go:455-467` |
| NP-H8 | handleADEX lacks length validation | `rpc/server/server.go:337-342` |
| NP-H9 | No per-peer transaction rate limiting | `services/transactionServices/onmessage.go:13` |
| NP-H10 | Broadcast amplification -- 5000 txs/sec to all peers | `services/transactionServices/serviceTransaction.go:58-87` |
| NP-H11 | Non-cryptographic PRNG for oracle values (predictable, influences consensus) -- uses `golang.org/x/exp/rand`, not `math/rand`, but equally insecure. **[Verified: import corrected]** | `services/nonceService/serviceNonce.go:113-114` |
| NP-H12 | Eclipse attack via peer IP injection in "hi" messages | `services/syncService/onmessage.go:146-199` |
| NP-H13 | MinPeersForLargeSync = 0 (should be >= 2) | `services/syncService/onmessage.go:45` |
| NP-H14 | No TLS/encryption on any channel -- all plaintext | Systemic |

### MEDIUM

| ID | Finding | File:Lines |
|----|---------|-----------|
| NP-M1 | Banned map grows unboundedly | `tcpip/helper.go:14,52` |
| NP-M2 | ChanPeer blocks sender (buffer 50) | `tcpip/listenerTcpService.go:14,100` |
| NP-M3 | Slice bounds panic in message framing (len < 7) -- recovered by connection teardown. **[Verified: citation corrected]** | `tcpip/listenerTcpService.go:261` |
| NP-M4 | Reconnection counter resets every 100 iterations | `tcpip/recieverTcpService.go:211-213` |
| NP-M5 | RegisterPeer trusts any non-banned IP immediately | `tcpip/recieverTcpService.go:297-341` |
| NP-M6 | RPC client infinite reconnect without backoff | `rpc/client/client.go:43-50` |
| NP-M7 | 1 MB fixed reply buffer per RPC call | `rpc/client/client.go:38` |
| NP-M8 | handleACCT lacks length validation | `rpc/server/server.go:436-453` |
| NP-M9 | Bad tx promotion to confirmed DB on peer request | `services/transactionServices/onmessage.go:196-208` |
| NP-M10 | Channel send silently drops messages | `services/transactionServices/serviceTransaction.go:118-131` |
| NP-M11 | defer merkleTrie.Destroy() inside loop (memory accumulation) | `services/nonceService/onmessage.go:224` |
| NP-M12 | EncryptionOptData read without lock (data race) | `services/nonceService/serviceNonce.go:125` |
| NP-M13 | Unbounded header serving on sync request | `services/syncService/serviceSync.go:85-122` |
| NP-M14 | Topology leak via peer sharing | `services/syncService/serviceSync.go:43` |

---

## 4. Web Handlers & HTTP

### CRITICAL

| ID | Finding | File:Lines |
|----|---------|-----------|
| WH-C1 | **Arbitrary Solidity compilation / file read via solc `import`** -- WebUI compiles fully attacker-controlled `req.Code` via solc, so `import "/etc/passwd"` leaks file contents in compiler errors. *(Not shell command injection: solc is invoked with an arg array, and the website path compiles a fixed template from regex-validated name/symbol, not user code.)* **[Verified: re-scoped]** | `cmd/webui/handlers/handlers.go:1454-1545` |
| WH-C2 | **Wildcard CORS on all endpoints** -- `Access-Control-Allow-Origin: *`. WebUI has no auth, so any website drains wallet via `/api/send`. | All `main.go` files |
| WH-C3 | **WebUI has zero authentication** -- All endpoints open: send, stake, trade, mnemonic, password change, logs. | `cmd/webui/main.go:77-108` |
| WH-C4 | **No CSRF protection anywhere** -- No tokens generated or validated on any endpoint. | All handler files |
| WH-C5 | **Mnemonic exposed without re-authentication** -- Private key recovery phrase returned with session only (website) or nothing (webui). | `cmd/website/handlers/wallet_handlers.go:133-157`, `cmd/webui/handlers/handlers.go:306-329` |
| WH-C6 | **Shared RPC channel = DoS + response mismatch** -- Single `InRPC/OutRPC` pair for all handlers. One slow call blocks all. Race = user A sees user B's data. | All handler files |

### HIGH

| ID | Finding | File:Lines |
|----|---------|-----------|
| WH-H1 | Compiler errors leak file paths (raw solc stderr returned) | `token_handlers.go:118`, `handlers.go:1501` |
| WH-H2 | Welcome tx abuse -- 5000 QWD/registration, multi-IP farming | `cmd/website/handlers/auth.go:164-165,261-336` |
| WH-H3 | Username enumeration via registration | `cmd/website/handlers/auth.go:101-104` |
| WH-H4 | No Secure flag on session cookie (HTTP transport) | `cmd/website/handlers/session.go:84-93` |
| WH-H5 | No security headers (CSP, X-Frame-Options, etc.) | All apps |
| WH-H6 | WebUI log file reading without auth | `cmd/webui/handlers/handlers.go:1877-1954` |
| WH-H7 | SMTP header injection in contact form -- spam relay | `cmd/explorer/handlers/contact_handler.go:50-63` |
| WH-H8 | No session invalidation on login -- stolen sessions persist | `cmd/website/handlers/auth.go:174-221` |
| WH-H9 | Unbounded request body -- no MaxBytesReader | All handlers |

### MEDIUM

| ID | Finding | File:Lines |
|----|---------|-----------|
| WH-M1 | Weak password policy (6 chars website, 1 char webui) | auth.go, handlers.go |
| WH-M2 | math/rand for tx nonces (predictable, enables front-running) | Multiple files |
| WH-M3 | No rate limiting on financial endpoints | All tx/staking/dex handlers |
| WH-M4 | Float-to-int64 precision loss in amounts | Transaction handlers |
| WH-M5 | No HTTP server timeouts (Slowloris vulnerability) | All main.go |
| WH-M6 | Website binds 0.0.0.0 on plain HTTP | `cmd/website/main.go:161` |
| WH-M8 | Rate limiter memory leak (no background cleanup) | `cmd/website/handlers/auth.go:22-54` |
| WH-M9 | Wallet in memory for full 30-min session | `cmd/website/handlers/session.go:19-23` |
| WH-M10 | X-Forwarded-For trusted directly -- rate limit bypass | `cmd/website/handlers/auth.go:56-61` |
| WH-M11 | No account lockout after failed logins | `cmd/website/handlers/auth.go:174-221` |
| WH-M12 | Explorer binds 0.0.0.0 without auth | `cmd/explorer/main.go:69` |

---

## 5. Database & Core/EVM

> **EVM Phase 1 remediation (2026-07-03, branch `security-fixes`, commits OB-91…OB-99):**
> The EVM `StateAccount` is now persisted to RocksDB (mirroring native account persistence), and the following correctness findings are **FIXED**: **DB-C3** (ecrecover fails loud — secp256k1 is meaningless on this post-quantum chain), **DB-C5** (real EIP-2929 access list), **DB-C6** (AddLog implemented), **DB-H2** (Suicide/HasSuicided, scoped within-tx), **DB-H3** (RevertToSnapshot storage-key corruption fixed via a change journal), **DB-H7/H8** (memory bounds/panic guards, overflow-safe), **DB-M2** (opCreate real nonce), **DB-M5** (dataCopy returns a copy), **DB-M6/M7** (ABI Pack/Unpack panics recovered into errors). **DB-H1** is addressed by the external `StateMutex` contract + persistence-entry locking.
> **EVM Phase 2 remediation (2026-07-03, commits OB-101…OB-104): DB-C1 FIXED.** `GetBalance`/`AddBalance`/`SubBalance` now bridge to the authoritative native `account.Accounts` balances (int64 base units, 1:1), journaled for revert; `Empty` (EIP-161) considers balance; SELFDESTRUCT is supply-neutral (burns on self-destruct-to-self); `account.SetBalance` upholds the `Address==key` invariant. See `docs/superpowers/specs/2026-07-03-evm-phase2-balance-bridge-design.md`.
> **EVM Phase 3a remediation (2026-07-08, branch `security-fixes`, OB-110 DB-C5 followup): DB-C2 FIXED, DB-C4 partially addressed.** `CanTransfer`/`Transfer` are wired (via `evmCanTransfer`/`evmTransfer` in `blocks/evaluate.go`, bridging to native balances per the Phase 2 bridge) and enforced in `Call`/`CallCode`/`create`, so `msg.value` transfers without funds are rejected. `State.PrepareAccessList` (Phase 1's EIP-2929 warm/cold implementation) is now invoked at tx-start in `EvaluateSC`, warming the sender, recipient, and active precompiles (`vm.ActivePrecompiles(rules)`) before the entry `Create`/`Call` — correcting execution semantics for cold/warm access accounting. DB-C4 remains open for the gas-economics half: gas-limit tx format, post-execution `gasUsed×gasPrice` fee, and applied refunds are deferred to **Phase 3b** (changes the signed tx format, `Verify`, `BlockFee`, and every sender).
>
> **EVM Phase 3b remediation (2026-07-08, branch `security-fixes`, OB-112): DB-C2 failure semantics FIXED for the contract-call path.** `EvaluateSCForBlock` now classifies `EvaluateSC` errors via `isEVMExecutionError` (`blocks/evaluate.go`): a reverting/erroring top-level contract call (e.g. a Solidity `require()`/`revert`, out-of-gas, invalid opcode) is a **per-tx failure** — the tx is included in the block, its size-based fee is charged, its value transfer/storage writes stay reverted (via the EVM's internal snapshot from Phase 3a), no contract is registered, and the block is **not** rejected. Node/processing errors (DB failures, anything not positively matched by `isEVMExecutionError`) remain block-fatal, as before. This matches Ethereum-style behavior (sender pays for a failed call) for the general contract-call path. **The DEX path (`EvaluateSCDex`) is out of scope and remains block-fatal** on any error — per-tx failure semantics for native DEX settlement are deferred. Note: a failed tx's persisted `OutputLogs` (tracer output, including a wall-clock timestamp) are **informational and non-consensus** — `OutputLogs` is excluded from `GetBytesWithoutSignature`/the tx-hash preimage (it appears only in `GetBytes` DB serialization), so it affects no tx hash, merkle root, block validity, or supply invariant; this is pre-existing behavior shared with the success path.

> **AC-H6 remediation (2026-07-08, branch `security-fixes`, OB-113): FIXED.** DEX buy/sell pricing is now exact constant-product (`x·y=k`). The swap denominator changed from `tokenPool − 2·amountToken` to `tokenPool − amountToken` (via the pure helper `constantProductPrice` in `blocks/evaluate.go`), so `k` is preserved by construction and the price diverges only as a trade approaches the **whole** token pool (blocked by the `denominator > 0` guard) rather than at **half** the pool — eliminating the "denominator approaches zero" blowup and the previous silent no-op for trades ≥ half the pool. By design decision, **no user slippage/min-output parameter and no swap fee were added**, and block-ordering (sandwich) mitigation beyond the honest constant-product curve was not pursued. Add-liquidity (op 2), withdraw (ops 5/6), sign conventions, balance checks, and pool-update lines are unchanged. See `docs/superpowers/specs/2026-07-08-ac-h6-dex-constant-product-design.md`. **Follow-up (OB-113b):** near the full-pool boundary the priced coin amount can exceed `math.MaxInt64` when scaled to base units, and casting an overflowing float to `int64` is implementation-defined in Go (non-portable across architectures); the buy and sell branches now scale via the pure helper `scaleToInt64`, which guards NaN/Inf/overflow so such an (always-unaffordable) trade becomes a portable no-op instead of a non-deterministic cast that could otherwise trip the balance check and reject the whole block.

### CRITICAL

| ID | Finding | File:Lines |
|----|---------|-----------|
| DB-C1 | **StateDB balance ops are no-ops** -- SubBalance/AddBalance do nothing. GetBalance returns 0. EVM cannot track any balances. | `core/stateDB/methods.go:103-111` |
| DB-C2 | **EVM value transfer checks commented out** -- CanTransfer and Transfer disabled in Call/create. Arbitrary value without funds. | `core/evm/evm.go:174-176,196,412-414,436` |
| DB-C3 | **ecrecover precompile is broken stub** -- Ignores signature entirely. Interprets first 32 bytes as address. All Ethereum sig verification broken. | `core/evm/contracts.go:165-200` |
| DB-C4 | **Gas refund mechanism non-functional** -- AddRefund/SubRefund are no-ops. Users overcharged. | `core/stateDB/methods.go:137-145` |
| DB-C5 | **Access list always returns true** -- All addresses "warm". Cold access surcharges never applied. Cheap DoS. | `core/stateDB/methods.go:195-215` |
| DB-C6 | **AddLog is no-op** -- All EVM events discarded. Breaks all event monitoring, DApp functionality. | `core/stateDB/methods.go:234-236` |

### HIGH

| ID | Finding | File:Lines |
|----|---------|-----------|
| DB-H1 | StateDB has no concurrency protection (maps without mutex) | `core/stateDB/methods.go` |
| DB-H2 | Suicide/HasSuicided always returns false -- contracts never destroyed | `core/stateDB/methods.go:175-180` |
| DB-H3 | RevertToSnapshot uses hash values as keys -- corrupts storage | `core/stateDB/methods.go:217-228` |
| DB-H4 | Database Close race condition -- timeout bypasses mutex | `database/DbRocksDB.go:98-164` |
| DB-H5 | Delete uses RLock instead of Lock -- concurrent corruption | `database/DbRocksDB.go:299-311` |
| DB-H6 | LOCK file unconditionally removed on startup -- dual-process corruption | `database/DbRocksDB.go:43-49` |
| DB-H7 | Memory GetPtr/GetCopy int64 signedness -- negative index bypass | `core/evm/memory.go:69,85` |
| DB-H8 | Memory Set/Set32 panic instead of error -- node crash | `core/evm/memory.go:41-43,53-55` |

### MEDIUM

| ID | Finding | File:Lines |
|----|---------|-----------|
| DB-M1 | EIP activation modifies slice during iteration | `core/evm/interpreter.go:93-101` |
| DB-M2 | opCreate hardcodes nonce 23 -- address collisions | `core/evm/instructions.go:610` |
| DB-M3 | GVMLogger ToString uses wrong field | `core/evm/logger.go:126` |
| DB-M4 | GVMLogger unbounded string concatenation (OOM) | `core/evm/logger.go:67-119` |
| DB-M5 | dataCopy precompile returns reference not copy | `core/evm/contracts.go:243-245` |
| DB-M6 | ABI Unpack panics on invalid type (crashes node) | `core/abi/type.go:258` |
| DB-M7 | ABI packNum panics on unexpected kind | `core/abi/pack.go:82-84` |
| DB-M8 | CloseDB guaranteed deadlock (double lock acquisition) | `database/blockchaindb.go:35-47` |
| DB-M9 | ForEachStorage misleading variables (dirty is always true) | `core/stateDB/methods.go:263-279` |
| DB-M10 | bigModExp truncation risk on >2^64 lengths | `core/evm/contracts.go:371-375` |

---

## 6. Test Coverage Assessment

### Packages With ZERO Test Files

| Package | Security Impact |
|---------|----------------|
| `transactionsDefinition/` | No tests for tx signing/verification |
| `transactionsPool/` | No tests for pool ops, merkle tree |
| `voting/` | No tests for vote counting/manipulation |
| `oracles/` | No tests for oracle values |
| `tcpip/` | No tests for networking, banning, peer mgmt |
| `rpc/client/`, `rpc/server/` | **No tests for any RPC handler** |
| `database/` | No tests for DB operations, locking |
| `core/stateDB/` | No tests for any StateDB method |
| `cmd/website/handlers/` | No tests for auth, sessions |
| `cmd/webui/handlers/` | No tests |
| `cmd/explorer/handlers/` | No tests |
| `genesis/`, `pubkeys/` | No tests |

### Packages With Insufficient Coverage

| Package | Gaps |
|---------|------|
| `crypto/oqs/` | Only byte serialization tested. Zero Sign/Verify/KeyGen/Clean tests |
| `wallet/` | No encrypt/decrypt, ChangePasswordInPlace, mnemonic, bad-input Verify tests |
| `account/` | No concurrent access, overflow, or DB tests |
| `blocks/` | No processTransaction, processBlock, evaluate tests |
| `services/` | Only message structure tests. No processing logic tests |

---

## 7. Prioritized Remediation Plan

### P0 -- Fix Immediately (Blocks Production)

| # | Action | Fixes |
|---|--------|-------|
| 1 | Bind RPC to `127.0.0.1`, remove TRAN from unauthenticated list | NP-C4 |
| 2 | Remove/protect handleWALL | NP-C5 |
| 3 | Add authentication to WebUI | WH-C3 |
| 4 | Replace CORS `*` with specific origins | WH-C2 |
| 5 | Fix AddBalance TOCTOU -- hold lock through entire read-check-write | AC-C1 |
| 6 | Add integer overflow checks on fee calculation | AC-C2 |
| 7 | Replace AES-CTR with AES-GCM | CW-C1 |
| 8 | Generate unique IV/nonce per encryption | CW-C2 |
| 9 | Implement Argon2id KDF for passwords | CW-C3 |
| 10 | Verify transactions in `bx` sync handler | NP-C6 |
| 11 | Add bounds checking to all RPC/network slice accesses | NP-C7, NP-H7, NP-H8 |
| 12 | Add mutex to whiteListIPs | NP-C1 |

### P1 -- Fix Before Beta

| # | Action | Fixes |
|---|--------|-------|
| 13 | Implement StateDB balance tracking, re-enable EVM value transfers | DB-C1, DB-C2 |
| 14 | Fix or disable ecrecover precompile | DB-C3 |
| 15 | Implement gas refunds, access lists, AddLog | DB-C4, DB-C5, DB-C6 |
| 16 | Add CSRF tokens to all POST endpoints | WH-C4 |
| 17 | Require re-auth for mnemonic access | WH-C5 |
| 18 | Add RPC request multiplexer with correlation IDs | WH-C6 |
| 19 | Sandbox solc execution | WH-C1 |
| 20 | Fix LoopSend busy-spin | NP-C2 |
| 21 | Add connection/rate limits | NP-H2, NP-H6, NP-H9 |
| 22 | Fix staking detail map erasure | AC-C3 |
| 23 | Fix DB Delete to use Lock() | DB-H5 |
| 24 | Fix CloseDB deadlock | DB-M8 |
| 25 | Fix RevertToSnapshot logic | DB-H3 |
| 26 | Add chain ID validation | AC-H3 |
| 27 | Add DEX slippage protection | AC-H6 |
| 28 | Free C strings in crypto/oqs | CW-H1 |
| 29 | Add Clean() calls to verification paths | CW-H5 |

### P2 -- Fix Before Production

| # | Action | Fixes |
|---|--------|-------|
| 30 | Add TLS support | NP-H14 |
| 31 | ~~Add peer authentication handshake~~ **[FIXED 2026-07-09, OB-115 -- see NP-C3 remediation note]** | NP-H3 |
| 32 | Validate peer IPs from sync messages | NP-H12 |
| 33 | Set MinPeersForLargeSync >= 2 | NP-H13 |
| 34 | Add security headers middleware | WH-H5 |
| 35 | Add MaxBytesReader to all handlers | WH-H9 |
| 36 | Add HTTP server timeouts | WH-M5 |
| 37 | Set Secure flag on cookies | WH-H4 |
| 38 | Fix welcome tx abuse (CAPTCHA, global limits) | WH-H2 |
| 39 | Sanitize email headers | WH-H7 |
| 40 | Fix unstake index removal | AC-H1 |
| 41 | Fix supply invariant inconsistency | AC-H7 |
| 42 | Fix prefix accumulation bug | AC-M3 |
| 43 | Zero sensitive memory | CW-C4, CW-H2 |
| 44 | Set wallet directory to 0700 | CW-H3 |
| 45 | Add Verify() input validation | CW-M1 |
| 46 | Remove LOCK file deletion | DB-H6 |
| 47 | Increase ban duration to >= 300s | Networking |
| 48 | Cap message reassembly buffers | NP-H4 |
| 49 | Fix X-Forwarded-For trust | WH-M10 |
| 50 | Use integer arithmetic for rewards | AC-H5, AC-M9 |

### P3 -- Ongoing

- Write comprehensive test suite (RPC handlers, tx verification, web auth)
- Fuzz test all network message parsers
- Replace int16 nonce with int64
- Implement account lockout
- Add session invalidation on login
- Enforce strong passwords
- Fix voting edge cases
- Replace panics with error returns in EVM/ABI

---

## Conclusion

The codebase has **significant security vulnerabilities across every layer**. The most urgent:

1. **Financial** -- Double-spend race, fee overflow, non-functional EVM balances
2. **Network** -- Unauthenticated RPC, no rate limiting, sync bypasses verification
3. **Web** -- Zero auth on WebUI, wildcard CORS, command injection, no CSRF
4. **Crypto** -- Broken wallet encryption (IV reuse, no auth, no KDF)

**The EVM implementation is largely non-functional** -- most StateDB methods are stubs returning defaults. This breaks all smart contract security guarantees.

Test coverage must be dramatically expanded. Most security-critical packages have zero tests.

**This codebase is not production-ready.** The P0 items must be addressed before any public deployment.

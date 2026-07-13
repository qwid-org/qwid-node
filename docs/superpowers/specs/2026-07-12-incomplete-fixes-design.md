# Incomplete-Fixes Pass — WH-C6, CW-H3, NP-M12, CW-M1

**Date:** 2026-07-12
**Branch:** `security-fixes`
**Source:** The 2026-07-12 audit reconciliation flagged four findings whose remediation was written but is **ineffective** (a fix that doesn't take effect, an unadopted wrapper, a wrong mutex, a half-guard). This closes those gaps.

## Context

Each of the four had an attempted fix that the reconciliation proved doesn't actually work. These are small, independent corrections — no design ambiguity beyond the WH-C6 scope decision (already made: concurrent HTTP servers only).

## The four fixes

### 1. CW-H3 [HIGH] — wallet directory world-readable (0755 defeats 0700)

`wallet/wallet.go:541` `StoreJSON` correctly does `os.MkdirAll(w.HomePath, 0700)`, but three callers **pre-create the same `HomePath` at `0755`** first, and `MkdirAll` does not chmod an existing directory, so the world-readable mode persists. `cmd/website/handlers/auth.go:209` already uses `0700` (correct).

**Fix:** change the mode `0755` → `0700` at the three pre-creation sites (same `HomePath`, so this makes the intended owner-only perms effective):
- `cmd/generateNewWallet/main.go:63` — `os.MkdirAll(folderPath, 0755)` → `0700`
- `cmd/webui/handlers/handlers.go:254` — `os.MkdirAll(wl.HomePath, 0755)` → `0700`
- `cmd/gui/qtwidgets/helper.go:60` — `os.MkdirAll(w.HomePath, 0755)` → `0700`

### 2. NP-M12 [MEDIUM] — wrong mutex on `EncryptionOptData`

`services/nonceService/serviceNonce.go:137-144` guards the `EncryptionOptData` read with `voting.VotesEncryptionMutex`, but the writers (`SetEncryptionData`/`ResetToDefaultEncryptionOptData`, `:50-65`) use **`encryptionMutex`** — so the read still races the writers.

**Fix (mind the lock ordering):** the `AfterReset` voting check legitimately needs `VotesEncryptionMutex`, and `ResetToDefaultEncryptionOptData` acquires `encryptionMutex` *internally* — so we must NOT hold `encryptionMutex` while calling it. Split into two non-overlapping critical sections: do the `AfterReset` handling under `VotesEncryptionMutex`, release it, then read `EncryptionOptData` under `encryptionMutex`:
```go
voting.VotesEncryptionMutex.Lock()
if voting.AfterReset {
	ResetToDefaultEncryptionOptData() // takes encryptionMutex internally
	voting.AfterReset = false
}
voting.VotesEncryptionMutex.Unlock()

encryptionMutex.Lock()
optData = append(optData, EncryptionOptData...) // NP-M12: read under the writers' lock
encryptionMutex.Unlock()
```
No lock is held across the other, so there is no deadlock and the read is now consistent with the writers. (`encryptionMutex` is package-level in the same file, `serviceNonce.go:43`.)

### 3. CW-M1 [MEDIUM] — empty message panics `Verify`

`wallet.Verify` (`wallet/wallet.go:938`) guards `len(sig) < 1` but not an empty `msg`; `oqs.Signature.Verify` (`crypto/oqs/oqs.go:452`) does `&message[0]` unconditionally → an empty `msg` (network-reachable via `transaction.Verify` → `wallet.Verify`) panics. (The same file's `&signature[0]` is a second panic site: `signature` is length-checked only for `> MaxLength`, not `== 0`.)

**Fix (guard at both layers — fail-fast + defense-in-depth for all callers):**
- `wallet.Verify` (`wallet/wallet.go`, next to the existing `len(sig)` guard): add `if len(msg) < 1 { return false }`.
- `oqs.Signature.Verify` (`crypto/oqs/oqs.go`, before the first `&…[0]` dereference): add `if len(message) == 0 || len(signature) == 0 { return false, errors.New("empty message or signature") }` — this protects **every** `oqs.Verify` caller from the panic, not just the wallet path. (`publicKey==0` is already caught by the existing `!= LengthPublicKey` check.)

Empty-input verification correctly returns `false`/error (a malformed/malicious input, never a legitimate signed payload on this chain).

### 4. WH-C6 [CRITICAL] — shared RPC channel request/response pairing

A mutex-safe wrapper `clientrpc.Call(msg []byte) []byte` exists (`rpc/client/client.go:31-36`, serializes `InRPC <- msg; <-OutRPC` under `reqMu`) but **no handler uses it** — all use the raw `clientrpc.InRPC <- msg; reply := <-clientrpc.OutRPC` pattern over the single global unbuffered channel pair.

Analysis: with **unbuffered** channels and a **single** `ConnectRPC` goroutine, the happy-path request/response IS correctly paired (a second `InRPC` send cannot complete until the prior reply is consumed). The real risk is a handler that **breaks the pair** — an early return, timeout, or panic between the send and the receive, or an error path that skips the receive — after which the next request receives a stale reply (cross-user response mixup). `Call()` makes send+receive **atomic** (no early exit between them), eliminating that class of bug.

**Scope decision (made):** adopt `clientrpc.Call(msg)` **only in the concurrent HTTP servers** — `cmd/website`, `cmd/webui`, `cmd/explorer` — where many goroutines share the channel and a broken pair could leak one user's reply to another. The single-user CLI/GUI tools (`cmd/sendingTransaction`, `cmd/generateNewWallet`, `cmd/gui`) run sequentially (no concurrency, no race) and are left as-is.

**Out of scope:** the residual true DoS — all RPC is serialized over one connection, so a slow call delays all others — which requires connection pooling / correlation IDs (a much larger change). Noted as a follow-up.

**Fix:** in the three HTTP-server packages, replace each adjacent `clientrpc.InRPC <- X` … `reply := <-clientrpc.OutRPC` pair with `reply := clientrpc.Call(X)`. **Each site must be the simple adjacent send-then-receive pattern**; if any site does work *between* the send and the receive (or sends/receives non-1:1), it must be handled individually — flag it rather than blindly converting.

## Non-goals

- Connection pooling / RPC parallelism (the WH-C6 serialization DoS).
- Converting the CLI/GUI raw RPC sites (no concurrency race there).
- Any other reconciliation finding (the DB-concurrency cluster, etc.) — separate batches.

## Error handling / determinism

- All four are node-local defensive fixes; none affects consensus, block/tx validity, or the wire format.
- NP-M12 and WH-C6 are concurrency-correctness fixes (mutex discipline); CW-H3 is filesystem perms; CW-M1 is input validation.

## Testing

- **CW-M1 (real unit tests):** `wallet.Verify(nil/empty msg, validLenSig, validPubkey, …)` returns `false` and does NOT panic; `oqs.Signature.Verify(emptyMsg, …)` and `(…, emptySig)` return `(false, error)` and do NOT panic. Non-empty happy path still verifies.
- **WH-C6 (Call serialization):** a unit test in `rpc/client` that runs many concurrent `Call()` goroutines against a stub `ConnectRPC`-style echo loop (a goroutine reading `InRPC` and echoing a request-tagged reply to `OutRPC`), asserting every caller receives ITS OWN reply (no mixup) — this proves `Call()` pairs correctly under concurrency. Plus a build-level check: no raw `InRPC <-`/`<-OutRPC` pattern remains in `cmd/website`/`cmd/webui`/`cmd/explorer` (grep).
- **NP-M12 (inspection + optional `-race`):** verified primarily by inspection (read now under `encryptionMutex`, matching writers; no lock-order overlap). Optionally a `-race` test hammering `SetEncryptionData` while the read path runs.
- **CW-H3 (inspection + perm test):** the three sites now pass `0700`; optionally a test that `os.MkdirAll(tmp, 0700)` then `os.Stat` reports `0700` (documents the intended mode). The cmd/ mains are not easily unit-testable — verified by inspection.

Tests run with `GOROOT=/home/wonabru/sdk/go1.24.0`.

## Files touched

- `cmd/generateNewWallet/main.go`, `cmd/webui/handlers/handlers.go`, `cmd/gui/qtwidgets/helper.go` — CW-H3 perms.
- `services/nonceService/serviceNonce.go` — NP-M12 mutex.
- `wallet/wallet.go`, `crypto/oqs/oqs.go` — CW-M1 guards (+ tests).
- `cmd/website/**`, `cmd/webui/**`, `cmd/explorer/**` handler files — WH-C6 `Call()` adoption.
- `rpc/client/client_test.go` (new) — the `Call()` concurrency test.

## Rollout / commit plan

`OB-xx` commits (node-local, not `(CONSENSUS)`); one per finding for clean review:
1. CW-M1 — empty-input guards + oqs/wallet tests.
2. CW-H3 — three `0755`→`0700`.
3. NP-M12 — read under `encryptionMutex`.
4. WH-C6 — adopt `Call()` in the three HTTP-server packages + the `Call()` concurrency test.

Update the `SECURITY_AUDIT.md` reconciliation section to move CW-M1/CW-H3/NP-M12 to FIXED and WH-C6 to FIXED (scoped: HTTP servers; serialization-DoS follow-up noted).

## Deferred (follow-ups)
- WH-C6 residual: RPC connection pooling / correlation IDs to remove single-connection serialization.
- The remaining OPEN/PARTIAL reconciliation items (DB-H4/H5/H6 concurrency cluster, CW-H2 key zeroing, NP-H2/H6/H10, etc.).

# Incomplete-Fixes Implementation Plan (WH-C6, CW-H3, NP-M12, CW-M1)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close four findings whose remediation was written but ineffective (world-readable wallet dir, wrong mutex, empty-msg panic, unadopted RPC wrapper).

**Architecture:** Four independent, node-local fixes. No consensus/wire/format impact.

**Tech Stack:** Go 1.23.6.

## Global Constraints
- Build/test with `GOROOT=/home/wonabru/sdk/go1.24.0`. Example: `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./wallet/ ./crypto/oqs/ ./rpc/...`.
- Branch `security-fixes`. Commit `OB-xx` (NOT `(CONSENSUS)`). End messages with `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- `clientrpc.Call(msg []byte) []byte` already exists (`rpc/client/client.go:31-36`, serializes send+receive under `reqMu`); the package is imported as `clientrpc "github.com/qwid-org/qwid-node/rpc/client"`.
- Do not change consensus, tx format, or the RPC channel design; WH-C6 only ADOPTS the existing `Call()` in the concurrent HTTP servers.

---

## Task 1: CW-M1 — empty-input guards in Verify (+ tests)

**Files:** Modify `wallet/wallet.go`, `crypto/oqs/oqs.go`; test `crypto/oqs/oqs_verify_test.go` (new) + `wallet/wallet_verify_test.go` (new).

- [ ] **Step 1: Failing tests**

`crypto/oqs/oqs_verify_test.go`:
```go
package oqs

import "testing"

func TestVerifyRejectsEmptyMessageOrSignatureNoPanic(t *testing.T) {
	var s Signature
	if err := s.Init("Falcon-512", nil); err != nil {
		t.Skipf("oqs Falcon unavailable: %v", err)
	}
	defer s.Clean()
	// empty message must return (false, error), never panic on &message[0]
	if ok, err := s.Verify(nil, []byte{1}, make([]byte, 897)); ok || err == nil {
		t.Fatalf("empty message: got ok=%v err=%v, want false + error", ok, err)
	}
	// empty signature likewise
	if ok, err := s.Verify([]byte{1}, nil, make([]byte, 897)); ok || err == nil {
		t.Fatalf("empty signature: got ok=%v err=%v, want false + error", ok, err)
	}
}
```

`wallet/wallet_verify_test.go`:
```go
package wallet

import "testing"

func TestVerifyRejectsEmptyMessageNoPanic(t *testing.T) {
	// len(msg)<1 must be rejected at the top of wallet.Verify (pure Go, no CGO),
	// mirroring the existing len(sig)<1 guard. Must not panic.
	if Verify(nil, []byte{1}, make([]byte, 897), "Falcon-512", "MAYO-5", false, false) {
		t.Fatal("empty message must not verify")
	}
	if Verify([]byte{1}, nil, make([]byte, 897), "Falcon-512", "MAYO-5", false, false) {
		t.Fatal("empty signature must not verify")
	}
}
```

- [ ] **Step 2: Run to verify it fails** — `GOROOT=… go test ./crypto/oqs/ -run TestVerifyRejectsEmpty ./wallet/ -run TestVerifyRejectsEmpty` → FAIL (the empty-message case panics or verifies).

- [ ] **Step 3: Add the guards**

In `crypto/oqs/oqs.go` `Signature.Verify`, add as the FIRST statement (before the pubkey-length check, so an empty message is rejected regardless of pubkey and before any `&…[0]`):
```go
	if len(message) == 0 || len(signature) == 0 {
		return false, errors.New("empty message or signature") // CW-M1: avoid &x[0] panic
	}
```
(`errors` is already imported.)

In `wallet/wallet.go` `Verify`, next to the existing `if len(sig) < 1 { return false }` guard, add:
```go
	if len(msg) < 1 { // CW-M1: empty message would panic the underlying oqs Verify
		return false
	}
```

- [ ] **Step 4: Run + build** — `GOROOT=… go test ./crypto/oqs/ ./wallet/ -run TestVerifyRejectsEmpty -v && GOROOT=… go build ./...` → PASS.
- [ ] **Step 5: Commit** — `OB-118 CW-M1: guard empty message/signature in wallet.Verify + oqs.Verify (avoid panic)` + Co-Authored-By.

---

## Task 2: CW-H3 — wallet directory 0700 (fix the pre-creation callers)

**Files:** Modify `cmd/generateNewWallet/main.go`, `cmd/webui/handlers/handlers.go`, `cmd/gui/qtwidgets/helper.go`.

- [ ] **Step 1: Change the three pre-creation modes 0755 → 0700**
- `cmd/generateNewWallet/main.go:63` — `os.MkdirAll(folderPath, 0755)` → `os.MkdirAll(folderPath, 0700)`
- `cmd/webui/handlers/handlers.go:254` — `os.MkdirAll(wl.HomePath, 0755)` → `os.MkdirAll(wl.HomePath, 0700)`
- `cmd/gui/qtwidgets/helper.go:60` — `os.MkdirAll(w.HomePath, 0755)` → `os.MkdirAll(w.HomePath, 0700)`

Add a short `// CW-H3: owner-only; matches StoreJSON's 0700 (MkdirAll won't chmod an existing dir)` comment at each.

- [ ] **Step 2: Confirm no other 0755 wallet-dir pre-creation remains** — `grep -rn "MkdirAll(.*07" cmd/ wallet/` — every wallet-`HomePath` creation should now be `0700`. (Non-wallet dirs are out of scope; do not change them.)

- [ ] **Step 3: Build** — `GOROOT=… go build ./...` → exit 0. (These are `main`/handler packages not easily unit-tested; verified by inspection + build.)

- [ ] **Step 4: Commit** — `OB-118 CW-H3: create wallet dir 0700 at all entry points (fix 0755 pre-creation)` + Co-Authored-By.

---

## Task 3: NP-M12 — read EncryptionOptData under the writers' mutex

**Files:** Modify `services/nonceService/serviceNonce.go`.

- [ ] **Step 1: Fix the reader (lines ~137-144)**

Replace the current block:
```go
	voting.VotesEncryptionMutex.Lock()
	if voting.AfterReset {
		ResetToDefaultEncryptionOptData()
		voting.AfterReset = false
	}
	// NP-M12: read the shared EncryptionOptData while still holding the lock.
	optData = append(optData, EncryptionOptData...)
	voting.VotesEncryptionMutex.Unlock()
```
with two non-overlapping critical sections (so `ResetToDefaultEncryptionOptData`'s internal `encryptionMutex` acquisition can't self-deadlock, and the read is guarded by the SAME `encryptionMutex` the writers use):
```go
	voting.VotesEncryptionMutex.Lock()
	if voting.AfterReset {
		ResetToDefaultEncryptionOptData() // takes encryptionMutex internally
		voting.AfterReset = false
	}
	voting.VotesEncryptionMutex.Unlock()

	// NP-M12: read EncryptionOptData under encryptionMutex — the lock the writers
	// (SetEncryptionData/ResetToDefaultEncryptionOptData) hold — not VotesEncryptionMutex.
	encryptionMutex.Lock()
	optData = append(optData, EncryptionOptData...)
	encryptionMutex.Unlock()
```
(`encryptionMutex` is package-level in the same file, `serviceNonce.go:43`.)

- [ ] **Step 2: Build + vet (+ optional race)** — `GOROOT=… go build ./... && GOROOT=… go vet ./services/nonceService/`. Expected: clean. (The fix is a mutex-correctness change verified by inspection; a full race repro needs the nonce service running — note the limitation.)

- [ ] **Step 3: Commit** — `OB-118 NP-M12: read EncryptionOptData under encryptionMutex (was wrong mutex)` + Co-Authored-By.

---

## Task 4: WH-C6 — adopt clientrpc.Call() in the concurrent HTTP servers (+ Call test)

**Files:** Modify handler files under `cmd/website/`, `cmd/webui/`, `cmd/explorer/`; test `rpc/client/client_test.go` (new).

- [ ] **Step 1: Write the Call() concurrency test** — `rpc/client/client_test.go`:
```go
package client

import (
	"sync"
	"testing"
)

// TestCallPairsResponsesUnderConcurrency proves Call() serializes a full
// request/response pair, so concurrent callers never receive each other's reply.
func TestCallPairsResponsesUnderConcurrency(t *testing.T) {
	stop := make(chan struct{})
	go func() { // stub ConnectRPC: echo each request back as its reply
		for {
			select {
			case m := <-InRPC:
				OutRPC <- m
			case <-stop:
				return
			}
		}
	}()
	defer close(stop)

	const N = 50
	var wg sync.WaitGroup
	mismatch := make([]bool, N)
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			reply := Call([]byte{byte(i)})
			if len(reply) != 1 || reply[0] != byte(i) {
				mismatch[i] = true
			}
		}(i)
	}
	wg.Wait()
	for i, m := range mismatch {
		if m {
			t.Fatalf("Call %d received a mismatched reply", i)
		}
	}
}
```

- [ ] **Step 2: Run it** — `GOROOT=… go test ./rpc/client/ -run TestCallPairs -race -v` → PASS (Call() is already correct; this locks the property in). If it fails/flakes, STOP and report (would indicate a real `Call()` bug).

- [ ] **Step 3: Adopt `clientrpc.Call()` in the three HTTP-server packages**

In every handler file under `cmd/website/`, `cmd/webui/`, and `cmd/explorer/`, replace each adjacent raw pair:
```go
	clientrpc.InRPC <- X
	reply := <-clientrpc.OutRPC
```
with:
```go
	reply := clientrpc.Call(X)
```
Find them with `grep -rn "clientrpc.InRPC <-" cmd/website cmd/webui cmd/explorer`. For each match, confirm the very next use is `<-clientrpc.OutRPC` assigned to a variable, and that NOTHING happens between the send and the receive. **If any site does work between the send and the receive, or does not follow the 1-send-1-receive shape, DO NOT convert it — list it in the report for individual handling.** Preserve the receiving variable's name and any surrounding logic. Do NOT touch `cmd/sendingTransaction/`, `cmd/generateNewWallet/`, or `cmd/gui/` (single-threaded, out of scope).

- [ ] **Step 4: Verify no raw pattern remains in the three packages** — `grep -rn "clientrpc.InRPC <-\|<-clientrpc.OutRPC" cmd/website cmd/webui cmd/explorer` should return nothing (except any site you deliberately left and reported). Build: `GOROOT=… go build ./...` → exit 0.

- [ ] **Step 5: Commit** — `OB-118 WH-C6: adopt mutex-safe clientrpc.Call() in website/webui/explorer RPC handlers` + Co-Authored-By.

---

## Final verification
- [ ] `GOROOT=… go build ./...` → exit 0.
- [ ] `GOROOT=… go test ./wallet/ ./crypto/oqs/ ./rpc/client/ ./services/nonceService/` → PASS.
- [ ] Update `SECURITY_AUDIT.md` reconciliation section: move **CW-M1, CW-H3, NP-M12** to FIXED; **WH-C6** to FIXED (scoped to the concurrent HTTP servers; note the residual single-connection serialization-DoS as a pooling follow-up).

## Deferred (not in this plan)
- WH-C6 residual: RPC connection pooling / correlation IDs.
- Remaining OPEN/PARTIAL reconciliation items (DB-H4/H5/H6, CW-H2, NP-H2/H6/H10, etc.).

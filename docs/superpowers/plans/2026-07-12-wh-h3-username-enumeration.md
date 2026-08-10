# WH-H3 Username Enumeration Mitigation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop the registration endpoint from disclosing whether a username exists, by returning a generic response for the taken-username (and `Create`-race) cases instead of a distinct "Username already taken" 409.

**Architecture:** One node-local web-handler change in `cmd/website/handlers/auth.go`: keep the existence check (it guards against overwriting an existing user's wallet dir) but genericize its response, and genericize the `Users.Create` error response too. The existing per-IP registration rate-limit is the enumeration throttle and is unchanged. Verified with a CGO-free `httptest` unit test.

**Tech Stack:** Go 1.23.6 (build with the `sdk/go1.24.0` toolchain), `net/http`, `net/http/httptest`.

## Global Constraints
- Build/test with `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go`. This repo uses CGO; export before building:
  ```
  export GOROOT=/home/wonabru/sdk/go1.24.0
  export PATH=$GOROOT/bin:$PATH
  export CGO_CFLAGS="-isystem $HOME/local/include"
  export CGO_LDFLAGS="-L$HOME/local/lib -L/usr/local/intelpython3/lib -lrocksdb -lstdc++ -lm -lz -lsnappy -llz4 -lzstd -lbz2 -lpthread -ldl"
  ```
- Branch `security-fixes`. Commit `OB-123` (NOT `(CONSENSUS)` — node-local web handler). End the commit message with a blank line then `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- Generic message (verbatim, used at BOTH sites): `Registration could not be completed. Please try different details.` — status `http.StatusBadRequest` (400), uniform with the other registration validation failures (NOT a distinct 409).
- Do NOT remove the `Users.Exists(req.Username)` check — it prevents a duplicate registration from overwriting an existing user's wallet directory. Only its response changes.
- Do NOT change `Login` (already generic), the rate-limit (`registerLimiter.allow(ip, 5, 10*time.Minute)`), the wallet/consensus layer, or the wire format.

---

## Task 1: Genericize the registration existence-disclosure responses (+ httptest)

**Files:**
- Modify: `cmd/website/handlers/auth.go` (the taken-username response at `:202-204`; the `Users.Create` error branch at `:261`)
- Test: `cmd/website/handlers/register_enum_test.go` (new)

**Interfaces:**
- Consumes (existing, unchanged): `Register(w http.ResponseWriter, r *http.Request)`; package globals `Users *UserRegistry` and `registerLimiter *rateLimiter`; `JsonError(w, msg string, code int)` which writes `{"error": msg}` with the status; `type UserRegistry struct { mu sync.RWMutex; users map[string]*UserEntry; filePath string }`; `type rateLimiter struct { entries map[string][]time.Time; ... }` (constructed as `&rateLimiter{entries: make(map[string][]time.Time)}`); `getClientIP` derives the IP from `r.RemoteAddr`.

- [ ] **Step 1: Write the failing test** — create `cmd/website/handlers/register_enum_test.go`:
```go
package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestRegisterDoesNotDiscloseUsernameExists verifies WH-H3: registering an
// already-taken username returns the same generic 400 as other registration
// failures, not a distinct "Username already taken" 409 enumeration oracle.
// The taken path returns at the Exists check, before any wallet/oqs work, so
// this test needs no CGO.
func TestRegisterDoesNotDiscloseUsernameExists(t *testing.T) {
	// Save and restore the package globals this test mutates.
	savedUsers, savedLimiter := Users, registerLimiter
	defer func() { Users, registerLimiter = savedUsers, savedLimiter }()

	// Seed a registry with an existing username (direct map write; no file I/O).
	Users = &UserRegistry{users: map[string]*UserEntry{"takenuser": {}}}
	// Fresh limiter so a single request is never throttled.
	registerLimiter = &rateLimiter{entries: make(map[string][]time.Time)}

	body := strings.NewReader(`{"username":"takenuser","password":"password123"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/register", body)
	req.RemoteAddr = "203.0.113.5:40000"
	rr := httptest.NewRecorder()

	Register(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("taken username: status = %d, want 400 (must not be a distinct 409)", rr.Code)
	}
	var resp map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	msg := resp["error"]
	for _, leak := range []string{"taken", "Taken", "exist", "Exist"} {
		if strings.Contains(msg, leak) {
			t.Fatalf("response leaks existence: %q contains %q", msg, leak)
		}
	}
	if msg != "Registration could not be completed. Please try different details." {
		t.Fatalf("unexpected message: %q", msg)
	}
}
```

- [ ] **Step 2: Run to verify it fails** — `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./cmd/website/handlers/ -run TestRegisterDoesNotDiscloseUsernameExists -v` → FAIL: current code returns status `409` and message `Username already taken` (contains "taken").

- [ ] **Step 3: Genericize the taken-username response** — in `cmd/website/handlers/auth.go`, replace:
```go
	if Users.Exists(req.Username) {
		JsonError(w, "Username already taken", http.StatusConflict)
		return
	}
```
with:
```go
	if Users.Exists(req.Username) {
		// WH-H3: do not disclose that the username exists. Return the same generic
		// 400 as other registration failures (not a distinct "already taken"/409),
		// so the response is not a trivially-scriptable enumeration oracle. Bulk
		// enumeration is further throttled by registerLimiter (5/10min/IP). The
		// existence check is retained because the wallet directory is derived from
		// the username and must not be overwritten.
		JsonError(w, "Registration could not be completed. Please try different details.", http.StatusBadRequest)
		return
	}
```

- [ ] **Step 4: Genericize the `Users.Create` error branch** — in the same file, replace:
```go
	if err := Users.Create(req.Username, req.Password, walletDir, address); err != nil {
		JsonError(w, fmt.Sprintf("Failed to register user: %v", err), http.StatusInternalServerError)
		return
	}
```
with:
```go
	if err := Users.Create(req.Username, req.Password, walletDir, address); err != nil {
		// WH-H3: Create also guards duplicates; on a TOCTOU race with the Exists
		// check above it returns "user already exists". Do not surface that — log
		// server-side and return the same generic message so this path is not a
		// fallback enumeration oracle.
		logger.GetLogger().Println("register: Users.Create failed:", err)
		JsonError(w, "Registration could not be completed. Please try different details.", http.StatusBadRequest)
		return
	}
```
(`logger` and `fmt` are already imported and still used elsewhere in the file — do not remove either import.)

- [ ] **Step 5: Run the test + build** —
```
GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./cmd/website/handlers/ -run TestRegisterDoesNotDiscloseUsernameExists -v
GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go build ./...
```
→ test PASS, build exit 0.

- [ ] **Step 6: Confirm no other distinct existence disclosure remains** — `grep -rn "already taken\|already exists\|StatusConflict" cmd/website/handlers/` should show no user-facing registration disclosure (the `Users.Create` internal `"user already exists"` error string in `users.go` may remain — it is server-side only and no longer surfaced to the client).

- [ ] **Step 7: Commit**
```bash
git add cmd/website/handlers/auth.go cmd/website/handlers/register_enum_test.go
git commit -m "$(printf 'OB-123 WH-H3: generic registration response (stop username enumeration disclosure)\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Final verification
- [ ] `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go build ./...` → exit 0.
- [ ] `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./cmd/website/handlers/ -run TestRegisterDoesNotDiscloseUsernameExists` → PASS.
- [ ] Update `SECURITY_AUDIT.md` reconciliation: move **WH-H3** from OPEN to FIXED; High OPEN −1 (→ 0), High FIXED +1; add a note that the mitigation is generic messaging + existing rate-limit, with the documented residual (success/failure outcome + response timing still allow throttled inference; full elimination needs an email-confirmation loop / timing normalization — deferred). (Controller handles this doc edit after the final review, mirroring prior clusters.)

## Deferred (not in this plan)
- Timing normalization / email-confirmation registration loop to remove the residual success/timing inference.
- The remaining OPEN reconciliation items (the mediums; deferred-by-design DB-C4 / NP-C4/C5 / RPC pooling; broaden `Wipe()` adoption; `database.MainDB` shutdown-race pointer guard).

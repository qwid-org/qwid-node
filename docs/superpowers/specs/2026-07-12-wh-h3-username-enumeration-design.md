# WH-H3 — Reduce Username Enumeration at Registration

**Date:** 2026-07-12
**Branch:** `security-fixes`
**Source:** `SECURITY_AUDIT.md` reconciliation — the last OPEN HIGH finding.

## Context

The multi-user website (`cmd/website`) registers users by username. `Register`
(`cmd/website/handlers/auth.go`) rejects a taken username with a **distinct**
`"Username already taken"` **409 Conflict** response, which directly confirms
whether a username exists — a username-enumeration oracle (WH-H3).

### Ground truth (from exploration)
- Registration is **already** per-IP rate-limited: `registerLimiter.allow(ip, 5, 10*time.Minute)` at `auth.go:170` (5 attempts / 10 min / IP). This already throttles bulk enumeration; it is the enumeration mitigation and is **kept**.
- Login **already** avoids enumeration: `Login` returns a generic `"Invalid username or password"` (401) for any auth failure and does not distinguish user-not-found from wrong-password. No change needed there.
- The only existence disclosure is the `Register` 409 at `auth.go:203`. There is no separate "username availability" endpoint.
- `Users.Exists(req.Username)` (`auth.go:202`) is also a **clobbering guard**: the wallet directory (`UserWalletDir(...)`, derived from the username) is created and `StoreJSON`'d *after* this check. Removing the check would let a duplicate registration **overwrite an existing user's wallet file**. The check must stay; only its *response* changes.
- `Users.Create` (`users.go:68`) internally guards duplicates too (`"user already exists"`); its handler error branch (`auth.go:261`) currently surfaces that verbatim in a 500, which would leak existence on a TOCTOU race between `Exists` and `Create`.

### The inherent limit (why this is a mitigation, not elimination)
On an **immediate-create, username-as-login** flow you cannot both (a) tell a
legitimate registrant "that name is taken, pick another" and (b) fully hide
whether the name exists — they are the same signal. Full elimination requires an
email-confirmation registration loop, which this system does not have. The
accepted, standard mitigation is **generic messaging + rate limiting** (already
in place), reducing the disclosure to an inference that is throttled and
non-trivial to script, with a documented residual.

## Decision (confirmed)
Genericize the taken-username response and keep the existing rate-limit
(chosen over "keep clear message" and over "fuller timing-normalization").
Generic message: `"Registration could not be completed. Please try different details."`; status **400** (uniform with the other registration validation failures, not a distinct 409).

## Design

All changes in `cmd/website/handlers/auth.go`; no new dependencies.

### 1. Genericize the taken-username response (`auth.go:202-204`)
Keep the existence check (clobbering guard); change only the response:
```go
	if Users.Exists(req.Username) {
		// WH-H3: do not disclose that the username exists. Return the same generic
		// 400 as other registration failures (not a distinct "already taken"/409),
		// so the response is not a trivially-scriptable enumeration oracle. Bulk
		// enumeration is further throttled by registerLimiter (5/10min/IP). The
		// existence check itself is retained because the wallet directory is derived
		// from the username and must not be overwritten.
		JsonError(w, "Registration could not be completed. Please try different details.", http.StatusBadRequest)
		return
	}
```

### 2. Genericize the `Users.Create` error branch (`auth.go:261`)
So a race-induced `"user already exists"` from `Create` cannot leak existence
either, return the identical generic response instead of the raw error:
```go
	if err := Users.Create(req.Username, req.Password, walletDir, address); err != nil {
		// WH-H3: Create also guards duplicates; on a TOCTOU race with the Exists
		// check above it returns "user already exists". Do not surface that — use
		// the same generic message so this path is not a fallback enumeration oracle.
		logger.GetLogger().Println("register: Users.Create failed:", err)
		JsonError(w, "Registration could not be completed. Please try different details.", http.StatusBadRequest)
		return
	}
```
(The real error is logged server-side for operators; the client sees only the generic message. `logger` is already imported in this file.)

### 3. Keep the existing rate-limit
No change to `registerLimiter.allow(ip, 5, 10*time.Minute)` — it remains the
enumeration throttle.

## Non-goals
- **Timing normalization** (the "fuller decoupling" option): the taken path returns fast while a fresh registration performs post-quantum key generation (slow), so response timing still allows inference. Padding/constant-time is explicitly out of scope for this fix (documented residual below); it was the rejected heavier option.
- Eliminating the success-vs-failure inference entirely (needs an email-confirmation loop; not available).
- Any change to `Login` (already generic), the wallet/consensus layer, or the wire format.
- Frontend code changes: the website JS will display the new generic message in place of "Username already taken" — the intended UX tradeoff. No JS change is required for correctness; it degrades gracefully.

## Error handling / determinism
- Node-local web-handler change; no consensus, tx/block, or wire-format impact.
- The taken-username and `Create`-race paths now return an identical generic `400`; the underlying reason is logged server-side only.
- The clobbering guard (`Users.Exists`) is preserved, so registration safety is unchanged.

## Documented residual (accepted)
Even after this change, a determined attacker can still *infer* existence from
(a) the success-vs-failure outcome and (b) response timing (taken → fast; fresh
→ slow PQ keygen), within the 5/10-min/IP rate budget. This is inherent to
immediate-create username registration; the mitigation (generic messaging +
rate limiting) reduces it to a throttled, non-trivial inference. Full
elimination (email-confirmation loop, timing normalization) is a larger,
separate change. This residual is stated in the `SECURITY_AUDIT.md`
reconciliation note when WH-H3 is moved to FIXED.

## Testing
CGO-free `httptest` unit test — the duplicate-username path returns at the
`Exists` check, **before** any wallet/oqs work, so no CGO is needed:
- Seed the package-level `Users` registry with an existing username (via `Users.Create(name, pass, dir, addr)`), using a `t.TempDir()`-based registry path so no real user store is touched.
- POST `/register` with that same username and a valid (8+ char) password, from a fresh client IP (so `registerLimiter` does not block).
- Assert: response status is `400` (NOT `409`), and the body contains the generic message and does **not** contain `"already taken"`, `"exists"`, or `"taken"`.
- (Optional) a second assertion that a malformed-input rejection (e.g. too-short username) returns the same `400` status, documenting that the taken case is not distinguishable by status code.

Notes for the implementer: `Register` reads the package-level `Users`, `registerLimiter`, and `WebsiteBasePath`; the test must set these up (fresh `registerLimiter` or unique IP; a temp `Users` registry). If wiring the global state proves impractical, fall back to asserting the two `JsonError` call sites use the generic message + `http.StatusBadRequest` (inspection-level), but the httptest path is preferred.

Tests run with `GOROOT=/home/wonabru/sdk/go1.24.0`. Build: `GOROOT=… go build ./...`.

## Files touched
- `cmd/website/handlers/auth.go` — genericize the two responses (`:203`, `:261`) + WH-H3 comments.
- New test: `cmd/website/handlers/register_enum_test.go`.

## Rollout / commit plan
`OB-123` commit (node-local, not `(CONSENSUS)`):
1. WH-H3: genericize the taken-username + `Create`-error responses (+ httptest enumeration test).

Not "done" until `cmd/website` builds and the test passes, and `SECURITY_AUDIT.md` reconciliation moves **WH-H3** to FIXED (with the documented residual note).

## Deferred (follow-ups)
- Timing normalization / email-confirmation registration loop to remove the residual success/timing inference.
- The remaining OPEN reconciliation items (the mediums; deferred-by-design DB-C4 / NP-C4/C5 / RPC pooling; broaden `Wipe()` adoption; `database.MainDB` shutdown-race pointer guard).

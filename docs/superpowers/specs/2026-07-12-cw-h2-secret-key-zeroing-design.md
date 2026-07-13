# CW-H2 — Zero Decrypted Secret Keys After Use

**Date:** 2026-07-12
**Branch:** `security-fixes`
**Source:** `SECURITY_AUDIT.md` reconciliation — the last-but-one OPEN HIGH crypto-hygiene finding.

## Context

The password and derived KDF key are zeroed on `Wallet.Wipe()` (CW-C4). Decrypted **secret-key** bytes are not. The audit lists eight `ds, err := w.decrypt(...)` sites in `wallet/wallet.go` (629, 661, 769, 784, 795, 847, 865, 879) where a plaintext post-quantum secret key sits in a heap slice that is never cleansed, so it lingers in memory (exposed to core dumps / swap) far longer than necessary.

### Retention analysis (the design driver)

The fix is not "cleanse at all eight sites" — memory retention splits them into two lifetimes:

- **`oqs.Signature.Init`** does `sig.secretKey = secretKey` — it **retains the slice**, no copy (`crypto/oqs/oqs.go:366`).
- **`common.PrivKey.Init`** does `pk.ByteValue = b[:]` — also **retains** (`common/types.go:369`).

So:

1. **Retained sites (2)** — `loadKeys` (`wallet/wallet.go:629`, `:661`). Here `ds` *becomes* the wallet's live secret key: `signer.Init(SigName, ds)` sets `signer.secretKey = ds`, then `ds = ds[:LengthSecretKey]` reslices (same backing array), `signer.Init` again, `w.AccountN.signer = signer`, and `secretKey.Init(ds, …)` sets `PrivKey.ByteValue = ds[:]`. Both `signer.secretKey` and `PrivKey.ByteValue` alias the same backing array and are held for the whole session so the wallet can sign. **These must NOT be zeroed after load** — they are cleansed at logout via `Wipe()`.
2. **Ephemeral sites (6)** — `ChangePassword` (`:769`, `:784`, `:795`) and `ChangePasswordInPlace` (`:847`, `:865`, `:879`). Each `ds` is a fresh allocation from `decrypt`, re-encrypted immediately (`encrypt(ds) → se`) and discarded; nothing retains it. **These are cleansed right after use.**

### Existing primitives
- `oqs.Signature.Clean()` (`crypto/oqs/oqs.go`) already does `if len(sig.secretKey) > 0 { MemCleanse(sig.secretKey) }; C.OQS_SIG_free(sig.sig); *sig = Signature{}` — it cleanses the retained secret key with `OQS_MEM_cleanse` (compiler-elision-proof) and is nil-safe on an uninitialized signer.
- `oqs.MemCleanse(v []byte)` does `C.OQS_MEM_cleanse(&v[0], len(v))` — it dereferences `&v[0]`, so it **panics on an empty slice**; callers must guard `len(v) > 0`.
- `Wipe()` (`wallet/wallet.go:123`) currently zeroes only `password` and `passwordBytes` with plain zero-loops.
- `common` does not import `crypto/oqs` (oqs's reference to common is a commented-out import), so either direction is cycle-free; we keep `PrivKey.Cleanse()` a plain zero-loop for consistency with the CW-C4 password wipe and to avoid adding a `common → oqs` dependency.

## Design

### Component 1 — cleanse the 6 ephemeral `ds` after use

In `ChangePassword` and `ChangePasswordInPlace`, cleanse each ephemeral `ds` on every exit path (including the `encrypt` error-returns between decrypt and the natural end).

- **Loop sites** (`:769` in `ChangePassword`, `:847` in `ChangePasswordInPlace`, each inside `for k, v := range w.Accounts`): wrap the loop body in an inline closure returning `error`, with `defer` cleanse inside, so the cleanse fires **per iteration** (not accumulated to function end). Shape:
  ```go
  for k, v := range w.Accounts {
      if err := func() error {
          ds, err := w.decrypt(v.EncryptedSecretKey)
          if err != nil {
              logger.GetLogger().Println(err)
              return err
          }
          defer func() { if len(ds) > 0 { oqs.MemCleanse(ds) } }() // CW-H2
          se, err := w2.encrypt(ds) // (ChangePasswordInPlace: the existing passwordBytes-swap around encrypt is preserved verbatim)
          if err != nil {
              logger.GetLogger().Println(err)
              return err
          }
          copy(w2.Accounts[k].EncryptedSecretKey, se)
          return nil
      }(); err != nil {
          return err
      }
  }
  ```
  (The closure preserves each function's existing re-encrypt mechanism exactly — `ChangePassword` re-encrypts via `w2.encrypt`; `ChangePasswordInPlace` re-encrypts via the `w.passwordBytes = newPasswordBytes … w.passwordBytes = oldPasswordBytes` swap around `w.encrypt` — only the decrypt/cleanse and the closure wrapper are added.)

- **Sequential Account1/Account2 sites** (`:784`, `:795`, `:865`, `:879`): add, immediately after the successful decrypt, a function-scoped guard:
  ```go
  ds, err := w.decrypt(w.Account1.EncryptedSecretKey)
  if err != nil {
      return fmt.Errorf("failed to decrypt Account1: %v", err)
  }
  defer func() { if len(ds) > 0 { oqs.MemCleanse(ds) } }() // CW-H2
  ```
  Two `defer`s per function (Account1 + Account2) accumulate to function return, then both are cleansed — a negligible, bounded lifetime, so no closure is needed here.

`oqs` is already imported in `wallet/wallet.go`. `ds` at these sites is distinct from the signer's retained key (a fresh `decrypt` allocation), so cleansing is safe and does not corrupt the live wallet.

### Component 2 — cleanse the retained secret key at `Wipe()`

Add a `PrivKey.Cleanse()` helper in `common/types.go` (plain zero-loop, mirroring the CW-C4 password wipe):
```go
// Cleanse zeroes the in-memory secret-key bytes. Call at logout/wipe (CW-H2).
func (pk *PrivKey) Cleanse() {
	for i := range pk.ByteValue {
		pk.ByteValue[i] = 0
	}
	pk.ByteValue = nil
}
```

Extend `Wallet.Wipe()` (`wallet/wallet.go`) to cleanse the live secret keys in addition to the existing password zeroing:
```go
func (w *Wallet) Wipe() {
	for i := range w.password {
		w.password[i] = 0
	}
	for i := range w.passwordBytes {
		w.passwordBytes[i] = 0
	}
	w.password = nil
	w.passwordBytes = nil
	// CW-H2: cleanse the live post-quantum secret keys. signer.Clean() runs
	// OQS_MEM_cleanse over the retained secret-key bytes (which alias
	// secretKey.ByteValue) and frees the C handle; it is nil-safe on an
	// account that never initialized (e.g. paused encryption).
	w.Account1.signer.Clean()
	w.Account2.signer.Clean()
	w.Account1.secretKey.Cleanse()
	w.Account2.secretKey.Cleanse()
}
```
`signer.Clean()` provides the strong `OQS_MEM_cleanse`; `secretKey.Cleanse()` is defense-in-depth for the `PrivKey.ByteValue` slice header (and covers any case where the lengths diverged). After `Wipe()` the wallet is intentionally unusable (logout/session-end), matching the CW-C4 model.

## Non-goals
- Broadening `Wipe()` **adoption** to the Qt/webui/CLI exit paths (only the website logout, `cmd/website/handlers/session.go:96`, calls it today). This batch makes `Wipe()` *correct*; wiring it into the other entry points is a follow-up, consistent with how CW-C4 was scoped.
- Reducing the retained key's in-memory lifetime below "the session" (impossible — the wallet must hold the secret key to sign).
- Changing the on-disk encrypted format, the signing path, or any consensus/wire surface.

## Error handling / determinism
- Node-local defensive hygiene; no consensus, tx/block validity, or wire-format impact.
- `MemCleanse` empty-slice panic is avoided by the `len(ds) > 0` guard at every ephemeral site; `signer.Clean()` is internally guarded.
- The ephemeral cleanse runs on all paths (success and the `encrypt` error-returns) via `defer`.

## Testing
- **`PrivKey.Cleanse()` (pure, `common`):** given a `PrivKey{ByteValue: []byte{1,2,3}}`, after `Cleanse()` the (captured) backing bytes are all zero and `ByteValue == nil`. Runs without CGO.
- **`Wipe()` cleanses secret keys (CGO/oqs-gated):** build a real wallet (`NewWallet`/load), capture a reference to `w.Account1.secretKey.ByteValue`, call `Wipe()`, assert the captured bytes are all zero (and `passwordBytes == nil`, preserving the CW-C4 assertion). `t.Skip` if oqs/CGO is unavailable in the sandbox.
- **`ChangePasswordInPlace` round-trip regression (CGO-gated):** after a password change, the wallet's keys are still usable (sign/verify or reload with the new password succeeds) — proving the ephemeral cleanse did not corrupt a retained key. `t.Skip` if oqs unavailable.

Tests run with `GOROOT=/home/wonabru/sdk/go1.24.0`. Build: `GOROOT=… go build ./...`.

## Files touched
- `common/types.go` — add `PrivKey.Cleanse()`.
- `wallet/wallet.go` — cleanse the 6 ephemeral `ds` sites; extend `Wipe()` to cleanse the retained keys.
- New tests: `common/privkey_cleanse_test.go`, `wallet/wipe_secretkey_test.go` (CGO-gated).

## Rollout / commit plan
`OB-121` commits (node-local, not `(CONSENSUS)`):
1. `common`: add `PrivKey.Cleanse()` (+ pure test).
2. `wallet`: extend `Wipe()` to cleanse retained keys (+ CGO-gated Wipe test).
3. `wallet`: cleanse the 6 ephemeral `ds` sites (+ CGO-gated round-trip regression).

(Tasks 1→2 ordered so `Wipe()` can call `Cleanse()`; Task 3 is independent of 1–2.)

Not "done" until `common` and `wallet` build and the pure test passes (CGO tests skip cleanly if unavailable), and `SECURITY_AUDIT.md` reconciliation moves CW-H2 to FIXED.

## Deferred (follow-ups)
- Broaden `Wipe()` adoption to all wallet entry points (Qt/webui/CLI) so secret keys are cleansed on every exit, not just website logout.
- Remaining OPEN reconciliation items (WH-H3, the mediums; deferred-by-design DB-C4 / NP-C4/C5 / RPC pooling; the `database.MainDB` shutdown-race pointer guard).

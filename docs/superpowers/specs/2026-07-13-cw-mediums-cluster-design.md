# Wallet Mediums Cluster — CW-M3, CW-M2

**Date:** 2026-07-13
**Branch:** `security-fixes`
**Source:** `SECURITY_AUDIT.md` reconciliation — the last two OPEN MEDIUM findings (cluster C of the mediums sweep). Closing these takes open mediums to zero.

## Context

Two wallet mediums, both in `wallet/wallet.go`, both node-local (no consensus/wire/format impact):
- **CW-M3** — a concurrency-correctness fix in `ChangePasswordInPlace`.
- **CW-M2** — an honesty fix for the mnemonic-backup feature's misleading error.

### Ground truth (from exploration)
- **CW-M3:** `ChangePasswordInPlace` (`wallet.go:888`) re-encrypts each secret under the new password by **toggling the shared field in place**: `w.passwordBytes = newPasswordBytes` → `w.encrypt(ds)` (which reads `w.passwordBytes` to build the AES key) → `w.passwordBytes = oldPasswordBytes`, repeated per account. `globalMutex` guards the two password-change functions against each other, but NOT against other goroutines that read `w.passwordBytes`. `encrypt`/`decrypt` are **internal-only** helpers (no external callers); `Sign` does **not** read `passwordBytes` (the signer holds the key). So the concurrent-reader risk is another goroutine calling `decrypt`/`encrypt` (via `StoreJSON`/`loadKeys`) or `CheckPassword` on the same wallet while the toggle flips `passwordBytes` — it could read `newPasswordBytes` when it should read `old`.
- **CW-M2:** `GetMnemonicWords` (`wallet.go:449`) rejects any secret `> 64` bytes with `"secret must be less than 64 bytes"`. A Falcon-512 secret key is ~1281 bytes, so for real post-quantum keys this **always errors** — the BIP39 mnemonic feature (wired to `/api/wallet/mnemonic` in website/webui/gui) is non-functional for actual keys, and the error message is misleading. `PrivKey.GetLength()` returns `len(ByteValue)`; `GetBytes()` returns `ByteValue`.

## Decisions (confirmed)
- **CW-M3:** eliminate the toggle. Add an internal `encryptWithKey(key, v)` and re-encrypt with the new key **without ever mutating `w.passwordBytes` mid-loop** — only the single final swap remains (matching the safer `ChangePassword`). Chosen over a full RLock-discipline overhaul (invasive, reentrancy risk).
- **CW-M2:** keep the 64-byte cap; make the behavior honest. Replace the misleading `> 64` error with a clear message directing the user to the encrypted wallet-file backup. Chosen over building a full large-key encoding and over won't-fix.

## Design

### CW-M3 — eliminate the password-byte toggle
Extract `encrypt`'s body into an explicit-key variant and have `encrypt` delegate:
```go
// encryptWithKey encrypts v under the given AES key without reading or mutating
// w.passwordBytes. CW-M3: lets ChangePasswordInPlace re-encrypt under the new
// key without toggling the shared field (which raced concurrent readers).
func (w *Wallet) encryptWithKey(key, v []byte) ([]byte, error) {
	cb, err := aes.NewCipher(key)
	if err != nil {
		logger.GetLogger().Println("Can not create AES function")
		return []byte{}, err
	}
	gcm, err := cipher.NewGCM(cb)
	if err != nil {
		logger.GetLogger().Println("Can not create GCM function")
		return []byte{}, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return []byte{}, err
	}
	return gcm.Seal(nonce, nonce, v, nil), nil
}

func (w *Wallet) encrypt(v []byte) ([]byte, error) {
	return w.encryptWithKey(w.passwordBytes, v)
}
```
Rewrite `ChangePasswordInPlace` so that:
- `decrypt` still reads `w.passwordBytes` — which stays the **old** key throughout (it is never toggled now), so decryption of old blobs is correct.
- each re-encryption uses `w.encryptWithKey(newPasswordBytes, ds)` (no `w.passwordBytes = new … = old` toggle, and no error-path restoration of `passwordBytes`).
- the local `oldPasswordBytes` is removed (it was only used for the toggle/restore).
- the single final `w.passwordBytes = newPasswordBytes` (already present, under the held `globalMutex.Lock()`) is the only write to `passwordBytes`.

Each of the three re-encrypt sites (the `Accounts` loop, Account1, Account2) collapses from:
```go
	w.passwordBytes = newPasswordBytes
	se, err := w.encrypt(ds)
	if err != nil {
		w.passwordBytes = oldPasswordBytes
		return … err
	}
	w.passwordBytes = oldPasswordBytes
	<store se>
```
to:
```go
	se, err := w.encryptWithKey(newPasswordBytes, ds) // CW-M3: no toggle
	if err != nil {
		return … err
	}
	<store se>
```
(The CW-H2 `defer oqs.MemCleanse(ds)` guards stay unchanged.)

**Residual (accepted, documented):** the final `w.passwordBytes = newPasswordBytes` is still an unsynchronized write versus the lock-free `passwordBytes` readers (`decrypt`/`encrypt`/`CheckPassword`). This single-assignment race is **pre-existing** and shared with `SetPassword`/`Wipe`/`LoadJSON`; it is NOT the per-operation toggle the finding cites. Fully closing it (RLock on every reader + Lock on every writer, avoiding reentrancy) is the deferred "full lock discipline" option.

### CW-M2 — honest mnemonic error for oversized keys
In `GetMnemonicWords`, replace:
```go
	if secretLength > 64 {
		return "", fmt.Errorf("secret must be less than 64 bytes")
	}
```
with a clear, directive error:
```go
	if secretLength > 64 {
		// CW-M2: BIP39-style mnemonics cannot represent a post-quantum secret key
		// (e.g. Falcon-512 is ~1281 bytes) — the 64-byte ceiling is intentional.
		// Direct the user to the real backup mechanism instead of a misleading
		// "less than 64 bytes" message.
		return "", fmt.Errorf("mnemonic backup is unavailable for keys larger than 64 bytes (post-quantum secret keys); use the encrypted wallet-file backup instead")
	}
```
The `< 64` padding path and the round-trip validation below it are unchanged (a ≤64-byte secret can still be mnemonic-backed).

## Non-goals
- A full wallet lock-discipline overhaul (RLock on all `passwordBytes` readers) — deferred; CW-M3's residual single-swap race is documented.
- A large-key/alternative mnemonic backup encoding for post-quantum keys — the encrypted wallet-file backup is the supported mechanism (CW-M2 keeps the 64-byte ceiling by decision).
- Any consensus/wire/format change.

## Error handling / determinism
- Both node-local; no consensus/tx/block/wire impact. Commits are `OB-126` (not `(CONSENSUS)`).
- CW-M3: `ChangePasswordInPlace`'s observable result is unchanged (secrets re-encrypted under the new password, `passwordBytes` ends at `newPasswordBytes`); only the intermediate toggling is removed.
- CW-M2: a key ≤64 bytes still produces a mnemonic; a key >64 bytes now gets a clear, actionable error instead of a misleading one.

## Testing
CGO-free unit tests (both use pure AES-GCM / a length check, no oqs):
- **CW-M3:** `encryptWithKey` round-trip — `w.encryptWithKey(K, v)` then set `w.passwordBytes = K` and `w.decrypt(se)` returns `v`; and encrypting with key K1 does NOT decrypt under a different key K2 (GCM auth fails). Confirms the explicit-key path is correct and independent of `w.passwordBytes`. (`ChangePasswordInPlace`'s full round-trip needs a real wallet/CGO; the toggle removal is additionally verified by inspection + a grep that `w.passwordBytes =` appears only once in the function.)
- **CW-M2:** construct `w := &Wallet{}` with `w.Account1.secretKey = common.PrivKey{ByteValue: make([]byte, 100)}`; `w.GetMnemonicWords(true)` returns an error whose message contains "wallet-file" (or "post-quantum") and does NOT contain "less than 64 bytes"; a ≤64-byte secret still returns a non-empty mnemonic with no error.

Tests run with `GOROOT=/home/wonabru/sdk/go1.24.0`; build `GOROOT=… go build ./...`.

## Files touched
- `wallet/wallet.go` — CW-M3 (`encryptWithKey` + `encrypt` delegation + `ChangePasswordInPlace` rewrite); CW-M2 (honest `GetMnemonicWords` error).
- New tests: `wallet/encrypt_key_test.go` (CW-M3), `wallet/mnemonic_test.go` (CW-M2).

## Rollout / commit plan
`OB-126` commits (node-local, not `(CONSENSUS)`):
1. CW-M3 — `encryptWithKey` + eliminate the `ChangePasswordInPlace` toggle (+ round-trip test).
2. CW-M2 — honest oversized-key mnemonic error (+ test).

Not "done" until `wallet` builds and the new tests pass, and `SECURITY_AUDIT.md` reconciliation moves CW-M2 and CW-M3 to FIXED — **taking open mediums to 0** (CW-M3 with its documented single-swap residual; CW-M2 as "bounded + honest, 64-byte ceiling by design").

## Deferred (follow-ups)
- Full wallet lock discipline (RLock on all `passwordBytes` readers) to close CW-M3's residual.
- A post-quantum-capable mnemonic/recovery encoding, if ever desired.
- Remaining deferred-by-design partials (DB-C4, NP-C4/C5, etc.) — the only non-medium OPEN/PARTIAL work left.

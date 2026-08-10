# CW-H2 Secret-Key Zeroing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Zero decrypted post-quantum secret keys in memory — the 6 ephemeral password-change `ds` slices right after use, and the 2 retained live keys at `Wipe()` (logout).

**Architecture:** Three small tasks. Task 1 adds a `PrivKey.Cleanse()` helper in `common`. Task 2 extends `Wallet.Wipe()` to cleanse the retained live keys (calls `Cleanse()` + `oqs.Signature.Clean()`). Task 3 cleanses the 6 ephemeral `ds` sites in the two password-change functions. Node-local; no consensus/wire/format change.

**Tech Stack:** Go 1.23.6 (build with the `sdk/go1.24.0` toolchain), CGO (RocksDB + liboqs), `crypto/oqs` bindings.

## Global Constraints
- Build/test with `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go`. This repo uses CGO; export before building:
  ```
  export GOROOT=/home/wonabru/sdk/go1.24.0
  export PATH=$GOROOT/bin:$PATH
  export CGO_CFLAGS="-isystem $HOME/local/include"
  export CGO_LDFLAGS="-L$HOME/local/lib -L/usr/local/intelpython3/lib -lrocksdb -lstdc++ -lm -lz -lsnappy -llz4 -lzstd -lbz2 -lpthread -ldl"
  ```
- Branch `security-fixes`. Commit `OB-121` (NOT `(CONSENSUS)` — node-local hygiene). End every commit message with a blank line then `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- `oqs.MemCleanse(v []byte)` dereferences `&v[0]` and PANICS on an empty slice — every call site must guard `len(v) > 0`.
- `oqs.Signature.Clean()` already `MemCleanse`s the retained secret key and frees the C handle; it is nil-safe on a zero-value / uninitialized signer.
- `oqs` is already imported in `wallet/wallet.go` as `"github.com/qwid-org/qwid-node/crypto/oqs"`. Do NOT add a `common → oqs` import (`PrivKey.Cleanse()` uses a plain zero-loop).
- Field types: `Account.secretKey` is `common.PrivKey` (value); `Account.signer` is `oqs.Signature` (value); both are addressable via `w.Account1.…`. `Wallet.encrypt`/`decrypt` are pure-Go AES-GCM (no CGO).

---

## Task 1: `common.PrivKey.Cleanse()`

**Files:**
- Modify: `common/types.go` (add method near `PrivKey.Init`, ~line 369)
- Test: `common/privkey_cleanse_test.go` (new)

**Interfaces:**
- Produces: `func (pk *PrivKey) Cleanse()` — zeroes `pk.ByteValue` in place, then sets it to `nil`.

- [ ] **Step 1: Write the failing test** — create `common/privkey_cleanse_test.go`:
```go
package common

import "testing"

func TestPrivKeyCleanse(t *testing.T) {
	pk := &PrivKey{ByteValue: []byte{1, 2, 3, 4}}
	backing := pk.ByteValue // capture the backing array before Cleanse nils the field
	pk.Cleanse()
	for i, b := range backing {
		if b != 0 {
			t.Fatalf("backing byte %d = %d, want 0", i, b)
		}
	}
	if pk.ByteValue != nil {
		t.Fatal("ByteValue should be nil after Cleanse")
	}
}

func TestPrivKeyCleanseEmptyIsSafe(t *testing.T) {
	pk := &PrivKey{} // nil ByteValue must not panic
	pk.Cleanse()
	if pk.ByteValue != nil {
		t.Fatal("ByteValue should remain nil")
	}
}
```

- [ ] **Step 2: Run to verify it fails** — `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./common/ -run TestPrivKeyCleanse -v` → FAIL to compile (`Cleanse` undefined).

- [ ] **Step 3: Add the method** — in `common/types.go`, immediately after the `PrivKey.Init` method (which ends around line 380):
```go
// Cleanse zeroes the in-memory secret-key bytes and drops the reference. Call at
// logout/wipe so a decrypted post-quantum secret key does not linger in memory
// (CW-H2). Plain zero-loop, mirroring the CW-C4 password wipe.
func (pk *PrivKey) Cleanse() {
	for i := range pk.ByteValue {
		pk.ByteValue[i] = 0
	}
	pk.ByteValue = nil
}
```

- [ ] **Step 4: Run + build** — `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./common/ -run TestPrivKeyCleanse -v && GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go build ./...` → test PASS, build exit 0.

- [ ] **Step 5: Commit**
```bash
git add common/types.go common/privkey_cleanse_test.go
git commit -m "$(printf 'OB-121 CW-H2: add PrivKey.Cleanse() to zero secret-key bytes\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Task 2: extend `Wallet.Wipe()` to cleanse retained secret keys

**Files:**
- Modify: `wallet/wallet.go` (`Wipe`, ~line 123-131)
- Test: `wallet/wipe_secretkey_test.go` (new)

**Interfaces:**
- Consumes: `PrivKey.Cleanse()` (Task 1); existing `oqs.Signature.Clean()`.
- Produces: `Wipe()` now also cleanses `w.Account1`/`w.Account2` signer + secret-key bytes.

- [ ] **Step 1: Write the failing test** — create `wallet/wipe_secretkey_test.go`:
```go
package wallet

import "testing"

// TestWipeCleansesSecretKeys verifies Wipe() zeroes the retained secret-key
// bytes (CW-H2) in addition to the password (CW-C4). Zero-value signers are
// used; Wipe()'s signer.Clean() is nil-safe on them (only OQS_SIG_free(nil)),
// so no real key material or algorithm init is needed.
func TestWipeCleansesSecretKeys(t *testing.T) {
	w := &Wallet{}
	w.password = []byte{4, 5}
	w.passwordBytes = []byte{1, 2, 3}
	w.Account1.secretKey.ByteValue = []byte{7, 7, 7, 7}
	w.Account2.secretKey.ByteValue = []byte{9, 9}
	bv1 := w.Account1.secretKey.ByteValue // capture backing arrays
	bv2 := w.Account2.secretKey.ByteValue

	w.Wipe()

	for i, b := range bv1 {
		if b != 0 {
			t.Fatalf("Account1 secret byte %d = %d, want 0", i, b)
		}
	}
	for i, b := range bv2 {
		if b != 0 {
			t.Fatalf("Account2 secret byte %d = %d, want 0", i, b)
		}
	}
	if w.passwordBytes != nil {
		t.Fatal("passwordBytes must be nil after Wipe (CW-C4 preserved)")
	}
}
```

- [ ] **Step 2: Run to verify it fails** — `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./wallet/ -run TestWipeCleansesSecretKeys -v` → FAIL (Account1/Account2 secret bytes are NOT zeroed by the current `Wipe`).

- [ ] **Step 3: Extend `Wipe()`** — in `wallet/wallet.go`, replace the current `Wipe` body:
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
}
```
with:
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
	// secretKey.ByteValue) and frees the C handle; it is nil-safe on an account
	// that never initialized (e.g. paused encryption). Cleanse() zeroes the
	// PrivKey.ByteValue slice as defense-in-depth.
	w.Account1.signer.Clean()
	w.Account2.signer.Clean()
	w.Account1.secretKey.Cleanse()
	w.Account2.secretKey.Cleanse()
}
```

- [ ] **Step 4: Run + build** — `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./wallet/ -run TestWipeCleansesSecretKeys -v && GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go build ./...` → test PASS, build exit 0.

- [ ] **Step 5: Commit**
```bash
git add wallet/wallet.go wallet/wipe_secretkey_test.go
git commit -m "$(printf 'OB-121 CW-H2: Wipe() cleanses retained secret keys (signer.Clean + PrivKey.Cleanse)\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Task 3: cleanse the 6 ephemeral `ds` in the password-change functions

**Files:**
- Modify: `wallet/wallet.go` (`ChangePassword` ~lines 768-806; `ChangePasswordInPlace` ~lines 843-895)
- Test: `wallet/encrypt_noretain_test.go` (new)

**Interfaces:**
- Consumes: existing `Wallet.encrypt`/`decrypt` (pure AES-GCM), `oqs.MemCleanse`.

This task adds an ephemeral-key cleanse on every exit path. `ds` at these sites is a fresh `decrypt` allocation, re-encrypted then discarded (never retained), so cleansing is safe. The test proves the enabling invariant: `encrypt` captures the plaintext by value, so zeroing `ds` afterward cannot corrupt the ciphertext.

- [ ] **Step 1: Write the failing test** — create `wallet/encrypt_noretain_test.go`:
```go
package wallet

import (
	"bytes"
	"testing"
)

// TestEncryptDoesNotRetainPlaintext proves that Wallet.encrypt captures its
// input by value: cleansing the plaintext slice after encrypt returns must not
// affect the ciphertext, which must still decrypt to the original. This is the
// invariant that makes the CW-H2 ephemeral `ds` cleanse safe. Pure AES-GCM, no CGO.
func TestEncryptDoesNotRetainPlaintext(t *testing.T) {
	w := &Wallet{passwordBytes: make([]byte, 32)} // AES-256 key (zeros are fine for a round-trip test)
	orig := []byte("super-secret-key-material-1234567")
	ds := append([]byte(nil), orig...)

	se, err := w.encrypt(ds)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	// Cleanse ds exactly as the CW-H2 fix does after re-encrypting.
	for i := range ds {
		ds[i] = 0
	}
	dec, err := w.decrypt(se)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(dec, orig) {
		t.Fatalf("decrypt after cleansing ds = %q, want %q", dec, orig)
	}
}
```

- [ ] **Step 2: Run to verify it passes already** — `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./wallet/ -run TestEncryptDoesNotRetainPlaintext -v` → PASS. (This test documents/locks the invariant the fix relies on; it is green before the edit because `encrypt` already copies. If it FAILS, STOP and report — the ephemeral cleanse would be unsafe.)

- [ ] **Step 3: Cleanse the two loop sites (closure-wrapped for per-iteration cleanse)**

In `ChangePassword`, replace the `for k, v := range w.Accounts { … }` block (currently):
```go
	for k, v := range w.Accounts {
		ds, err := w.decrypt(v.EncryptedSecretKey)
		if err != nil {
			logger.GetLogger().Println(err)
			return err
		}
		se, err := w2.encrypt(ds)
		if err != nil {
			logger.GetLogger().Println(err)
			return err
		}
		copy(w2.Accounts[k].EncryptedSecretKey, se)
	}
```
with:
```go
	for k, v := range w.Accounts {
		if err := func() error {
			ds, err := w.decrypt(v.EncryptedSecretKey)
			if err != nil {
				logger.GetLogger().Println(err)
				return err
			}
			defer func() { // CW-H2: cleanse the ephemeral decrypted key
				if len(ds) > 0 {
					oqs.MemCleanse(ds)
				}
			}()
			se, err := w2.encrypt(ds)
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

In `ChangePasswordInPlace`, replace the `for k, v := range w.Accounts { … }` block (currently):
```go
	for k, v := range w.Accounts {
		ds, err := w.decrypt(v.EncryptedSecretKey)
		if err != nil {
			logger.GetLogger().Println(err)
			return err
		}
		w.passwordBytes = newPasswordBytes
		se, err := w.encrypt(ds)
		if err != nil {
			w.passwordBytes = oldPasswordBytes
			logger.GetLogger().Println(err)
			return err
		}
		w.passwordBytes = oldPasswordBytes
		copy(w.Accounts[k].EncryptedSecretKey, se)
	}
```
with:
```go
	for k, v := range w.Accounts {
		if err := func() error {
			ds, err := w.decrypt(v.EncryptedSecretKey)
			if err != nil {
				logger.GetLogger().Println(err)
				return err
			}
			defer func() { // CW-H2: cleanse the ephemeral decrypted key
				if len(ds) > 0 {
					oqs.MemCleanse(ds)
				}
			}()
			w.passwordBytes = newPasswordBytes
			se, err := w.encrypt(ds)
			if err != nil {
				w.passwordBytes = oldPasswordBytes
				logger.GetLogger().Println(err)
				return err
			}
			w.passwordBytes = oldPasswordBytes
			copy(w.Accounts[k].EncryptedSecretKey, se)
			return nil
		}(); err != nil {
			return err
		}
	}
```

- [ ] **Step 4: Cleanse the four sequential Account1/Account2 sites**

In BOTH `ChangePassword` and `ChangePasswordInPlace`, for each of the four `if len(…Account1/Account2.EncryptedSecretKey) > 0 {` blocks, insert the cleanse `defer` immediately AFTER the decrypt's error check (before the `encrypt`). Example for `ChangePassword`'s Account1 block — change:
```go
	if len(w2.Account1.EncryptedSecretKey) > 0 {
		ds, err := w.decrypt(w.Account1.EncryptedSecretKey)
		if err != nil {
			return fmt.Errorf("failed to decrypt Account1: %v", err)
		}
		se, err := w2.encrypt(ds)
```
to:
```go
	if len(w2.Account1.EncryptedSecretKey) > 0 {
		ds, err := w.decrypt(w.Account1.EncryptedSecretKey)
		if err != nil {
			return fmt.Errorf("failed to decrypt Account1: %v", err)
		}
		defer func() { // CW-H2: cleanse the ephemeral decrypted key
			if len(ds) > 0 {
				oqs.MemCleanse(ds)
			}
		}()
		se, err := w2.encrypt(ds)
```
Apply the same insertion (the `defer func() { if len(ds) > 0 { oqs.MemCleanse(ds) } }()` line, right after the decrypt error check) to:
- `ChangePassword` Account2 block (`w2.Account2`, decrypt of `w.Account2.EncryptedSecretKey`),
- `ChangePasswordInPlace` Account1 block (decrypt of `w.Account1.EncryptedSecretKey`),
- `ChangePasswordInPlace` Account2 block (decrypt of `w.Account2.EncryptedSecretKey`).

Each block declares its own `ds`, so each deferred closure captures that block's slice; the defers run at function return (2 per function — a bounded, negligible lifetime), cleansing every ephemeral key on both the success and `encrypt`-error paths.

- [ ] **Step 5: Run + build + vet** — 
```
GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./wallet/ -run 'TestEncryptDoesNotRetainPlaintext|TestWipeCleansesSecretKeys' -v
GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go vet ./wallet/
GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go build ./...
```
→ tests PASS, vet clean, build exit 0.

- [ ] **Step 6: Commit**
```bash
git add wallet/wallet.go wallet/encrypt_noretain_test.go
git commit -m "$(printf 'OB-121 CW-H2: cleanse ephemeral decrypted keys in ChangePassword/ChangePasswordInPlace\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Final verification
- [ ] `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go build ./...` → exit 0.
- [ ] `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./common/ ./wallet/` → PASS (new CW-H2 tests green; pre-existing wallet tests unaffected).
- [ ] Update `SECURITY_AUDIT.md` reconciliation: move **CW-H2** from OPEN to FIXED; High FIXED +1, OPEN −1. (Controller handles this doc edit after the final review, mirroring prior clusters.)

## Deferred (not in this plan)
- Broaden `Wipe()` adoption to all wallet entry points (Qt/webui/CLI) so secret keys are cleansed on every exit, not just website logout.
- Remaining OPEN reconciliation items (WH-H3, the mediums; deferred-by-design DB-C4 / NP-C4/C5 / RPC pooling; the `database.MainDB` shutdown-race pointer guard).

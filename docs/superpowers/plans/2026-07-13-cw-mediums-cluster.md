# Wallet Mediums Cluster Implementation Plan (CW-M3, CW-M2)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the last two wallet mediums — eliminate the `passwordBytes` toggling race in `ChangePasswordInPlace` (CW-M3), and give an honest error when a secret key is too large for the mnemonic backup (CW-M2). Closing these takes open mediums to zero.

**Architecture:** Two independent, node-local fixes in `wallet/wallet.go`. CW-M3 adds an explicit-key `encryptWithKey` so re-encryption no longer flips the shared `w.passwordBytes`. CW-M2 replaces one misleading error message. No consensus/wire/format change.

**Tech Stack:** Go 1.23.6 (build with the `sdk/go1.24.0` toolchain), CGO (RocksDB + liboqs). Tests are pure Go (AES-GCM / a length check), no CGO needed. Test files use `package wallet`.

## Global Constraints
- Build/test with `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go`. This repo uses CGO; export before building:
  ```
  export GOROOT=/home/wonabru/sdk/go1.24.0
  export PATH=$GOROOT/bin:$PATH
  export CGO_CFLAGS="-isystem $HOME/local/include"
  export CGO_LDFLAGS="-L$HOME/local/lib -L/usr/local/intelpython3/lib -lrocksdb -lstdc++ -lm -lz -lsnappy -llz4 -lzstd -lbz2 -lpthread -ldl"
  ```
- Branch `security-fixes`. Commit `OB-126` (NOT `(CONSENSUS)` — node-local wallet). End every commit message with a blank line then `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- `aes`, `cipher`, `io`, `crypto/rand` (as `rand`), `logger`, `oqs`, `common` are already imported in `wallet.go`. Do not remove imports still in use.
- Known pre-existing `./wallet/` state: the store/load roundtrip tests were repaired earlier (OB-122) and pass; do not introduce new failures.

---

## Task 1: CW-M3 — eliminate the password-byte toggle in ChangePasswordInPlace

**Files:**
- Modify: `wallet/wallet.go` (add `encryptWithKey`; make `encrypt` delegate; rewrite the three re-encrypt sites in `ChangePasswordInPlace`; remove `oldPasswordBytes`)
- Test: `wallet/encrypt_key_test.go` (new)

**Interfaces:**
- Produces: `func (w *Wallet) encryptWithKey(key, v []byte) ([]byte, error)`.
- Consumes (existing): `encrypt`/`decrypt`, `ChangePasswordInPlace`, `newPasswordBytes` (local, `argon2Key(newPassword, newSalt)`).

- [ ] **Step 1: Write the failing tests** — create `wallet/encrypt_key_test.go`:
```go
package wallet

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// TestEncryptWithKeyRoundTrip proves encryptWithKey encrypts under the GIVEN key
// (independent of w.passwordBytes), and the ciphertext decrypts back with that key.
func TestEncryptWithKeyRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	w := &Wallet{}
	plain := []byte("secret-key-material-xyz")

	se, err := w.encryptWithKey(key, plain)
	if err != nil {
		t.Fatalf("encryptWithKey: %v", err)
	}
	// decrypt reads w.passwordBytes; set it to the same key and round-trip.
	w.passwordBytes = key
	dec, err := w.decrypt(se)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(dec, plain) {
		t.Fatalf("round-trip mismatch: %q != %q", dec, plain)
	}
}

// TestEncryptWithKeyWrongKeyFails proves ciphertext from key K1 does not decrypt
// under a different key (GCM auth fails; the legacy fallback also errors with no Iv).
func TestEncryptWithKeyWrongKeyFails(t *testing.T) {
	w := &Wallet{}
	k1 := make([]byte, 32)
	k2 := make([]byte, 32)
	k2[0] = 0xff

	se, err := w.encryptWithKey(k1, []byte("data-to-protect"))
	if err != nil {
		t.Fatal(err)
	}
	w.passwordBytes = k2 // wrong key; w.Iv is nil, so the legacy fallback errors too
	if _, err := w.decrypt(se); err == nil {
		t.Fatal("decrypt with the wrong key must fail")
	}
}
```

- [ ] **Step 2: Run to verify it fails** — `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./wallet/ -run 'TestEncryptWithKey' -v` → FAIL to compile (`encryptWithKey` undefined).

- [ ] **Step 3: Add `encryptWithKey` and make `encrypt` delegate** — in `wallet/wallet.go`, replace the existing `encrypt`:
```go
func (w *Wallet) encrypt(v []byte) ([]byte, error) {
	cb, err := aes.NewCipher(w.passwordBytes)
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
	// Seal appends the ciphertext (including the auth tag) to nonce, so the
	// returned slice is nonce || ciphertext+tag.
	return gcm.Seal(nonce, nonce, v, nil), nil
}
```
with the explicit-key helper plus a thin `encrypt` wrapper:
```go
// encryptWithKey encrypts v under the given AES key without reading or mutating
// w.passwordBytes. CW-M3: lets ChangePasswordInPlace re-encrypt under the new key
// without toggling the shared field (which raced concurrent passwordBytes readers).
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
	// Seal appends the ciphertext (including the auth tag) to nonce, so the
	// returned slice is nonce || ciphertext+tag.
	return gcm.Seal(nonce, nonce, v, nil), nil
}

func (w *Wallet) encrypt(v []byte) ([]byte, error) {
	return w.encryptWithKey(w.passwordBytes, v)
}
```

- [ ] **Step 4: Remove `oldPasswordBytes` and the toggle in `ChangePasswordInPlace`** — in `ChangePasswordInPlace`:

  (a) Delete the line `oldPasswordBytes := w.passwordBytes` (it is only used by the toggle/restore being removed; `newPasswordBytes := argon2Key(newPassword, newSalt)` stays).

  (b) In the `for k, v := range w.Accounts` closure, replace:
```go
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
```
with:
```go
			se, err := w.encryptWithKey(newPasswordBytes, ds) // CW-M3: no toggle
			if err != nil {
				logger.GetLogger().Println(err)
				return err
			}
			copy(w.Accounts[k].EncryptedSecretKey, se)
			return nil
```

  (c) In the Account1 block, replace:
```go
		w.passwordBytes = newPasswordBytes
		se, err := w.encrypt(ds)
		if err != nil {
			w.passwordBytes = oldPasswordBytes
			return fmt.Errorf("failed to encrypt Account1: %v", err)
		}
		w.passwordBytes = oldPasswordBytes
		w.Account1.EncryptedSecretKey = se
```
with:
```go
		se, err := w.encryptWithKey(newPasswordBytes, ds) // CW-M3: no toggle
		if err != nil {
			return fmt.Errorf("failed to encrypt Account1: %v", err)
		}
		w.Account1.EncryptedSecretKey = se
```

  (d) In the Account2 block, replace:
```go
		w.passwordBytes = newPasswordBytes
		se, err := w.encrypt(ds)
		if err != nil {
			w.passwordBytes = oldPasswordBytes
			return fmt.Errorf("failed to encrypt Account2: %v", err)
		}
		w.passwordBytes = oldPasswordBytes
		w.Account2.EncryptedSecretKey = se
```
with:
```go
		se, err := w.encryptWithKey(newPasswordBytes, ds) // CW-M3: no toggle
		if err != nil {
			return fmt.Errorf("failed to encrypt Account2: %v", err)
		}
		w.Account2.EncryptedSecretKey = se
```
Leave the `decrypt` calls, the CW-H2 `defer oqs.MemCleanse(ds)` guards, and the final `w.password = []byte(newPassword)` / `w.passwordBytes = newPasswordBytes` / `w.KdfSalt = newSalt` block unchanged.

- [ ] **Step 5: Run + build + grep-guard** —
```
GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./wallet/ -run 'TestEncryptWithKey' -v
GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go build ./...
```
→ both tests PASS, build exit 0. Then confirm the toggle is gone: `awk '/func \(w \*Wallet\) ChangePasswordInPlace/,/^}/' wallet/wallet.go | grep -c 'w.passwordBytes ='` must print `1` (only the single final swap remains), and `grep -n oldPasswordBytes wallet/wallet.go` must print nothing.

- [ ] **Step 6: Commit**
```bash
git add wallet/wallet.go wallet/encrypt_key_test.go
git commit -m "$(printf 'OB-126 CW-M3: encryptWithKey eliminates passwordBytes toggle in ChangePasswordInPlace\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Task 2: CW-M2 — honest error for oversized-key mnemonic backup

**Files:**
- Modify: `wallet/wallet.go` (`GetMnemonicWords`, the `> 64` branch)
- Test: `wallet/mnemonic_test.go` (new)

**Interfaces:**
- Consumes (existing): `GetMnemonicWords(primary bool) (string, error)`, `GetSecretKey()` → `common.PrivKey` (`GetBytes()`=`ByteValue`, `GetLength()`=`len(ByteValue)`).

- [ ] **Step 1: Write the failing test** — create `wallet/mnemonic_test.go`:
```go
package wallet

import (
	"strings"
	"testing"

	"github.com/qwid-org/qwid-node/common"
)

// TestGetMnemonicWordsRejectsOversizedKeyHonestly verifies CW-M2: a secret key
// larger than the 64-byte mnemonic ceiling (e.g. a post-quantum key) gets a clear,
// directive error instead of the misleading "less than 64 bytes" message. Pure
// length check — no oqs/CGO.
func TestGetMnemonicWordsRejectsOversizedKeyHonestly(t *testing.T) {
	w := &Wallet{}
	w.Account1.secretKey = common.PrivKey{ByteValue: make([]byte, 100)} // > 64

	_, err := w.GetMnemonicWords(true)
	if err == nil {
		t.Fatal("expected an error for a >64-byte secret key")
	}
	msg := err.Error()
	if strings.Contains(msg, "less than 64 bytes") {
		t.Fatalf("misleading old message still present: %q", msg)
	}
	if !strings.Contains(msg, "wallet-file") {
		t.Fatalf("error should direct the user to the wallet-file backup: %q", msg)
	}
}
```

- [ ] **Step 2: Run to verify it fails** — `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./wallet/ -run TestGetMnemonicWordsRejectsOversizedKeyHonestly -v` → FAIL (current message is `secret must be less than 64 bytes`, which contains "less than 64 bytes" and not "wallet-file").

- [ ] **Step 3: Replace the misleading error** — in `wallet/wallet.go` `GetMnemonicWords`, replace:
```go
	if secretLength > 64 {
		return "", fmt.Errorf("secret must be less than 64 bytes")
	}
```
with:
```go
	if secretLength > 64 {
		// CW-M2: BIP39-style mnemonics cannot represent a post-quantum secret key
		// (e.g. Falcon-512 is ~1281 bytes) — the 64-byte ceiling is intentional.
		// Give a clear, actionable error instead of the misleading "< 64 bytes" one.
		return "", fmt.Errorf("mnemonic backup is unavailable for keys larger than 64 bytes (post-quantum secret keys); use the encrypted wallet-file backup instead")
	}
```
Leave the `< 64` padding path and the round-trip validation below it unchanged.

- [ ] **Step 4: Run + build** — `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./wallet/ -run TestGetMnemonicWordsRejectsOversizedKeyHonestly -v && GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go build ./...` → test PASS, build exit 0.

- [ ] **Step 5: Commit**
```bash
git add wallet/wallet.go wallet/mnemonic_test.go
git commit -m "$(printf 'OB-126 CW-M2: honest error when a secret key is too large for mnemonic backup\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Final verification
- [ ] `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go build ./...` → exit 0.
- [ ] `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./wallet/ -run 'TestEncryptWithKey|TestGetMnemonicWordsRejectsOversizedKeyHonestly'` → PASS (and the broader `./wallet/` suite shows no NEW failures versus its pre-cluster state).
- [ ] Update `SECURITY_AUDIT.md` reconciliation: move **CW-M2, CW-M3** from OPEN to FIXED; Medium FIXED +2, OPEN −2 → **0 open mediums**; note CW-M3's documented single-swap residual and CW-M2's "64-byte ceiling by design, honest error". (Controller handles this doc edit after the final review.)

## Deferred (not in this plan)
- Full wallet lock discipline (RLock on all `passwordBytes` readers) to close CW-M3's residual single-swap race.
- A post-quantum-capable mnemonic/recovery encoding, if ever desired.
- Remaining deferred-by-design partials (DB-C4, NP-C4/C5, etc.).

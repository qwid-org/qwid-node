# NP-C5 handleWALL Response Redaction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop the `WALL` RPC from returning wallet encryption material — redact the `handleWALL` response to a safe public projection (`PublicView`) that omits `KdfSalt`, `EncryptedSecretKey`, `Iv`, `HomePath`, and the `Accounts` map.

**Architecture:** Add a redacted `PublicWalletView` projection on the wallet type (new `wallet/publicview.go`) exposing only identity fields; `handleWALL` marshals `w.PublicView()` instead of the raw `*Wallet`. Node-local; no consensus/wire/format change.

**Tech Stack:** Go 1.23.6 (build with the `sdk/go1.24.0` toolchain), CGO (RocksDB + liboqs). The new test is pure Go (struct copy + `json.Marshal`), no CGO. Test file uses `package wallet`.

## Global Constraints
- Build/test with `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go`. This repo uses CGO; export before building:
  ```
  export GOROOT=/home/wonabru/sdk/go1.24.0
  export PATH=$GOROOT/bin:$PATH
  export CGO_CFLAGS="-isystem $HOME/local/include"
  export CGO_LDFLAGS="-L$HOME/local/lib -L/usr/local/intelpython3/lib -lrocksdb -lstdc++ -lm -lz -lsnappy -llz4 -lzstd -lbz2 -lpthread -ldl"
  ```
- Branch `security-fixes`. Commit `OB-127` (NOT `(CONSENSUS)` — node-local RPC response). End the commit message with a blank line then `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- The redacted view MUST omit `KdfSalt` (`kdf_salt`), `EncryptedSecretKey` (`encrypted_secret_key`), `Iv` (`iv`), `HomePath` (`home_path`), and the `Accounts` map (`accounts`). It MUST keep `WalletNumber`, `MainAddress`, per-account `PublicKey` + `Address`, `SigName`, `SigName2`.
- `PublicView` must be nil-safe (`(*Wallet)(nil).PublicView()` returns an empty view, no panic).
- `rpc/server/server.go` already imports `encoding/json`, `logger`, and `wallet`; `common` is imported in the `wallet` package. Do not remove imports still in use.

---

## Task 1: Redacted PublicView + handleWALL uses it

**Files:**
- Create: `wallet/publicview.go`
- Modify: `rpc/server/server.go` (`handleWALL`)
- Test: `wallet/publicview_test.go` (new)

**Interfaces:**
- Produces: `type PublicWalletView struct {…}`, `type PublicAccountView struct {…}`, `func (w *Wallet) PublicView() PublicWalletView`.
- Consumes (existing): `Wallet` fields `WalletNumber`, `MainAddress`, `SigName`, `SigName2`, `Account1`/`Account2` (`.PublicKey`, `.Address`); `wallet.GetActiveWallet()`.

- [ ] **Step 1: Write the failing test** — create `wallet/publicview_test.go`:
```go
package wallet

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPublicViewRedactsEncryptionMaterial(t *testing.T) {
	w := &Wallet{
		Iv:           []byte("legacy-iv-bytes"),
		KdfSalt:      []byte("argon2id-salt-16"),
		HomePath:     "/home/user/.qwid",
		WalletNumber: 7,
		SigName:      "Falcon-512",
		SigName2:     "MAYO-5",
	}
	w.Account1.EncryptedSecretKey = []byte("ENCRYPTED-SECRET-1")
	w.Account2.EncryptedSecretKey = []byte("ENCRYPTED-SECRET-2")

	b, err := json.Marshal(w.PublicView())
	if err != nil {
		t.Fatalf("marshal PublicView: %v", err)
	}
	s := string(b)

	// The encryption material and local path must be absent.
	for _, leak := range []string{"kdf_salt", "encrypted_secret_key", "\"iv\"", "home_path", "\"accounts\""} {
		if strings.Contains(s, leak) {
			t.Fatalf("PublicView JSON leaks %q:\n%s", leak, s)
		}
	}
	// The public identity fields must be present.
	for _, keep := range []string{"wallet_number", "main_address", "sig_name", "public_key", "account_1"} {
		if !strings.Contains(s, keep) {
			t.Fatalf("PublicView JSON missing %q:\n%s", keep, s)
		}
	}
}

func TestPublicViewNilSafe(t *testing.T) {
	var w *Wallet
	_ = w.PublicView() // must not panic
}
```

- [ ] **Step 2: Run to verify it fails** — `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./wallet/ -run 'TestPublicView' -v` → FAIL to compile (`PublicView` undefined).

- [ ] **Step 3: Create `wallet/publicview.go`**:
```go
package wallet

import "github.com/qwid-org/qwid-node/common"

// PublicWalletView is the RPC-safe projection of a Wallet: identity/public fields
// only. It deliberately omits KdfSalt, EncryptedSecretKey, Iv, HomePath, and the
// Accounts map — everything an attacker would need for an offline password-cracking
// attack — so the WALL RPC cannot leak encryption material (NP-C5). The plaintext
// secret key, password, and signer are already unexported and never serialized.
type PublicWalletView struct {
	WalletNumber uint8             `json:"wallet_number"`
	MainAddress  common.Address    `json:"main_address"`
	SigName      string            `json:"sig_name"`
	SigName2     string            `json:"sig_name_2"`
	Account1     PublicAccountView `json:"account_1"`
	Account2     PublicAccountView `json:"account_2"`
}

type PublicAccountView struct {
	PublicKey common.PubKey  `json:"public_key"`
	Address   common.Address `json:"address"`
}

// PublicView returns the RPC-safe projection of w. Nil-safe.
func (w *Wallet) PublicView() PublicWalletView {
	if w == nil {
		return PublicWalletView{}
	}
	return PublicWalletView{
		WalletNumber: w.WalletNumber,
		MainAddress:  w.MainAddress,
		SigName:      w.SigName,
		SigName2:     w.SigName2,
		Account1:     PublicAccountView{PublicKey: w.Account1.PublicKey, Address: w.Account1.Address},
		Account2:     PublicAccountView{PublicKey: w.Account2.PublicKey, Address: w.Account2.Address},
	}
}
```

- [ ] **Step 4: Run the test to verify it passes** — `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./wallet/ -run 'TestPublicView' -v` → PASS.

- [ ] **Step 5: Wire `handleWALL` to the redacted view** — in `rpc/server/server.go`, replace:
```go
func handleWALL(line []byte, reply *[]byte) {
	logger.GetLogger().Println(string(line))
	w := wallet.GetActiveWallet()
	r, err := json.Marshal(w)
	if err != nil {
		logger.GetLogger().Println("Cannot marshal stat's struct")
		return
	}
	*reply = r
}
```
with:
```go
func handleWALL(line []byte, reply *[]byte) {
	logger.GetLogger().Println(string(line))
	w := wallet.GetActiveWallet()
	// NP-C5: return a redacted public projection — never the KdfSalt, the
	// EncryptedSecretKey, the Iv, or HomePath (the offline-attack material).
	r, err := json.Marshal(w.PublicView())
	if err != nil {
		logger.GetLogger().Println("Cannot marshal wallet public view")
		return
	}
	*reply = r
}
```

- [ ] **Step 6: Build** — `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go build ./...` → exit 0.

- [ ] **Step 7: Confirm no other full-wallet marshal leaks the same fields** — `grep -rn "json.Marshal(w)\|json.Marshal(wallet.GetActiveWallet" rpc/ cmd/` should show no remaining `json.Marshal` of a raw active `*Wallet` in an RPC/response path (the `WALL` site is now redacted; if another handler marshals the raw wallet, note it in the report — out of scope for this task unless it is the same `handleWALL`).

- [ ] **Step 8: Commit**
```bash
git add wallet/publicview.go wallet/publicview_test.go rpc/server/server.go
git commit -m "$(printf 'OB-127 NP-C5: redact handleWALL response (drop KdfSalt/EncryptedSecretKey/Iv/HomePath)\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Final verification
- [ ] `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go build ./...` → exit 0.
- [ ] `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./wallet/ -run 'TestPublicView'` → PASS.
- [ ] Update `SECURITY_AUDIT.md` reconciliation: move **NP-C5** from OPEN to FIXED; Critical OPEN −1 → **0**; **OPEN findings now 0** (every Critical/High/Medium fixed or a documented PARTIAL/deferred-by-design). (Controller handles this doc edit after the final review.)

## Deferred (not in this plan)
- The remaining PARTIAL / deferred-by-design items (DB-C4, NP-C4, NP-H12/H5/H9, WH-H5/H9, CW-M7, full wallet lock discipline, RPC pooling, etc.) — none are OPEN findings.

# NP-C5 — Redact the handleWALL RPC Response

**Date:** 2026-07-13
**Branch:** `security-fixes`
**Source:** `SECURITY_AUDIT.md` reconciliation — the last OPEN finding.

## Context

`handleWALL` (`rpc/server/server.go:200`) responds to the `WALL` RPC with `json.Marshal(wallet.GetActiveWallet())` — the entire `Wallet` struct, verbatim.

The unexported secrets (`password`, `passwordBytes`, `Account.secretKey`, `Account.signer`) are already omitted by `json.Marshal` (Go does not marshal unexported fields). But the exported/tagged fields that ARE serialized include the wallet's encryption material:
- **`KdfSalt`** (`json:"kdf_salt"`) — the Argon2id salt.
- **`EncryptedSecretKey`** (`json:"encrypted_secret_key"`, on each `Account`) — the encrypted secret-key blob.
- **`Iv`** (`json:"iv"`) — the legacy AES-CTR IV.
- **`HomePath`** (`json:"home_path"`) — a local filesystem path.
- Plus the identity fields: `WalletNumber`, `MainAddress`, per-account `PublicKey`/`Address`, `SigName`/`SigName2`, and the `Accounts` map (whose entries also carry `EncryptedSecretKey`).

**The exposure:** `KdfSalt` + `EncryptedSecretKey` are exactly the ingredients for an **offline password-cracking attack** — a known Argon2id salt plus the encrypted key lets an attacker brute-force the wallet password offline and decrypt the secret key. `WALL` is signature-gated (it is NOT in `common.ConnectionsWithoutVerification`) and the RPC binds loopback by default (NP-C4), which is why NP-C5 was re-scoped down from CRITICAL — but a wallet-info RPC has no legitimate reason to return the KDF salt or the encrypted key, so the response is over-broad.

### Ground truth
- No client consumes the redacted-out fields: a grep for `WALL` response consumers in `cmd/`/`rpc/client` found none; `WALL` is a wallet-info/display endpoint (addresses, public keys, sig names).
- `rpc/server/server.go` already imports the `wallet` package (`handleWALL` calls `wallet.GetActiveWallet()`).
- `common.Address` / `common.PubKey` are public value types with their own JSON tags and marshal cleanly.

## Decision (confirmed)
Return a **redacted view** with only the safe public identity fields; redact `KdfSalt`, `EncryptedSecretKey`, `Iv`, `HomePath`, and the `Accounts` map. The redaction lives on the wallet type (which owns the fields), so `rpc/server` never re-implements field-safety knowledge.

## Design

New file `wallet/publicview.go` (keeps the redaction focused and separate from the large `wallet.go`):
```go
package wallet

import "github.com/wonabru/qwid-node/common"

// PublicWalletView is the RPC-safe projection of a Wallet: identity/public fields
// only. It deliberately omits KdfSalt, EncryptedSecretKey, Iv, HomePath, and the
// Accounts map — i.e. everything an attacker would need for an offline
// password-cracking attack — so the WALL RPC cannot leak encryption material
// (NP-C5). The plaintext secret key, password, and signer are already unexported
// on Wallet/Account and never serialized.
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

`handleWALL` (`rpc/server/server.go`) marshals the projection instead of the raw wallet:
```go
func handleWALL(line []byte, reply *[]byte) {
	logger.GetLogger().Println(string(line))
	w := wallet.GetActiveWallet()
	r, err := json.Marshal(w.PublicView()) // NP-C5: redact KdfSalt/EncryptedSecretKey/Iv/HomePath
	if err != nil {
		logger.GetLogger().Println("Cannot marshal wallet public view")
		return
	}
	*reply = r
}
```
`w.PublicView()` is nil-safe, so a nil active wallet yields an empty view rather than a panic (the previous code marshaled a nil `*Wallet` to `null`; the projection is a safe, well-typed empty object).

## Non-goals
- Changing `WALL`'s auth gating (already signature-gated) or the loopback bind (NP-C4).
- Redacting the identity fields the endpoint exists to serve (addresses, public keys, sig names, wallet number).
- Any consensus/wire/format change to blocks or transactions.

## Error handling / determinism
- Node-local RPC-response change; no consensus/tx/block/wire impact. Commit is `OB-127` (not `(CONSENSUS)`).
- The redacted response is a strict subset of the prior response's identity fields; the removed fields (`kdf_salt`, `encrypted_secret_key`, `iv`, `home_path`, `accounts`) were the encryption material / local path — no consumer needs them.

## Testing
Pure, CGO-free unit test in the `wallet` package (`PublicView` is plain struct copying + `json.Marshal`, no oqs):
- Build a `Wallet` with sentinel `Iv`, `KdfSalt`, `HomePath`, and per-account `EncryptedSecretKey`, plus identity fields; marshal `w.PublicView()`.
- Assert the JSON does **NOT** contain the keys `"kdf_salt"`, `"encrypted_secret_key"`, `"iv"`, `"home_path"`, or `"accounts"`.
- Assert it **DOES** contain the identity keys `"wallet_number"`, `"main_address"`, `"sig_name"`, `"public_key"`, `"account_1"`.
- Assert `(*Wallet)(nil).PublicView()` does not panic (nil-safe).

`handleWALL`'s one-line change is verified by inspection + build (it needs a live active wallet/RPC to exercise end-to-end; the redaction logic under test is `PublicView`).

Tests run with `GOROOT=/home/wonabru/sdk/go1.24.0`; build `GOROOT=… go build ./...`.

## Files touched
- `wallet/publicview.go` (new) — `PublicWalletView`, `PublicAccountView`, `PublicView()`.
- `rpc/server/server.go` — `handleWALL` marshals `w.PublicView()`.
- New test: `wallet/publicview_test.go`.

## Rollout / commit plan
`OB-127` commit (node-local, not `(CONSENSUS)`):
1. NP-C5 — redacted `PublicView` + `handleWALL` uses it (+ test).

Not "done" until `wallet` and `rpc/server` build and the test passes, and `SECURITY_AUDIT.md` reconciliation moves **NP-C5** to FIXED — **taking OPEN findings to 0** (every Critical/High/Medium fixed or documented PARTIAL/deferred-by-design).

## Deferred (follow-ups)
- The remaining PARTIAL / deferred-by-design items (DB-C4 gas economics, NP-C4 TRAN auth, NP-H12/H5/H9, WH-H5/H9, CW-M7, full wallet lock discipline, RPC pooling, etc.) — none are OPEN findings; all are documented design tradeoffs or larger future work.

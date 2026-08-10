# EVM Phase 2 — Balance Bridge Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bridge the EVM's balance methods to the authoritative native `account.Accounts` balances so contracts read real balances and SELFDESTRUCT moves real value supply-neutrally.

**Architecture:** `GetBalance`/`AddBalance`/`SubBalance` on `stateDB.StateAccount` read/write native `int64` base-unit balances via `account.GetBalance`/`SetBalance` (1:1, no wei rescaling); writes append a `balanceChange` entry to the Phase 1 change journal so `RevertToSnapshot` restores the prior native balance. `Empty` gains the EIP-161 balance term, and `opSelfdestruct` zeroes the contract's balance when crediting the beneficiary.

**Tech Stack:** Go 1.23.6, go-ethereum-derived `core/evm`/`core/stateDB`, native `account` package (RocksDB-backed, `int64` base units).

## Global Constraints

- Build/test with `GOROOT=/home/wonabru/sdk/go1.24.0` (avoids the local toolchain mismatch). Example: `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./core/stateDB/`.
- Branch `security-fixes`. Commit per task, `OB-xx (CONSENSUS)` message convention (Phase 2 mutates native balances → consensus-affecting). End commit messages with `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- Native balance is `int64` QWD base units. EVM balances are `*big.Int` **1:1 in base units** — NO Ethereum 18-decimal / wei rescaling.
- `account.GetBalance(addr [20]byte) int64` and `account.SetBalance(addr [20]byte, v int64)` are SELF-LOCKING (they take `account.AccountsRWMutex` internally). The bridge methods MUST call these accessors and MUST NOT hold `AccountsRWMutex` themselves. Lock ordering is `blocks.StateMutex → account.AccountsRWMutex` (already established; do not introduce the reverse).
- `AddBalance`/`SubBalance` cannot return errors (fixed `StateDB` interface). Out-of-`int64` amounts and would-be-negative results SATURATE (Add clamps at `math.MaxInt64`, Sub floors at `0`) with a `logger` warning — never wrap/corrupt. This path is unreachable with valid balances (total supply < `math.MaxInt64`); it exists so malformed state degrades safely.
- `common.Address` has field `ByteValue [20]byte`; `common.AddressLength == 20`.

---

## File Structure

- `core/stateDB/methods.go` — `GetBalance`/`AddBalance`/`SubBalance` bridge, `Empty` update, `bigToBaseUnits` helper (Tasks 1–2).
- `core/stateDB/journal.go` — `balanceChange` entry; add `account` import (Task 2).
- `core/stateDB/methods_test.go` — balance read/write/revert + `Empty` tests (Tasks 1–2).
- `core/evm/instructions.go` — `opSelfdestruct` supply-neutrality (Task 3).
- `blocks/evm_balance_test.go` (new) — supply-conservation test (Task 3).

---

## Task 1: GetBalance read bridge + Empty (EIP-161)

**Files:**
- Modify: `core/stateDB/methods.go` (`GetBalance` ~line 109-111, `Empty` ~line 191-193)
- Test: `core/stateDB/methods_test.go`

**Interfaces:**
- Consumes: `account.GetBalance(addr [20]byte) int64`.
- Produces: `func (sa *StateAccount) GetBalance(a common.Address) *big.Int` (now native-backed); `Empty` now balance-aware.

- [ ] **Step 1: Write the failing test**

Add to `core/stateDB/methods_test.go` (add imports `"math/big"` and `"github.com/qwid-org/qwid-node/account"` if absent):

```go
// initNativeAccounts resets the native account map so balance bridging has a
// clean, non-nil map to write into.
func initNativeAccounts() {
	account.AccountsRWMutex.Lock()
	account.Accounts.AllAccounts = make(map[[common.AddressLength]byte]account.Account)
	account.AccountsRWMutex.Unlock()
}

func TestGetBalanceReadsNative(t *testing.T) {
	initNativeAccounts()
	sa := CreateStateDB()
	a := addr(0x10)
	account.SetBalance(a.ByteValue, 4200)
	if got := sa.GetBalance(a); got.Int64() != 4200 {
		t.Fatalf("GetBalance = %s, want 4200", got.String())
	}
	// Absent account reads as zero.
	if got := sa.GetBalance(addr(0x11)); got.Sign() != 0 {
		t.Fatalf("absent GetBalance = %s, want 0", got.String())
	}
}

func TestEmptyConsidersBalance(t *testing.T) {
	initNativeAccounts()
	sa := CreateStateDB()
	a := addr(0x12)
	// zero nonce, no code, but non-zero balance => NOT empty (EIP-161).
	account.SetBalance(a.ByteValue, 1)
	if sa.Empty(a) {
		t.Fatal("account with balance reported Empty")
	}
	account.SetBalance(a.ByteValue, 0)
	if !sa.Empty(a) {
		t.Fatal("zero nonce/code/balance account not reported Empty")
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./core/stateDB/ -run 'TestGetBalanceReadsNative|TestEmptyConsidersBalance' -v`
Expected: FAIL — `GetBalance` returns hardcoded 0; `Empty` ignores balance.

- [ ] **Step 3: Implement the bridge**

In `core/stateDB/methods.go`, replace `GetBalance`:

```go
func (sa *StateAccount) GetBalance(a common.Address) *big.Int {
	return new(big.Int).SetInt64(account.GetBalance(a.ByteValue))
}
```

And replace `Empty`:

```go
// Empty returns whether the given account is empty per EIP-161
// (nonce == 0 && code == 0 && balance == 0).
func (sa *StateAccount) Empty(a common.Address) bool {
	return sa.Nonces[a.ByteValue] == 0 && len(sa.Codes[a.ByteValue]) == 0 &&
		sa.GetBalance(a).Sign() == 0
}
```

(`account` and `math/big` are already imported in methods.go.)

- [ ] **Step 4: Run to verify it passes**

Run: `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./core/stateDB/ -run 'TestGetBalanceReadsNative|TestEmptyConsidersBalance' -v`
Expected: PASS.

- [ ] **Step 5: Build dependents + commit**

Run: `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go build ./core/... ./blocks/...`

```bash
git add core/stateDB/methods.go core/stateDB/methods_test.go
git commit -m "OB-101 DB-C1 (CONSENSUS): GetBalance reads native balances, Empty considers balance

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 2: AddBalance/SubBalance write bridge + balanceChange journal

**Files:**
- Modify: `core/stateDB/methods.go` (`SubBalance`/`AddBalance` ~line 103-108, add `bigToBaseUnits`)
- Modify: `core/stateDB/journal.go` (add `balanceChange`, add `account` import)
- Test: `core/stateDB/methods_test.go`

**Interfaces:**
- Consumes: `account.GetBalance`/`SetBalance`; the journal (`sa.journal`, `sa.SnapShotNum`, `changeEntry`), `Snapshot()`/`RevertToSnapshot()`.
- Produces: native-mutating `AddBalance`/`SubBalance`; `balanceChange` journal entry.

- [ ] **Step 1: Write the failing test**

Add to `core/stateDB/methods_test.go`:

```go
func TestAddSubBalanceMutatesNativeAndReverts(t *testing.T) {
	initNativeAccounts()
	sa := CreateStateDB()
	a := addr(0x20)
	account.SetBalance(a.ByteValue, 1000)

	snap := sa.Snapshot()
	sa.AddBalance(a, big.NewInt(500))
	if account.GetBalance(a.ByteValue) != 1500 {
		t.Fatalf("after AddBalance native = %d, want 1500", account.GetBalance(a.ByteValue))
	}
	sa.SubBalance(a, big.NewInt(200))
	if account.GetBalance(a.ByteValue) != 1300 {
		t.Fatalf("after SubBalance native = %d, want 1300", account.GetBalance(a.ByteValue))
	}

	sa.RevertToSnapshot(snap)
	if account.GetBalance(a.ByteValue) != 1000 {
		t.Fatalf("after revert native = %d, want 1000 (restored)", account.GetBalance(a.ByteValue))
	}
}

func TestSubBalanceFloorsAtZero(t *testing.T) {
	initNativeAccounts()
	sa := CreateStateDB()
	a := addr(0x21)
	account.SetBalance(a.ByteValue, 50)
	sa.SubBalance(a, big.NewInt(9999)) // would go negative
	if account.GetBalance(a.ByteValue) != 0 {
		t.Fatalf("SubBalance did not floor at 0: got %d", account.GetBalance(a.ByteValue))
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./core/stateDB/ -run 'TestAddSubBalance|TestSubBalanceFloors' -v`
Expected: FAIL — `AddBalance`/`SubBalance` are no-ops.

- [ ] **Step 3: Add the balanceChange journal entry**

In `core/stateDB/journal.go`, change the import line
`import "github.com/qwid-org/qwid-node/common"`
to:

```go
import (
	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/common"
)
```

Append at the end of `journal.go`:

```go
// balanceChange restores a native account balance to its prior value on revert.
type balanceChange struct {
	addr [common.AddressLength]byte
	prev int64
}

func (c balanceChange) revert(sa *StateAccount) {
	account.SetBalance(c.addr, c.prev)
}
```

- [ ] **Step 4: Implement AddBalance/SubBalance + bigToBaseUnits**

In `core/stateDB/methods.go`, add the helper (near the balance methods) and add `"math"` to the imports:

```go
// bigToBaseUnits converts an EVM *big.Int amount (base units, 1:1 with native
// QWD) to int64. ok is false when the amount is outside int64 range; callers
// saturate rather than wrap (unreachable with valid balances).
func bigToBaseUnits(amount *big.Int) (v int64, ok bool) {
	if amount == nil {
		return 0, true
	}
	if !amount.IsInt64() {
		return 0, false
	}
	return amount.Int64(), true
}
```

Replace `SubBalance` and `AddBalance`:

```go
func (sa *StateAccount) AddBalance(a common.Address, amount *big.Int) {
	amt, ok := bigToBaseUnits(amount)
	if !ok {
		logger.GetLogger().Println("EVM AddBalance: amount exceeds int64 range, saturating", a.GetHex())
		amt = math.MaxInt64
	}
	prev := account.GetBalance(a.ByteValue)
	next := prev + amt
	if next < prev { // int64 overflow => saturate
		next = math.MaxInt64
	}
	sa.journal = append(sa.journal, balanceChange{addr: a.ByteValue, prev: prev})
	sa.SnapShotNum = len(sa.journal)
	account.SetBalance(a.ByteValue, next)
}

func (sa *StateAccount) SubBalance(a common.Address, amount *big.Int) {
	amt, ok := bigToBaseUnits(amount)
	if !ok {
		logger.GetLogger().Println("EVM SubBalance: amount exceeds int64 range, saturating", a.GetHex())
		amt = math.MaxInt64
	}
	prev := account.GetBalance(a.ByteValue)
	// amt is non-negative (EVM balances are uint256-derived) and both operands
	// are in [0, MaxInt64], so prev-amt cannot int64-underflow; a negative
	// result just means "insufficient balance" => floor at 0 (a native balance
	// must never go negative).
	next := prev - amt
	if next < 0 {
		next = 0
	}
	sa.journal = append(sa.journal, balanceChange{addr: a.ByteValue, prev: prev})
	sa.SnapShotNum = len(sa.journal)
	account.SetBalance(a.ByteValue, next)
}
```

Confirm `logger` is imported in methods.go; if not, add `"github.com/qwid-org/qwid-node/logger"`. (`common.Address` has a `GetHex()` method used in the log lines.)

- [ ] **Step 5: Run to verify it passes**

Run: `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./core/stateDB/ -run 'TestAddSubBalance|TestSubBalanceFloors' -v`
Expected: PASS.

- [ ] **Step 6: Full stateDB suite + build + commit**

Run: `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./core/stateDB/ && GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go build ./...`
Expected: PASS, build OK.

```bash
git add core/stateDB/methods.go core/stateDB/journal.go core/stateDB/methods_test.go
git commit -m "OB-102 DB-C1 (CONSENSUS): AddBalance/SubBalance bridge native balances with journaled revert

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 3: SELFDESTRUCT supply-neutrality + supply-conservation test

**Files:**
- Modify: `core/evm/instructions.go` (`opSelfdestruct`)
- Test: `blocks/evm_balance_test.go` (new)

**Interfaces:**
- Consumes: `StateAccount.GetBalance`/`AddBalance`/`SubBalance` (Tasks 1–2); `blocks.GetSupplyInAccounts()`; `account.SetBalance`.

**Background:** `opSelfdestruct` (`core/evm/instructions.go`) credits the beneficiary with the contract's balance but never zeroes the contract, so with the live write bridge it would inflate supply. Add a paired `SubBalance(contract, balance)`.

- [ ] **Step 1: Write the failing supply-conservation test**

Create `blocks/evm_balance_test.go`:

```go
package blocks

import (
	"testing"

	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
)

// TestSelfdestructConservesSupply exercises the balance sequence that
// opSelfdestruct performs (credit beneficiary, debit contract) and asserts total
// supply is unchanged and the contract balance is zeroed.
func TestSelfdestructConservesSupply(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	account.AccountsRWMutex.Lock()
	account.Accounts.AllAccounts = make(map[[common.AddressLength]byte]account.Account)
	account.AccountsRWMutex.Unlock()
	InitStateDB()

	var contract, beneficiary common.Address
	contract.ByteValue[0] = 0x30
	beneficiary.ByteValue[0] = 0x31
	account.SetBalance(contract.ByteValue, 700)
	account.SetBalance(beneficiary.ByteValue, 100)
	before := GetSupplyInAccounts()

	// The exact sequence opSelfdestruct performs (verified by Step 3):
	bal := State.GetBalance(contract)
	State.AddBalance(beneficiary, bal)
	State.SubBalance(contract, bal)

	if account.GetBalance(beneficiary.ByteValue) != 100+700 {
		t.Fatalf("beneficiary = %d, want 800", account.GetBalance(beneficiary.ByteValue))
	}
	if account.GetBalance(contract.ByteValue) != 0 {
		t.Fatalf("contract balance not zeroed: %d", account.GetBalance(contract.ByteValue))
	}
	if after := GetSupplyInAccounts(); after != before {
		t.Fatalf("supply changed: before=%d after=%d", before, after)
	}
}
```

- [ ] **Step 2: Run to verify it passes for the sequence (documents the required behavior)**

Run: `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./blocks/ -run TestSelfdestructConservesSupply -v`
Expected: PASS — this test asserts the *sequence* (Add then Sub) conserves supply; it defines the behavior `opSelfdestruct` must emit. (If it FAILS, Tasks 1–2 are wrong.)

- [ ] **Step 3: Make opSelfdestruct supply-neutral**

In `core/evm/instructions.go`, in `opSelfdestruct`, add the paired `SubBalance` right after the `AddBalance` line:

```go
	balance := interpreter.evm.StateDB.GetBalance(scope.Contract.Address())
	interpreter.evm.StateDB.AddBalance(common.SetByteAddress(beneficiary.Bytes20()), balance)
	interpreter.evm.StateDB.SubBalance(scope.Contract.Address(), balance) // supply-neutral (DB-C1)
	interpreter.evm.StateDB.Suicide(scope.Contract.Address())
```

Note: `balance` is read ONCE before the pair, so self-destruct-to-self (beneficiary == contract) nets to zero — credit then debit the same address by the same amount = the go-ethereum result (balance burned).

- [ ] **Step 4: Build + run**

Run: `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go build ./... && GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./core/evm/ ./blocks/ -run 'Selfdestruct|TestSelfdestruct'`
Expected: build OK; test PASS.

- [ ] **Step 5: Commit**

```bash
git add core/evm/instructions.go blocks/evm_balance_test.go
git commit -m "OB-103 DB-C1 (CONSENSUS): SELFDESTRUCT zeroes contract balance (supply-neutral)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Final verification

- [ ] `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go build ./...` → exit 0.
- [ ] `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./core/stateDB/ ./core/evm/ ./blocks/` → PASS (blocks EVM persistence tests may SKIP without a live DB; the known pre-existing `core/abi` `ExampleJSON` panic is unrelated).
- [ ] Update `SECURITY_AUDIT.md`: mark **DB-C1** addressed by Phase 2 (DB-C2 value transfer and DB-C4 refunds remain for Phase 3).

## Deferred to Phase 3 (not in this plan)
- DB-C2: re-enable `CanTransfer`/`Transfer` in `core/evm/evm.go` (general `msg.value`).
- DB-C4: real gas pricing, debiting gas from balances, refunds.
- Wiring `PrepareAccessList` at tx-start (carried from Phase 1).

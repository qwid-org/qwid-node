# EVM Phase 3a — Value Transfer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Re-enable EVM value transfer so contracts can hold and move QWD, with a correct top-level `msg.value`, without double-moving value or breaking the native fee path.

**Architecture:** Install `CanTransfer`/`Transfer` hooks (backed by the Phase 2 native balance bridge) into the EVM `BlockContext` and un-comment their use in `evm.go`; route a contract-call tx's `Amount` through the EVM as `msg.value` while `ProcessTransaction` skips the native Amount move for exactly those txs; keep the size-based signed fee unchanged (EVM gas stays a step-limiter).

**Tech Stack:** Go 1.23.6, go-ethereum-derived `core/evm`/`core/stateDB`, native `account` package.

## Global Constraints

- Build/test with `GOROOT=/home/wonabru/sdk/go1.24.0`. Example: `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./blocks/`.
- Branch `security-fixes`. Commit per task, `OB-xx (CONSENSUS)` convention. End messages with `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- **KEEP the size-based signed fee.** Do NOT change the tx format, signing, `Verify`, `BlockFee`, `CalcFee`, or `GasUsage`. EVM gas remains a step-limiter with no fee effect.
- **The `isContractCallTx` predicate (Task 2) is consensus-critical and must match EXACTLY when `EvaluateSCForBlock` routes a tx to `EvaluateSC`.** That condition is: `len(OptData) > 0` AND recipient is NOT a delegated account (`account.IntDelegatedAccountFromAddress(recipient)` returns a non-nil error) AND the sender is NOT a multisign account (`senderAcc.MultiSignNumber == 0`) AND the sender is NOT escrow-delayed (`!(senderAcc.TransactionDelay > 0 && tx.GetHeight()+senderAcc.TransactionDelay > height)`). If the predicate is too broad (e.g. only `OptData>0`), a multisign-account contract tx would have its value moved by NEITHER the EVM (skipped) nor the native path (guarded off) — value loss.
- `common.Address` has field `ByteValue [20]byte`; `common.AddressLength == 20`. Value hooks use the Phase 2 native-bridged `db.GetBalance`/`SubBalance`/`AddBalance` (all `*big.Int` / journaled).
- Contract-level end-to-end tests through real bytecode are impractical without a full opcode harness; where noted, exercise the value hooks / `ProcessTransaction` guard / predicate directly at the `blocks` level and state the limitation.

---

## File Structure

- `blocks/evaluate.go` — `evmCanTransfer`/`evmTransfer`, install hooks in the 3 `BlockContext`s, pass `tx.Amount` as the entry value, `isContractCallTx` helper, `PrepareAccessList` wiring.
- `core/evm/evm.go` — un-comment `CanTransfer`/`Transfer` in `Call` and `create`.
- `blocks/processTransaction.go` — guard the native Amount move with `!isContractCallTx(...)`.
- `core/stateDB/methods.go` — `AddRefund`/`SubRefund`/`GetRefund` + `refund` field; `ResetTransient` resets it.
- Tests in `blocks/` and `core/stateDB/`.

---

## Task 1: EVM value hooks + enable transfer + CallCode-safe

**Files:**
- Modify: `blocks/evaluate.go` (add `evmCanTransfer`/`evmTransfer`; set them in the 3 `BlockContext`s at ~`:372-373`, `:459-460`, `:517-518`)
- Modify: `core/evm/evm.go` (un-comment `CanTransfer`/`Transfer` in `Call` `:174-176,:196` and `create` `:412-414,:436`)
- Test: `blocks/evm_transfer_test.go` (new)

**Interfaces:**
- Consumes: Phase 2 `stateDB` bridge (`GetBalance`/`AddBalance`/`SubBalance`), `vm.StateDB`, `vm.CanTransferFunc func(StateDB, common.Address, *big.Int) bool`, `vm.TransferFunc func(StateDB, common.Address, common.Address, *big.Int)`.
- Produces: `func evmCanTransfer(vm.StateDB, common.Address, *big.Int) bool`, `func evmTransfer(vm.StateDB, common.Address, common.Address, *big.Int)`.

- [ ] **Step 1: Write the failing test**

Create `blocks/evm_transfer_test.go`:

```go
package blocks

import (
	"math/big"
	"testing"

	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
)

func initNativeAccountsBlocks() {
	account.AccountsRWMutex.Lock()
	account.Accounts.AllAccounts = make(map[[common.AddressLength]byte]account.Account)
	account.AccountsRWMutex.Unlock()
}

func TestEvmTransferMovesValueAndCanTransfer(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	initNativeAccountsBlocks()
	InitStateDB()

	var from, to common.Address
	from.ByteValue[0] = 0x50
	to.ByteValue[0] = 0x51
	account.SetBalance(from.ByteValue, 1000)

	if !evmCanTransfer(&State, from, big.NewInt(400)) {
		t.Fatal("CanTransfer should allow 400 from balance 1000")
	}
	if evmCanTransfer(&State, from, big.NewInt(1001)) {
		t.Fatal("CanTransfer should reject 1001 from balance 1000")
	}
	evmTransfer(&State, from, to, big.NewInt(400))
	if account.GetBalance(from.ByteValue) != 600 || account.GetBalance(to.ByteValue) != 400 {
		t.Fatalf("transfer wrong: from=%d to=%d", account.GetBalance(from.ByteValue), account.GetBalance(to.ByteValue))
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./blocks/ -run TestEvmTransferMovesValue`
Expected: FAIL — `evmCanTransfer`/`evmTransfer` undefined.

- [ ] **Step 3: Add the hooks**

In `blocks/evaluate.go`, add (near the top-level funcs; `vm`, `common`, `math/big` are already imported):

```go
// evmCanTransfer reports whether addr's native balance covers amount (DB-C2).
func evmCanTransfer(db vm.StateDB, addr common.Address, amount *big.Int) bool {
	return db.GetBalance(addr).Cmp(amount) >= 0
}

// evmTransfer moves amount between native balances via the Phase 2 bridge
// (journaled, so a reverted EVM call restores both sides).
func evmTransfer(db vm.StateDB, from, to common.Address, amount *big.Int) {
	db.SubBalance(from, amount)
	db.AddBalance(to, amount)
}
```

In the SAME file, in each of the three `vm.BlockContext{...}` literals (`EvaluateSC`, `EvaluateSCDex`, `GetViewFunctionReturns`), replace:
```go
		CanTransfer: nil,
		Transfer:    nil,
```
with:
```go
		CanTransfer: evmCanTransfer,
		Transfer:    evmTransfer,
```

- [ ] **Step 4: Un-comment the hooks in evm.go**

In `core/evm/evm.go` `Call`, un-comment the CanTransfer guard (`:174-176`) and the Transfer (`:196`):
```go
	if value.Sign() != 0 && !evm.Context.CanTransfer(evm.StateDB, caller.Address(), value) {
		return nil, gas, ErrInsufficientBalance
	}
```
```go
	evm.Context.Transfer(evm.StateDB, caller.Address(), addr, value)
```
In `create` (`:412-414`, `:436`), un-comment:
```go
	if !evm.Context.CanTransfer(evm.StateDB, caller.Address(), value) {
		return nil, common.Address{}, gas, ErrInsufficientBalance
	}
```
```go
	evm.Context.Transfer(evm.StateDB, caller.Address(), address, value)
```
`CallCode`'s existing live `CanTransfer` call (`:263`) now resolves against a real hook — no code change there, but it is no longer a nil-deref.

- [ ] **Step 5: Run + build**

Run: `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./blocks/ -run TestEvmTransferMovesValue -v && GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go build ./...`
Expected: PASS, build OK.

- [ ] **Step 6: Commit**

```bash
git add blocks/evaluate.go core/evm/evm.go blocks/evm_transfer_test.go
git commit -m "OB-106 DB-C2 (CONSENSUS): enable EVM value transfer hooks (native-bridged), fix CallCode nil

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 2: Route contract-tx value through the EVM + guard native path

**Files:**
- Modify: `blocks/evaluate.go` (add `isContractCallTx`; pass `tx.Amount` as entry value at `VM.Create` ~`:418` and `VM.Call` ~`:426`)
- Modify: `blocks/processTransaction.go` (guard the native Amount move ~`:297-305`)
- Test: `blocks/evm_transfer_test.go`

**Interfaces:**
- Consumes: `account.IntDelegatedAccountFromAddress`, `account.Account` (fields `MultiSignNumber`, `TransactionDelay`).
- Produces: `func isContractCallTx(tx transactionsDefinition.Transaction, senderAcc account.Account, height int64) bool`.

- [ ] **Step 1: Write the failing predicate test**

Append to `blocks/evm_transfer_test.go` (add imports `transactionsDefinition` and any needed):

```go
func TestIsContractCallTxPredicate(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	var recipient common.Address
	recipient.ByteValue[0] = 0x60 // a plain, non-delegated address

	mk := func(opt []byte) transactionsDefinition.Transaction {
		var tx transactionsDefinition.Transaction
		tx.TxData.OptData = opt
		tx.TxData.Recipient = recipient
		return tx
	}
	plain := account.Account{}                 // normal account
	multi := account.Account{MultiSignNumber: 2}

	// OptData present, normal account, non-delegated recipient => contract call.
	if !isContractCallTx(mk([]byte{0x01}), plain, 100) {
		t.Fatal("expected contract-call tx to be detected")
	}
	// No OptData => not a contract call.
	if isContractCallTx(mk(nil), plain, 100) {
		t.Fatal("empty OptData must not be a contract call")
	}
	// Multisign sender => EVM does not run => NOT a contract call (native moves value).
	if isContractCallTx(mk([]byte{0x01}), multi, 100) {
		t.Fatal("multisign-account tx must not be treated as EVM-owned")
	}
	// Escrow-delayed sender => EVM does not run => NOT a contract call.
	escrow := account.Account{TransactionDelay: 50}
	txEscrow := mk([]byte{0x01})
	txEscrow.Height = 100 // height+delay(150) > current(100) => delayed
	if isContractCallTx(txEscrow, escrow, 100) {
		t.Fatal("escrow-delayed tx must not be treated as EVM-owned")
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./blocks/ -run TestIsContractCallTxPredicate`
Expected: FAIL — `isContractCallTx` undefined.

- [ ] **Step 3: Implement isContractCallTx**

In `blocks/evaluate.go`:

```go
// isContractCallTx reports whether the EVM (via EvaluateSC) owns this tx's value
// transfer, so the native ProcessTransaction path must NOT also move it. It must
// match EXACTLY the condition under which EvaluateSCForBlock routes a tx to
// EvaluateSC: OptData present, non-delegated recipient, and a sender that is
// neither a multisign account nor escrow-delayed (both skip SC execution).
func isContractCallTx(tx transactionsDefinition.Transaction, senderAcc account.Account, height int64) bool {
	if len(tx.TxData.OptData) == 0 {
		return false
	}
	if _, err := account.IntDelegatedAccountFromAddress(tx.TxData.Recipient); err == nil {
		return false // delegated recipient (staking/reward/DEX) — not an SC call
	}
	if senderAcc.MultiSignNumber > 0 {
		return false // multisign accounts skip SC execution
	}
	if senderAcc.TransactionDelay > 0 && tx.GetHeight()+senderAcc.TransactionDelay > height {
		return false // escrow-delayed — SC not executed
	}
	return true
}
```

- [ ] **Step 4: Pass tx.Amount as the EVM entry value**

In `EvaluateSC` (`blocks/evaluate.go`), replace the endowment/value `new(big.Int).SetInt64(0)`:
- `VM.Create(...)` (~`:418`): change the 4th arg from `new(big.Int).SetInt64(0)` to `big.NewInt(tx.TxData.Amount)`.
- `VM.Call(...)` (~`:426`): change the final value arg from `new(big.Int).SetInt64(0)` to `big.NewInt(tx.TxData.Amount)`.
(Leave `EvaluateSCDex` and `GetViewFunctionReturns` value args at 0 — DEX/view are value-less.)

- [ ] **Step 5: Guard the native Amount move**

In `blocks/processTransaction.go`, in `ProcessTransaction`, the innermost `else` (~`:293-306`) that moves the amount. `senderAcc` is already in scope (declared ~`:281`), `height` is a parameter. Wrap the two `AddBalance` amount moves:

Replace:
```go
			err = AddBalance(address.ByteValue, -amount)
			if err != nil {
				return err
			}

			err = AddBalance(addressRecipient.ByteValue, amount)
			if err != nil {
				return err
			}
```
with:
```go
			// DB-C2: for contract-call txs the EVM already moved Amount as
			// msg.value; the native path must not move it again. Non-contract
			// (plain) transfers move natively as before.
			if !isContractCallTx(tx, senderAcc, height) {
				err = AddBalance(address.ByteValue, -amount)
				if err != nil {
					return err
				}
				err = AddBalance(addressRecipient.ByteValue, amount)
				if err != nil {
					return err
				}
			}
```
The fee deduction below (`AddBalance(address.ByteValue, -fee)`) is UNCHANGED — the fee is always charged.

- [ ] **Step 6: Write the no-double-move test**

Append to `blocks/evm_transfer_test.go` — verify the ProcessTransaction guard skips amount for a contract tx and keeps it for a plain tx, exercised via the predicate + evmTransfer (documenting that the full ProcessTransaction path needs a signed tx harness):

```go
func TestContractTxValueNotDoubleMoved(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	initNativeAccountsBlocks()
	InitStateDB()

	var sender, contract common.Address
	sender.ByteValue[0] = 0x70
	contract.ByteValue[0] = 0x71
	account.SetBalance(sender.ByteValue, 1000)

	// Simulate the EVM entry Transfer for a contract-call tx (msg.value=200).
	evmTransfer(&State, sender, contract, big.NewInt(200))
	// The native guard must classify this as a contract-call tx (predicate true),
	// so ProcessTransaction would skip the native amount move — no second move.
	var tx transactionsDefinition.Transaction
	tx.TxData.OptData = []byte{0x01}
	tx.TxData.Recipient = contract
	if !isContractCallTx(tx, account.Account{}, 100) {
		t.Fatal("contract tx not detected; native path would double-move value")
	}
	if account.GetBalance(sender.ByteValue) != 800 || account.GetBalance(contract.ByteValue) != 200 {
		t.Fatalf("value moved once only expected: sender=%d contract=%d",
			account.GetBalance(sender.ByteValue), account.GetBalance(contract.ByteValue))
	}
}
```

- [ ] **Step 7: Run + build + commit**

Run: `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./blocks/ -run 'TestIsContractCallTx|TestContractTxValueNotDoubleMoved' -v && GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go build ./...`
Expected: PASS, build OK.

```bash
git add blocks/evaluate.go blocks/processTransaction.go blocks/evm_transfer_test.go
git commit -m "OB-107 DB-C2 (CONSENSUS): route contract-tx Amount through EVM msg.value, guard native path

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 3: Confirm failed top-level call reverts value (evm.go already snapshots)

**Files:**
- Test: `blocks/evm_transfer_test.go`
- (No production change expected — `evm.go` `Call`/`create` already `Snapshot()` before `Transfer` and `RevertToSnapshot` on error. This task VERIFIES that and adds a regression test. If the trace shows `create` does NOT revert on error, add the revert there.)

- [ ] **Step 1: Verify evm.go revert-on-error**

Read `core/evm/evm.go` `Call` and `create`: confirm each takes `snapshot := evm.StateDB.Snapshot()` before the (now un-commented) `Transfer`, and on `err != nil` calls `evm.StateDB.RevertToSnapshot(snapshot)`. `Call` does (the `if err != nil { RevertToSnapshot }` block). Confirm `create` does too; if `create` is missing the revert on the value-transfer path, add `evm.StateDB.RevertToSnapshot(snapshot)` in its error path (matching `Call`). Note findings in the report.

- [ ] **Step 2: Write the revert regression test**

Append to `blocks/evm_transfer_test.go` — model the snapshot/transfer/revert sequence the EVM performs on a failed call:

```go
func TestValueTransferRevertedOnFailure(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	initNativeAccountsBlocks()
	InitStateDB()

	var from, to common.Address
	from.ByteValue[0] = 0x80
	to.ByteValue[0] = 0x81
	account.SetBalance(from.ByteValue, 1000)

	snap := State.Snapshot()
	evmTransfer(&State, from, to, big.NewInt(300)) // as the EVM does after Snapshot()
	// Simulate the call failing: EVM reverts to the snapshot.
	State.RevertToSnapshot(snap)

	if account.GetBalance(from.ByteValue) != 1000 || account.GetBalance(to.ByteValue) != 0 {
		t.Fatalf("value not restored on revert: from=%d to=%d",
			account.GetBalance(from.ByteValue), account.GetBalance(to.ByteValue))
	}
}
```

- [ ] **Step 3: Run + commit**

Run: `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./blocks/ -run TestValueTransferRevertedOnFailure -v && GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go build ./...`
Expected: PASS.

```bash
git add blocks/evm_transfer_test.go core/evm/evm.go
git commit -m "OB-108 DB-C2 (CONSENSUS): verify+test failed-call value revert (snapshot/revert)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 4: Refund accounting (DB-C4, accounting-only)

**Files:**
- Modify: `core/stateDB/methods.go` (`AddRefund`/`SubRefund`/`GetRefund` ~`:195-203`; add `refund uint64` transient field; `ResetTransient` resets it)
- Test: `core/stateDB/methods_test.go`

- [ ] **Step 1: Write the failing test**

Append to `core/stateDB/methods_test.go`:

```go
func TestRefundAccounting(t *testing.T) {
	sa := CreateStateDB()
	if sa.GetRefund() != 0 {
		t.Fatal("fresh refund not zero")
	}
	sa.AddRefund(100)
	sa.AddRefund(50)
	if sa.GetRefund() != 150 {
		t.Fatalf("GetRefund = %d, want 150", sa.GetRefund())
	}
	sa.SubRefund(20)
	if sa.GetRefund() != 130 {
		t.Fatalf("after SubRefund = %d, want 130", sa.GetRefund())
	}
	sa.SubRefund(9999) // clamp, no underflow
	if sa.GetRefund() != 0 {
		t.Fatalf("SubRefund underflow not clamped: %d", sa.GetRefund())
	}
	sa.AddRefund(77)
	sa.ResetTransient()
	if sa.GetRefund() != 0 {
		t.Fatalf("ResetTransient did not clear refund: %d", sa.GetRefund())
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./core/stateDB/ -run TestRefundAccounting`
Expected: FAIL — `AddRefund`/`SubRefund` are no-ops; `GetRefund` returns 0.

- [ ] **Step 3: Implement refund accounting**

In `core/stateDB/methods.go`, add a `refund uint64` field to the `StateAccount` struct (near the other transient fields `logs`/`suicided`, unexported, no json tag). Replace the stubs:

```go
func (sa *StateAccount) AddRefund(gas uint64) {
	sa.refund += gas
}
func (sa *StateAccount) SubRefund(gas uint64) {
	if gas > sa.refund {
		sa.refund = 0 // clamp; refund is not applied to the fee this phase (DB-C4 accounting-only)
		return
	}
	sa.refund -= gas
}
func (sa *StateAccount) GetRefund() uint64 {
	return sa.refund
}
```

In `ResetTransient` (`core/stateDB/methods.go`), add `sa.refund = 0` alongside the other transient resets.

- [ ] **Step 4: Run + build + commit**

Run: `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./core/stateDB/ -run TestRefundAccounting -v && GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go build ./...`
Expected: PASS, build OK.

```bash
git add core/stateDB/methods.go core/stateDB/methods_test.go
git commit -m "OB-109 DB-C4: refund accounting (AddRefund/SubRefund/GetRefund), reset per-tx

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 5: Wire PrepareAccessList at tx-start

**Files:**
- Modify: `blocks/evaluate.go` (`EvaluateSC`, before the entry `VM.Call`/`Create`)

**Interfaces:**
- Consumes: `State.PrepareAccessList(sender common.Address, dest *common.Address, precompiles []common.Address, txAccesses types.AccessList)` (Phase 1 Task 5), `vm.ActivePrecompiles(rules)` or the precompile address list for the active fork.

- [ ] **Step 1: Add the PrepareAccessList call**

In `EvaluateSC` (`blocks/evaluate.go`), after `State.ResetTransient()` and before the `if tx.TxData.Recipient == common.EmptyAddress()` dispatch, add:

```go
	// EIP-2929: warm the tx sender, recipient, and precompiles at tx start.
	var accessDest *common.Address
	if tx.TxData.Recipient != common.EmptyAddress() {
		r := tx.TxData.Recipient
		accessDest = &r
	}
	State.PrepareAccessList(tx.TxParam.Sender, accessDest, vm.ActivePrecompiles(VM.ChainRules()), nil)
```

Adapt the precompile-list expression to the real API: check how the active precompile set is obtained in `core/evm` (e.g. `vm.ActivePrecompiles(rules)` or a `PrecompiledAddresses...` list for `params.AllEthashProtocolChanges`). If `VM.ChainRules()`/`ActivePrecompiles` don't exist with those names, use the concrete precompile address slice the interpreter uses; if unclear, STOP and report rather than guessing. `txAccesses` is `nil` (this chain's txs carry no EIP-2930 access list).

- [ ] **Step 2: Build + run existing suites**

Run: `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go build ./... && GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./core/stateDB/ ./core/evm/ ./blocks/`
Expected: build OK; tests PASS (blocks EVM persistence may SKIP without a DB; the known `core/abi` `ExampleJSON` panic is unrelated).

- [ ] **Step 3: Commit**

```bash
git add blocks/evaluate.go
git commit -m "OB-110 DB-C5 followup: wire PrepareAccessList at EVM tx-start (EIP-2929 warm)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Final verification

- [ ] `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go build ./...` → exit 0.
- [ ] `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./core/stateDB/ ./core/evm/ ./blocks/` → PASS (known unrelated `core/abi` `ExampleJSON` panic aside).
- [ ] Update `SECURITY_AUDIT.md`: mark **DB-C2** addressed and **DB-C4** partially addressed (accounting only; real gas-economics fee/refund application deferred to "Phase 3b").

## Deferred (not in this plan)
- Real gas economics: gas-limit tx format, post-execution `gasUsed×gasPrice` fee, applied refunds (the remainder of DB-C4). Separate "Phase 3b" effort — changes the signed tx format, `Verify`, `BlockFee`, and every sender.

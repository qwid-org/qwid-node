# EVM Phase 3b — Per-Tx Contract Failure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A top-level contract call that fails with an EVM execution error becomes a per-tx failure (tx included, state/value reverted, size-based fee charged) instead of rejecting the whole block.

**Architecture:** In `EvaluateSCForBlock`, classify the error from `EvaluateSC`: EVM execution errors (revert, out-of-gas, invalid opcode, stack, etc.) become per-tx failures — record the tx and `continue`; all other (node/processing) errors keep today's block-fatal `return false`. Everything else already composes from Phase 3a (evm.go reverts value/storage on error; `ProcessTransaction` charges the size-based fee and skips the amount move for contract txs).

**Tech Stack:** Go 1.23.6, go-ethereum-derived `core/evm` (imported as `vm` in `blocks`).

## Global Constraints

- Build/test with `GOROOT=/home/wonabru/sdk/go1.24.0`. Example: `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./blocks/`.
- Branch `security-fixes`. Commit per task, `OB-xx (CONSENSUS)` convention. End messages with `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- **KEEP the size-based signed fee.** Do NOT change the tx format, signing, `Verify`, `CalcFee`, `GasUsage`, `ProcessTransaction`, or `isContractCallTx`. This phase changes ONLY the block-vs-per-tx failure decision.
- **Conservative classification:** only positively-identified EVM execution errors become per-tx failures; anything else stays block-fatal (`return false`). Never swallow a node/DB/processing error.
- **DEX path is out of scope:** do NOT change the `EvaluateSCDex` branch (`blocks/evaluate.go:229-233`).
- `core/evm` is imported as `vm` in `blocks/evaluate.go` (line 10). The sentinel EVM errors are at `core/evm/errors.go:26-38`; the struct-typed errors `*vm.ErrInvalidOpCode`, `*vm.ErrStackUnderflow`, `*vm.ErrStackOverflow` (pointer types, constructed with `&`) are at `core/evm/errors.go:47-72`.
- `errors` is NOT currently imported in `blocks/evaluate.go` — add it.

---

## File Structure

- `blocks/evaluate.go` — add `isEVMExecutionError(err error) bool`; add `"errors"` to imports; change the `EvaluateSCForBlock` error branch (`~:368-371`) from unconditional `return false` to per-tx-failure-vs-block-fatal.
- `blocks/evm_failure_test.go` (new) — classification test + reverting-bytecode tests.

---

## Task 1: `isEVMExecutionError` classification helper

**Files:**
- Modify: `blocks/evaluate.go` (add `"errors"` import; add the helper)
- Test: `blocks/evm_failure_test.go` (new)

**Interfaces:**
- Consumes: `vm.ErrExecutionReverted` … (sentinels, `core/evm/errors.go:26-38`), `*vm.ErrInvalidOpCode`/`*vm.ErrStackUnderflow`/`*vm.ErrStackOverflow` (`:47-72`).
- Produces: `func isEVMExecutionError(err error) bool`.

- [ ] **Step 1: Write the failing test**

Create `blocks/evm_failure_test.go`:

```go
package blocks

import (
	"errors"
	"fmt"
	"testing"

	vm "github.com/qwid-org/qwid-node/core/evm"
)

func TestIsEVMExecutionError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"reverted", vm.ErrExecutionReverted, true},
		{"out of gas", vm.ErrOutOfGas, true},
		{"code store oog", vm.ErrCodeStoreOutOfGas, true},
		{"depth", vm.ErrDepth, true},
		{"insufficient balance", vm.ErrInsufficientBalance, true},
		{"addr collision", vm.ErrContractAddressCollision, true},
		{"max code size", vm.ErrMaxCodeSizeExceeded, true},
		{"invalid jump", vm.ErrInvalidJump, true},
		{"write protection", vm.ErrWriteProtection, true},
		{"return data oob", vm.ErrReturnDataOutOfBounds, true},
		{"gas uint overflow", vm.ErrGasUintOverflow, true},
		{"invalid code", vm.ErrInvalidCode, true},
		{"nonce uint overflow", vm.ErrNonceUintOverflow, true},
		{"wrapped reverted", fmt.Errorf("evaluate: %w", vm.ErrExecutionReverted), true},
		{"struct invalid opcode", &vm.ErrInvalidOpCode{}, true},
		{"struct stack underflow", &vm.ErrStackUnderflow{}, true},
		{"struct stack overflow", &vm.ErrStackOverflow{}, true},
		{"nil", nil, false},
		{"plain db error", errors.New("db read failed"), false},
		{"wrapped non-evm", fmt.Errorf("boom: %w", errors.New("io")), false},
	}
	for _, c := range cases {
		if got := isEVMExecutionError(c.err); got != c.want {
			t.Errorf("%s: isEVMExecutionError = %v, want %v", c.name, got, c.want)
		}
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./blocks/ -run TestIsEVMExecutionError`
Expected: FAIL — `isEVMExecutionError` undefined (and possibly a compile error on the struct types if a name differs — see Step 3).

- [ ] **Step 3: Implement the helper**

First add `"errors"` to the import block in `blocks/evaluate.go` (it is not currently imported; `vm "github.com/qwid-org/qwid-node/core/evm"` already is).

Then add the helper (near the other package-level helpers in `evaluate.go`):

```go
// isEVMExecutionError reports whether err is an EVM execution failure — a
// contract-caused failure the sender pays for and the block includes — as
// opposed to a node/processing error, which must stay block-fatal. Anything
// not positively matched here is treated as block-fatal (the safe default).
func isEVMExecutionError(err error) bool {
	switch {
	case errors.Is(err, vm.ErrExecutionReverted),
		errors.Is(err, vm.ErrOutOfGas),
		errors.Is(err, vm.ErrCodeStoreOutOfGas),
		errors.Is(err, vm.ErrDepth),
		errors.Is(err, vm.ErrInsufficientBalance),
		errors.Is(err, vm.ErrContractAddressCollision),
		errors.Is(err, vm.ErrMaxCodeSizeExceeded),
		errors.Is(err, vm.ErrInvalidJump),
		errors.Is(err, vm.ErrWriteProtection),
		errors.Is(err, vm.ErrReturnDataOutOfBounds),
		errors.Is(err, vm.ErrGasUintOverflow),
		errors.Is(err, vm.ErrInvalidCode),
		errors.Is(err, vm.ErrNonceUintOverflow):
		return true
	}
	var opErr *vm.ErrInvalidOpCode
	if errors.As(err, &opErr) {
		return true
	}
	var suErr *vm.ErrStackUnderflow
	if errors.As(err, &suErr) {
		return true
	}
	var soErr *vm.ErrStackOverflow
	if errors.As(err, &soErr) {
		return true
	}
	return false
}
```

All sentinel names are verified present at `core/evm/errors.go:26-38`; the three struct types at `:47-72`. If the compiler reports any name mismatch, correct it against `core/evm/errors.go` (do not invent names).

- [ ] **Step 4: Run to verify it passes + build**

Run: `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./blocks/ -run TestIsEVMExecutionError -v && GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go build ./...`
Expected: PASS, build OK.

- [ ] **Step 5: Commit**

```bash
git add blocks/evaluate.go blocks/evm_failure_test.go
git commit -m "OB-111 EVM Phase 3b (CONSENSUS): isEVMExecutionError classifier (execution vs node error)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 2: Per-tx failure branch in `EvaluateSCForBlock`

**Files:**
- Modify: `blocks/evaluate.go` (the error branch at `~:368-371`)
- Test: `blocks/evm_failure_test.go`

**Interfaces:**
- Consumes: `isEVMExecutionError` (Task 1), `EvaluateSC`, `t.StoreToDBPoolTx(poolprefix)`, `t.OutputLogs`.

- [ ] **Step 1: Write the failing test (EvaluateSC returns an execution error for reverting code)**

Append to `blocks/evm_failure_test.go` (imports needed: `math/big` not required here; add `"github.com/qwid-org/qwid-node/account"`, `"github.com/qwid-org/qwid-node/common"`, `"github.com/qwid-org/qwid-node/logger"`, `"github.com/qwid-org/qwid-node/transactionsDefinition"`). Minimal reverting init code `0x60006000fd` (`PUSH1 0 PUSH1 0 REVERT`) reverts during contract construction, so a Create returns an execution error:

```go
func TestEvaluateSCRevertingCreateIsExecutionError(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	account.AccountsRWMutex.Lock()
	account.Accounts.AllAccounts = make(map[[common.AddressLength]byte]account.Account)
	account.AccountsRWMutex.Unlock()
	InitStateDB()

	var sender common.Address
	sender.ByteValue[0] = 0x90
	account.SetBalance(sender.ByteValue, 1_000_000)

	var tx transactionsDefinition.Transaction
	tx.TxParam.Sender = sender
	tx.TxData.Recipient = common.EmptyAddress() // Create
	tx.TxData.OptData = []byte{0x60, 0x00, 0x60, 0x00, 0xfd} // PUSH1 0 PUSH1 0 REVERT
	tx.GasUsage = 30000

	bl := Block{}
	_, _, _, _, err := EvaluateSC(tx, bl)
	if err == nil {
		t.Fatal("expected reverting Create to return an error")
	}
	if !isEVMExecutionError(err) {
		t.Fatalf("reverting Create error not classified as execution error: %v", err)
	}
	// The endowment/state must be reverted: sender balance intact.
	if account.GetBalance(sender.ByteValue) != 1_000_000 {
		t.Fatalf("sender balance changed on reverted Create: %d", account.GetBalance(sender.ByteValue))
	}
}
```

If constructing `EvaluateSC` inputs needs a field this omits (the implementer should check `EvaluateSC`'s use of `bl.GetHeader()`, `tx.TxParam.Nonce`, etc. and set the minimum needed for it not to nil-panic), set those minimal fields and note it in the report. If `EvaluateSC` cannot run without a fuller block/DB harness, fall back to exercising `isEVMExecutionError` with `vm.ErrExecutionReverted` directly for this classification and state the limitation — do not fake a pass.

- [ ] **Step 2: Run to verify it fails**

Run: `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./blocks/ -run TestEvaluateSCRevertingCreate`
Expected: FAIL only if the branch isn't reached — but this test targets `EvaluateSC` (Task-1 helper already exists), so it should PASS once inputs are correct. Its purpose is to establish the reverting-bytecode fixture the block-level assertion (Step 4) builds on; if it passes immediately, that is fine (it proves the fixture).

- [ ] **Step 3: Implement the per-tx failure branch**

In `blocks/evaluate.go`, replace the error branch (currently at `~:368-371`):

```go
	if err != nil {
		loggerMain.GetLogger().Println(err)
		return false, logs, map[[common.HashLength]byte]common.Address{}, map[[common.AddressLength]byte][]byte{}, map[[common.HashLength]byte][]byte{}
	}
```

with:

```go
	if err != nil {
		loggerMain.GetLogger().Println(err)
		if isEVMExecutionError(err) {
			// Phase 3b (CONSENSUS): per-tx contract failure. The EVM's internal
			// snapshot (evm.go Call/create) already reverted this call's value
			// transfer and storage writes. Include the tx (ProcessTransaction
			// charges its size-based fee; value stays with the sender), record
			// it as failed, register NO contract, and do NOT reject the block.
			t.OutputLogs = []byte(l)
			if serr := t.StoreToDBPoolTx(poolprefix); serr != nil {
				loggerMain.GetLogger().Println(serr)
				return false, logs, map[[common.HashLength]byte]common.Address{}, map[[common.AddressLength]byte][]byte{}, map[[common.HashLength]byte][]byte{}
			}
			continue
		}
		// Non-execution (node/processing) error: block-fatal, as before.
		return false, logs, map[[common.HashLength]byte]common.Address{}, map[[common.AddressLength]byte][]byte{}, map[[common.HashLength]byte][]byte{}
	}
```

Do NOT populate `rets`/`addresses`/`logs`/`optDatas` for the failed tx — a failed tx registers no contract and drives no downstream effects. `poolprefix`, `l`, and `t` are all in scope in this loop (the success path below uses the same `l` and `StoreToDBPoolTx(poolprefix)`).

- [ ] **Step 4: Write the block-level test (block NOT rejected on a reverting contract tx) — DB-gated**

`EvaluateSCForBlock(bl Block)` takes a `Block` by value and does NOT read txs directly: it iterates `bl.GetBlockTransactionsHashes()` and **loads each tx from the DB** via `transactionsDefinition.LoadFromDBPoolTx(common.TransactionPoolHashesDBPrefix[:], hash)`. So the block-level test must persist the tx first and reference it by hash — which needs a DB. Gate it with the same skip pattern `blocks/evm_persistence_test.go` uses (`t.Skipf` when the DB write fails). Append to `blocks/evm_failure_test.go` — the `Block` type and `EvaluateSCForBlock` are in package `blocks` (no import needed); the `account`/`common`/`logger`/`transactionsDefinition` imports were already added in Task 1 Step 1 and Task 2 Step 1:

```go
func TestEvaluateSCForBlockNotRejectedOnRevert(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	account.AccountsRWMutex.Lock()
	account.Accounts.AllAccounts = make(map[[common.AddressLength]byte]account.Account)
	account.AccountsRWMutex.Unlock()
	InitStateDB()

	var sender common.Address
	sender.ByteValue[0] = 0x91
	account.SetBalance(sender.ByteValue, 1_000_000)
	account.AddTransactionsSender(sender.ByteValue, common.Hash{}) // sender account must exist

	var tx transactionsDefinition.Transaction
	tx.TxParam.Sender = sender
	tx.TxData.Recipient = common.EmptyAddress()
	tx.TxData.OptData = []byte{0x60, 0x00, 0x60, 0x00, 0xfd} // PUSH1 0 PUSH1 0 REVERT
	tx.GasUsage = 30000
	// EvaluateSCForBlock/EvaluateSC dereference the fields below; set the minimum
	// so CalcHashAndSet succeeds and the loop reaches EvaluateSC. Read
	// transaction.go GetBytesWithoutSignature to see which fields are required
	// (e.g. Pubkey/GasPrice/Height/Nonce); set them to valid non-nil minimums.
	tx.GasPrice = 1
	if err := tx.CalcHashAndSet(); err != nil {
		t.Skipf("cannot hash tx (harness): %v", err)
	}
	if err := tx.StoreToDBPoolTx(common.TransactionPoolHashesDBPrefix[:]); err != nil {
		t.Skipf("DB not available: %v", err)
	}

	var bl Block
	bl.BaseBlock.BaseHeader.Height = 1        // EvaluateSCForBlock reads bl.GetHeader().Height
	bl.TransactionsHashes = []common.Hash{tx.Hash}

	ok, _, addresses, _, _ := EvaluateSCForBlock(bl)
	if !ok {
		t.Fatal("block wrongly rejected on a reverting contract tx (Phase 3b regression)")
	}
	hh := [common.HashLength]byte{}
	copy(hh[:], tx.Hash.GetBytes())
	if _, registered := addresses[hh]; registered {
		t.Fatal("failed tx must not register a contract address")
	}
}
```

Field paths to verify against source before finalizing: `bl.BaseBlock.BaseHeader.Height` (the height `GetHeader().Height` returns), `bl.TransactionsHashes` (the slice `GetBlockTransactionsHashes()` returns — confirmed `blocks/Block.go:52-53`), and the exact fields `CalcHashAndSet`→`GetBytesWithoutSignature` requires (`transactionsDefinition/transaction.go:141-159`). If `CalcHashAndSet` or `StoreToDBPoolTx` cannot be satisfied in a unit test (no DB, or the tx needs a real Pubkey/signature to hash), the test **skips cleanly** — that is acceptable. In that case the always-running coverage is `TestIsEVMExecutionError` (Task 1) + `TestEvaluateSCRevertingCreateIsExecutionError` (Step 1) plus reviewer inspection of the 6-line branch; document the skip in the report. Do NOT fabricate a passing block-level test.

- [ ] **Step 5: Run + build**

Run: `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./blocks/ -run 'TestEvaluateSC|TestIsEVMExecutionError' -v && GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go build ./...`
Expected: PASS, build OK.

- [ ] **Step 6: Commit**

```bash
git add blocks/evaluate.go blocks/evm_failure_test.go
git commit -m "OB-112 EVM Phase 3b (CONSENSUS): reverting contract call is a per-tx failure, not block-fatal

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Final verification

- [ ] `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go build ./...` → exit 0.
- [ ] `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./blocks/ ./core/evm/ ./core/stateDB/` → PASS (known unrelated `core/abi` `ExampleJSON` panic aside).
- [ ] Update `SECURITY_AUDIT.md`: the DB-C2 failure-semantics note (added in OB-110b) now says reverting contract calls are **per-tx failures** (tx included, size-based fee charged, value reverted), not block-fatal. Note the DEX path is still block-fatal (out of scope).

## Deferred (not in this plan)
- Real gas economics: gas-limit tx format, `gasUsed × gasPrice` fee, applied refunds, `BlockFee`/supply rework.
- Per-tx failure semantics for the DEX path (`EvaluateSCDex`), entangled with native DEX settlement.

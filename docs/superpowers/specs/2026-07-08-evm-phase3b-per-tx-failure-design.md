# EVM Phase 3b — Per-Tx Contract Failure (keep size-based fee)

**Date:** 2026-07-08
**Branch:** `security-fixes` (EVM work continues here)
**Source:** The Phase 3a final-review finding — a reverting top-level contract call currently rejects the **whole block**.
**Parent effort:** Full go-ethereum value-layer EVM. Phases 1 (persistence/correctness), 2 (balance bridge), and 3a (value transfer) are complete. This is **Phase 3b (targeted)**. The full gas-economics overhaul (gas-limit tx format, `gasUsed`-based fee, applied refunds) is a **separate, deferred effort** — explicitly NOT this spec.

## Context and decision

During Phase 3b design we chose the **targeted failure-model fix, keeping the size-based signed fee** — not the full gas-economics overhaul (which the exploration confirmed is a from-scratch build touching the tx format, all 16 senders, `Verify`, the two-pass fee flow, refunds, and `BlockFee`/supply, and whose real-gas-metering and per-tx-failure parts are coupled).

**The problem (real liveness bug today):** In `EvaluateSCForBlock` (`blocks/evaluate.go`), when `EvaluateSC` returns an error the function does `return false`, which makes `EvaluateSmartContracts` return false (`blocks/processBlock.go:448`), which makes `CheckBlockAndTransactions` (`:472-474`) and `CheckBlockAndTransferFunds` (`:524-526`) reject the **entire block**. So any block containing a tx whose top-level contract call reverts — including a normal Solidity `require()`/revert (`ErrExecutionReverted`) — is invalid and cannot be produced or accepted.

**The fix:** when the error is an **EVM execution failure**, do not reject the block. Record the tx as failed and `continue` to the next tx. The tx stays in the block; `ProcessTransaction` charges its size-based fee; its value and state stay reverted.

### Why the rest already composes (Phase 3a)

- `evm.go`'s `Call`/`create` already `Snapshot()` before the value transfer and `RevertToSnapshot` on error, so a failed call's **value transfer and storage writes are already rolled back** — value stays with the sender.
- Once the block is not rejected, `ProcessBlockTransfers → ProcessTransaction` runs for the failed tx like any other. Because it is a contract tx (`isContractCallTx` returns true independent of EVM success), `ProcessTransaction` **skips the native amount move and charges the size-based fee** — exactly "failed tx pays the fee, moves no value."
- Supply is conserved: the fee is removed to `BlockFee` (already in the supply invariant at `processBlock.go:535`); no value moves.
- Determinism: EVM execution is deterministic, so every node observes the same error and the same failed/succeeded outcome; producer and validators agree on block validity.

## Goals

1. A top-level contract call that fails with an EVM execution error becomes a **per-tx failure**: the tx is included, its state/value stay reverted, and its size-based fee is charged — the block is NOT rejected.
2. **Non-execution errors** (node/processing/DB errors) keep today's **block-fatal** behavior — they must not be silently swallowed.
3. A failed tx is observable (persisted with its logs; no contract registered for it).

## Non-goals (deferred / out of scope)

- Real gas economics: gas-limit tx format, `gasUsed × gasPrice` fee, applied refunds, `BlockFee`/supply rework. The separate big overhaul.
- The **DEX path** (`EvaluateSCDex`, delegated `n > 512`): its failures are entangled with native DEX settlement (coin/token transfers at `evaluate.go:247-256` that run only on the `err == nil` path). DEX failure semantics need separate treatment; this spec does NOT change the DEX branch (`evaluate.go:229-233`).
- Any change to the tx wire format, signing, `Verify`, `CalcFee`, or `GasUsage`.

## Design

### 1. Error classification (the crux)

Add a helper in `blocks` (the `core/evm` package is imported as `vm`):

```go
// isEVMExecutionError reports whether err is an EVM execution failure — a
// contract-caused failure the sender pays for and the block includes — as
// opposed to a node/processing error, which must stay block-fatal.
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
	// Struct-typed interpreter errors (opcode / stack). Verify the exact
	// exported names/types in core/evm before finalizing; use errors.As.
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

The sentinel errors are defined at `core/evm/errors.go:26-38`. The struct-typed errors (`ErrInvalidOpCode`, `ErrStackUnderflow`, `ErrStackOverflow`) live in the same package — the implementer must confirm their exact exported names/types; if any differs or does not exist, adjust the `errors.As` blocks accordingly (a non-existent type is simply omitted, since such an error would then fall through to block-fatal, which is the safe default).

**Conservative default:** anything NOT matched is treated as a non-execution error and stays block-fatal. This preserves safety for unexpected/system errors.

### 2. The `EvaluateSCForBlock` change

At `blocks/evaluate.go:341` the call is `l, ret, address, _, err := EvaluateSC(t, bl)`, followed by the token-registration block (guarded by `err == nil`, unchanged) and then the error check at `:368-371`:

```go
	if err != nil {
		loggerMain.GetLogger().Println(err)
		return false, logs, map[[common.HashLength]byte]common.Address{}, map[[common.AddressLength]byte][]byte{}, map[[common.HashLength]byte][]byte{}
	}
```

Replace that block with:

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

Notes:
- The failed branch persists the tx with `t.OutputLogs = []byte(l)` — the **same log source** the success path uses (`outputLogs := []byte(l)` at `:377`), so it is exactly as deterministic/consensus-safe as today's successful-tx logs (no new, possibly-divergent string is introduced).
- The failed branch deliberately does NOT populate `rets`/`addresses`/`logs`/`optDatas` (the success-only maps at `:388-391`) — a failed tx registers no contract and drives no downstream contract effects.
- `StoreToDBPoolTx` failure remains block-fatal (it is a genuine DB/system error).
- The `continue` lands in the same for-loop over block txs; the next tx proceeds against the (correctly reverted) state.

### 3. What is unchanged (and why it's correct)

- `ProcessTransaction` / `isContractCallTx` — untouched. A failed contract tx is still a contract tx, so the native amount move is skipped and the fee is charged. No code change; the correctness comes from no longer rejecting the block.
- `CheckBlockTransfers` affordability (`fee + amount`, `processBlock.go:250`) — untouched; it was already checked pre-execution and is conservative for a failed tx (which only spends the fee).
- `evm.go` snapshot/revert — untouched (Phase 3a).
- The DEX branch and all non-EVM paths — untouched.

### 4. Error handling / consensus

- Deterministic: the classification is a pure function of the error identity, which is deterministic across nodes.
- Consensus-affecting: blocks that were previously **rejected** (containing a reverting contract call) are now **valid** (tx included, fee charged). Labeled `(CONSENSUS)`; acceptable under the genesis reset.
- Safety net: any error not positively identified as an EVM execution error still rejects the block — no silent swallowing of node/DB/processing errors.

## Testing

- **`isEVMExecutionError` unit test:** returns true for `vm.ErrExecutionReverted`, `vm.ErrOutOfGas`, a wrapped `fmt.Errorf("...: %w", vm.ErrExecutionReverted)`, and (if present) a struct-typed opcode/stack error; returns **false** for `errors.New("db read failed")` and a plain `fmt.Errorf` with no EVM sentinel.
- **`EvaluateSC` returns an execution error for reverting code:** deploy/call minimal reverting bytecode `0x60006000fd` (`PUSH1 0 PUSH1 0 REVERT`) as a Create (`Recipient == EmptyAddress`, `OptData` = the bytecode) and assert `EvaluateSC` returns an err for which `isEVMExecutionError(err)` is true, and that native/EVM state is unchanged afterward (sender balance intact — the endowment revert).
- **Block-level (highest value):** construct a minimal `Block` whose single tx is a reverting-contract tx, run `EvaluateSCForBlock`, and assert it returns `true` (block NOT rejected) with the failed tx registering no contract (absent from the `addresses` map). If assembling a full `Block` + sender account in a unit test is impractical, cover the branch by asserting the classification + `EvaluateSC`-returns-execution-error and state the limitation; do not fake a pass.
- **Non-execution error stays block-fatal:** assert `isEVMExecutionError(errors.New("boom"))` is false (documenting that such an error keeps the `return false` path).

Tests run with `GOROOT=/home/wonabru/sdk/go1.24.0`.

## Files touched

- `blocks/evaluate.go` — add `isEVMExecutionError`; change the `EvaluateSCForBlock` error branch (`~:368-371`) to per-tx-failure-vs-block-fatal.
- Tests in `blocks/` (new `blocks/evm_failure_test.go`).

## Rollout / commit plan

Section-sized `OB-xx (CONSENSUS)` commits:
1. `isEVMExecutionError` helper + its unit test (classification, incl. wrapped-error and non-EVM cases).
2. The `EvaluateSCForBlock` per-tx-failure branch + reverting-bytecode test(s) (EvaluateSC-level, and block-level if feasible).

Not "done" until `blocks` builds and its tests pass, and `SECURITY_AUDIT.md`'s DB-C2 failure-semantics note (added in OB-110b) is updated to reflect that reverting contract calls are now per-tx failures rather than block-fatal.

## Deferred (explicitly not in this plan)
- Real gas economics: gas-limit tx format, `gasUsed × gasPrice` fee, applied refunds (EIP-3529), `BlockFee`/supply rework. The large protocol overhaul.
- Per-tx failure semantics for the **DEX** path (entangled with native DEX settlement).

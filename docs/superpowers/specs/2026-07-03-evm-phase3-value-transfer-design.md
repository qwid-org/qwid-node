# EVM Phase 3a — Value Transfer (DB-C2)

**Date:** 2026-07-03
**Branch:** `security-fixes` (EVM work continues here)
**Source:** `SECURITY_AUDIT.md` DB-C2 (and the residual of DB-C4), reinterpreted against the actual architecture.
**Parent effort:** Full go-ethereum value-layer EVM. Phase 1 (persistence + correctness) and Phase 2 (balance bridge) are complete. This is **Phase 3a**. The full gas-economics overhaul (real post-execution gas + fee, DB-C4) is a **separate deferred effort** ("Phase 3b"), not this spec.

## Context and decisions

Phase 2 bridged the EVM balance methods to native `account.Accounts` balances (journaled). Phase 3a re-enables EVM value transfer so contracts can move QWD, backed by that bridge. Two decisions were settled during design:

- **Gas model:** KEEP the existing size-based, sender-signed fee (`CalcFee = GasPrice × GasUsageEstimate`). EVM gas remains an execution step-limiter (DoS bound) with no effect on the fee. Real go-ethereum gas economics (gas limit + post-execution fee + applied refunds) is deferred — it would change the signed tx format, `Verify`, `BlockFee`, and every sender.
- **Top-level value reconciliation:** The EVM owns contract-tx value. For a contract-call tx, `tx.Amount` becomes the EVM entry value and moves via the EVM; `ProcessTransaction` skips the native Amount move for contract txs (fee only). Plain (non-contract) transfers stay entirely native.

### Ground truth (current flow, from code exploration)

- **Native mover:** for a plain (non-delegated) tx, value moves ONLY in `blocks/processTransaction.go` `ProcessTransaction` `else` branch: `AddBalance(sender, -amount)` (`:297`), `AddBalance(recipient, +amount)` (`:302`), `AddBalance(sender, -fee)` (`:308`). Contract-call txs (OptData present, non-delegated recipient) currently take this same `else` branch, so their Amount moves natively.
- **EVM entry value is hardcoded 0:** `EvaluateSC` calls `VM.Create(..., new(big.Int).SetInt64(0), nonce)` (`blocks/evaluate.go:418`) and `VM.Call(..., new(big.Int).SetInt64(0))` (`:426`).
- **Hooks disabled:** `BlockContext.CanTransfer/Transfer` are `nil` (`evaluate.go:372-373`, `:459-460`, `:517-518`). In `core/evm/evm.go`, `Call` has commented `CanTransfer` (`:174-176`) and `Transfer` (`:196`); `create` has commented `CanTransfer` (`:412-414`) and `Transfer` (`:436`); **`CallCode` has a LIVE `CanTransfer` call (`:263`) that nil-derefs today.** Types: `CanTransferFunc func(StateDB, common.Address, *big.Int) bool` (`evm.go:35-36`), `TransferFunc func(StateDB, common.Address, common.Address, *big.Int)` (`evm.go:37-38`).
- **Two-pass order in `CheckBlockAndTransferFunds`:** `CheckBlockTransfers` (overspend check on a local map copy; verifies `total_amount = fee + amount` affordability, `processBlock.go:244/249/303`) → `EvaluateSmartContracts` (`:524`, runs the EVM, real state mutations) → `ProcessBlockTransfers` → `ProcessTransaction` (`:572`, native apply of fee/amount).
- **Refunds:** `AddRefund`/`SubRefund`/`GetRefund` are stubs (`core/stateDB/methods.go:195-203`); the gas tables call them (no-op) and `GetRefund` is never consumed. `leftOverGas` is discarded (`evaluate.go:308`, `:339-340` TODO).

## Goals

1. Re-enable EVM value transfer (`CanTransfer`/`Transfer`) backed by Phase 2's native bridge, for internal calls and (via #2) top-level value. Fix the `CallCode` nil-deref.
2. Give payable contracts a correct top-level `msg.value == tx.Amount` by routing contract-tx value through the EVM and skipping the native Amount move for contract txs.
3. Ensure a failed top-level contract call rolls back its value transfer (snapshot/revert) while the fee is still charged.
4. Implement `AddRefund`/`SubRefund`/`GetRefund` accounting (correct values), documented as not applied to the fee.
5. Wire `PrepareAccessList` at tx-start.

## Non-goals (deferred)

- Real gas economics: gas-limit tx format, post-execution `gasUsed × gasPrice` fee, applied refunds (DB-C4 "users overcharged"). This is the separate Phase 3b effort.
- Changing the tx wire format, signing, `Verify`, `BlockFee`, or any sender.

## Design

### 1. Value hooks (`blocks/evaluate.go`, backed by Phase 2)

Add package-level functions in `blocks` (they use the Phase 2 `stateDB` bridge, which already mutates native balances + journals):

```go
func evmCanTransfer(db vm.StateDB, addr common.Address, amount *big.Int) bool {
	return db.GetBalance(addr).Cmp(amount) >= 0
}
func evmTransfer(db vm.StateDB, from, to common.Address, amount *big.Int) {
	db.SubBalance(from, amount)
	db.AddBalance(to, amount)
}
```

Install them in every `vm.BlockContext` (replace the three `CanTransfer: nil, Transfer: nil` sites). Un-comment the `CanTransfer`/`Transfer` calls in `core/evm/evm.go` `Call` (`:174-176`, `:196`) and `create` (`:412-414`, `:436`). The `CallCode` live call (`:263`) now resolves against a real hook. `DelegateCall`/`StaticCall` remain value-less (unchanged).

`GetBalance`/`SubBalance`/`AddBalance` are the Phase 2 native-bridged methods; `evmTransfer` therefore moves real QWD and is journaled, so `RevertToSnapshot` restores both sides.

### 2. Top-level `msg.value` (EVM owns contract-tx value)

- **Pass the value:** in `EvaluateSC`, replace the hardcoded `new(big.Int).SetInt64(0)` entry value with the tx amount — `big.NewInt(tx.TxData.Amount)` — for both the `VM.Call` (`:426`) and `VM.Create` endowment (`:418`) paths. (DEX/view paths keep value 0.)
- **Skip the native Amount move for contract txs:** in `ProcessTransaction` `else` branch (`processTransaction.go:279-317`), detect a contract-call tx (`len(tx.TxData.OptData) > 0`) and, for those, deduct the fee only (`AddBalance(sender, -fee)`) — skip the `AddBalance(sender, -amount)` / `AddBalance(recipient, +amount)` pair, because the EVM already moved `Amount`. Plain transfers (no OptData) are unchanged.
- **Consistency of the "contract tx" predicate:** the value is moved by the EVM iff `EvaluateSCForBlock` routes the tx to `EvaluateSC` (i.e. non-delegated recipient with OptData). `ProcessTransaction`'s skip condition MUST match exactly the same predicate the EVM dispatch uses, or value is moved zero or two times. Define one shared helper `isContractCallTx(tx) bool` used by both the dispatch decision and the ProcessTransaction guard.

### 3. Snapshot / revert around the top-level call (must get right)

`EvaluateSC` runs the EVM during the check-flow (before `ProcessTransaction`). A failed top-level call (revert/out-of-gas/error) must not move value. Implement:

- Take `snap := State.Snapshot()` immediately before the entry `VM.Call`/`VM.Create`.
- If the call returns an error (or the EVM signals revert), `State.RevertToSnapshot(snap)` — this rolls back the journaled value transfer (and any storage writes) so `Amount` is NOT moved.
- The fee is deducted by `ProcessTransaction` regardless (Ethereum semantics: a failed tx pays its cost but moves no value). Since the fee here is the fixed size-based fee, no change is needed there.
- Affordability: `CheckBlockTransfers` already verifies `fee + amount` up front on the pre-execution balances, so the EVM `CanTransfer` (balance ≥ value) and the later native fee deduction cannot both be starved — the sender was verified to afford `fee + amount`.
- **Verify existing evm.go snapshot behavior first (implementation note):** go-ethereum's `Call`/`create` typically take their own `StateDB.Snapshot()` and `RevertToSnapshot` on error, which would already roll back the value transfer. Before adding the `EvaluateSC`-level snapshot, check whether the ported `core/evm/evm.go` `Call`/`create` already snapshot+revert around the (now un-commented) `Transfer`. If they do, the top-level value is already protected and the extra `EvaluateSC` snapshot is redundant (keep it only if the port does NOT revert the caller-side transfer on failure). Do not double-handle — a redundant snapshot/revert of already-reverted state is harmless but the plan should pick one owner of top-level revert and test it.

### 4. Refund accounting (DB-C4, accounting-only)

Implement in `core/stateDB/methods.go`:

```go
func (sa *StateAccount) AddRefund(gas uint64)  { sa.refund += gas }
func (sa *StateAccount) SubRefund(gas uint64)  { if gas > sa.refund { sa.refund = 0; return }; sa.refund -= gas }
func (sa *StateAccount) GetRefund() uint64      { return sa.refund }
```

`refund uint64` is a transient field, reset by `ResetTransient` (per-tx) and never persisted. It is a simple counter — NOT journaled — because `GetRefund` is not consumed by the fee this phase, so an intra-tx revert leaving a stale refund count has no observable effect (the count is discarded at the next `ResetTransient`). Document that the value is tracked for the future gas-economics effort but is not applied to any fee now.

### 5. `PrepareAccessList` at tx-start

In `EvaluateSC`, before the entry `VM.Call`/`Create`, call `State.PrepareAccessList(sender, &dest, precompiles, txAccessList)` where `sender`/`dest` are the tx sender/recipient, `precompiles` is the active precompile set, and `txAccessList` is empty (this chain's txs carry no EIP-2930 access list). This warms sender/dest/precompiles per EIP-2929. Effect is gas-cosmetic this phase (size-based fee) but corrects execution semantics.

### 6. Data flow summary

- Plain transfer (no OptData): native only, unchanged.
- Contract-call tx with value: overspend-checked for `fee+amount` → EVM snapshot → EVM `Transfer` moves `Amount` (sender→contract, journaled) and runs code; on failure, revert to snapshot (Amount not moved) → `ProcessTransaction` deducts `fee` only. Supply conserved (Amount stays within accounts; fee removed to `BlockFee`).
- Internal contract call with value: EVM `Transfer` moves value, journaled; never touches `ProcessTransaction`.

### 7. Error handling / consensus

- `CanTransfer` guards insufficient balance → the EVM call returns `ErrInsufficientBalance` and reverts; no partial move.
- Deterministic: balance checks/moves and snapshot/revert are order-independent across nodes.
- Consensus-affecting: contract-tx value now moves via the EVM and `ProcessTransaction` changes for contract txs. Labeled `(CONSENSUS)`; acceptable under the genesis reset.

## Testing

- **Internal transfer + revert:** a contract that sends value to an address moves it; a call that reverts after sending restores balances.
- **Top-level `msg.value`:** a payable contract sees `msg.value == tx.Amount`; the contract's balance increases by `Amount`; sender decreases by `Amount + fee`.
- **No double-move:** for a contract-call tx, total sender debit == `Amount + fee` (not `2·Amount + fee`); assert `GetSupplyInAccounts` conserved.
- **Insufficient balance:** `CanTransfer` false → call reverts, `Amount` not moved, fee still charged.
- **Failed contract call:** value reverted via snapshot, fee deducted.
- **`CallCode` with value:** no nil-panic (regression for the live `:263` hook).
- **Refund accounting:** `AddRefund`/`SubRefund`/`GetRefund` return correct values; reset per-tx by `ResetTransient`.

Tests run with `GOROOT=/home/wonabru/sdk/go1.24.0`. Contract-level tests may use a minimal deployed bytecode or exercise the value hooks/ProcessTransaction guard directly at the `blocks` level where a full opcode harness is impractical (state the limitation).

## Files touched

- `blocks/evaluate.go` — `evmCanTransfer`/`evmTransfer`, install hooks, pass `tx.Amount` as entry value, snapshot/revert around the top-level call, `PrepareAccessList`, `isContractCallTx` helper.
- `core/evm/evm.go` — un-comment `CanTransfer`/`Transfer` in `Call`/`create`; `CallCode` now safe.
- `blocks/processTransaction.go` — skip native Amount move for contract txs (fee only).
- `core/stateDB/methods.go` — `AddRefund`/`SubRefund`/`GetRefund` + `refund` field; `ResetTransient` resets it.
- Tests in `blocks/` and `core/stateDB/`.

## Rollout / commit plan

Section-sized `OB-xx (CONSENSUS)` commits:
1. Value hooks + install in BlockContext + un-comment evm.go Call/create + CallCode-safe test.
2. `isContractCallTx` helper; pass `tx.Amount` as entry value; `ProcessTransaction` skip-amount-for-contract-tx; top-level msg.value + no-double-move tests.
3. Snapshot/revert around the top-level call; failed-call-reverts-value test.
4. Refund accounting + `ResetTransient` reset + test.
5. `PrepareAccessList` wiring.

Not "done" until `core/stateDB`, `core/evm`, and `blocks` build and their tests pass.

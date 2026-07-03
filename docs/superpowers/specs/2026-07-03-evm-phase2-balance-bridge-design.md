# EVM Phase 2 — Balance Bridge (DB-C1)

**Date:** 2026-07-03
**Branch:** `security-fixes` (EVM work continues here)
**Source:** `SECURITY_AUDIT.md` DB-C1, reinterpreted against the actual architecture.
**Parent effort:** Full go-ethereum value-layer EVM (3 phases). This is **Phase 2 of 3**. Phase 1 (persistence + correctness) is complete (commits OB-91…OB-99).

## Context

Phase 1 made the EVM a persisted, correct compute layer. Its `stateDB.StateAccount` balance methods remain stubs: `GetBalance` returns 0, `AddBalance`/`SubBalance` are no-ops (`core/stateDB/methods.go`). Meanwhile QWD value lives in the native `account.Accounts` system (`account/accountsStates.go`): `int64` base units (8 decimals), persisted per height, guarded by `account.AccountsRWMutex`, mutated via `account.GetBalance`/`SetBalance` and `blocks.AddBalance`.

Phase 2 bridges the EVM balance methods to the native balances so contracts see and (in the SELFDESTRUCT case) move real QWD. It does **not** re-enable general value transfer (`msg.value`), gas pricing, or refunds — those are Phase 3.

### Who calls the EVM balance methods (established during design)

- `GetBalance` — **live**: `opBalance` (`BALANCE` opcode, `instructions.go:264`), `opSelfBalance` (`eips.go:83`), `opSelfdestruct` (`instructions.go:840`), and EIP-158 empty-account gas checks (`gas_table.go:429`, `operations_acl.go:235`).
- `AddBalance` — **live**: `opSelfdestruct` (`instructions.go:841`) credits the beneficiary with the self-destructing contract's balance.
- `SubBalance` — callers are the disabled `Transfer` path (Phase 3); effectively dormant in Phase 2, but implemented for completeness and for SELFDESTRUCT supply-neutrality.

## Goals

1. `GetBalance` returns the authoritative native balance (so `address.balance` / `SELFBALANCE` are correct).
2. `AddBalance`/`SubBalance` mutate native balances, journaled for revert (integrating with the Phase 1 change journal).
3. `Empty` (EIP-161) considers balance (Phase 1 deferred this).
4. SELFDESTRUCT is **supply-neutral** (moves the contract's balance to the beneficiary without inflating total supply).

## Non-goals (deferred to Phase 3)

- Re-enabling `CanTransfer`/`Transfer` in `evm.go` (general `msg.value` transfer) — DB-C2.
- Real gas pricing / debiting gas from balances / refunds — DB-C4.
- Wiring `PrepareAccessList` at tx-start (carried over from Phase 1 deferral).

## Design

### 1. Balance representation and conversion

- Native balance is `int64` base units (QWD, 8 decimals). EVM balances are `*big.Int` **1:1 in base units** — no Ethereum 18-decimal / wei rescaling. A contract reading `address(x).balance` receives the base-unit count.
- `GetBalance(a common.Address) *big.Int` returns `big.NewInt(account.GetBalance(a.ByteValue))`.
- Conversion helper `bigToBaseUnits(amount *big.Int) (int64, bool)` returns the `int64` value and an `ok` flag that is false when `amount` exceeds `int64` range (defensive; unreachable with valid QWD amounts, since total supply < `math.MaxInt64`).

### 2. Write path with journaling

`AddBalance`/`SubBalance` cannot return errors (the `StateDB` interface signatures are fixed). Sequence for each:

1. Convert `amount` to `int64` via `bigToBaseUnits`. If `!ok` (out of `int64` range), log a warning and saturate (`AddBalance`: clamp result to `math.MaxInt64`; `SubBalance`: clamp result floor to `0`) rather than silently wrapping. This path is unreachable with valid balances; it exists so malformed state degrades safely instead of corrupting.
2. Read the current native balance `prev := account.GetBalance(a.ByteValue)`.
3. Compute `next` (`prev + amount` for Add, `prev - amount` for Sub) with saturation: Add clamps at `math.MaxInt64`; Sub floors at `0` (a native balance must never go negative — that would corrupt the supply invariant).
4. Append a `balanceChange{addr: a.ByteValue, prev: prev}` entry to the journal and bump `SnapShotNum` (same pattern as `slotChange`/`suicideChange`), so `RevertToSnapshot` restores `prev` via `account.SetBalance`.
5. Write `account.SetBalance(a.ByteValue, next)`.

New journal entry in `core/stateDB/journal.go`:

```go
type balanceChange struct {
	addr [common.AddressLength]byte
	prev int64
}
func (c balanceChange) revert(sa *StateAccount) {
	account.SetBalance(c.addr, c.prev)
}
```

`balanceChange` is transient (part of the journal, never persisted). Note: `RevertToSnapshot`/`revert` now mutate native `account.Accounts`, so a revert restores native balances — correct, since the forward mutation also touched native state.

### 3. `Empty` (EIP-161)

`Empty(a)` becomes `nonce==0 && len(code)==0 && GetBalance(a).Sign()==0`. This corrects the Phase 1 placeholder that ignored balance, so the EIP-158/161 empty-account gas checks (`gas_table.go:429`, `operations_acl.go:235`) behave correctly.

### 4. SELFDESTRUCT supply-neutrality

`opSelfdestruct` (`core/evm/instructions.go:840-841`) currently reads the contract balance and `AddBalance(beneficiary, balance)`, but Phase 1's `Suicide` only *marks* the account — it never zeroes the contract's balance. With the write bridge live, this would inflate supply (beneficiary gains `b`; contract still holds `b`).

Fix: make the transfer supply-neutral in `opSelfdestruct` — zero the contract's balance as part of crediting the beneficiary:

```go
balance := interpreter.evm.StateDB.GetBalance(scope.Contract.Address())
interpreter.evm.StateDB.AddBalance(beneficiaryAddr, balance)
interpreter.evm.StateDB.SubBalance(scope.Contract.Address(), balance) // supply-neutral
interpreter.evm.StateDB.Suicide(scope.Contract.Address())
```

Edge case: self-destruct to self (beneficiary == contract). Order matters — credit then debit the same address nets to zero, which is the go-ethereum result (self-destruct to self burns the balance). Compute `balance` once up front (as above) so the paired Add/Sub cancel exactly.

### 5. Concurrency / lock ordering

The EVM executes under `blocks.StateMutex`. `GetBalance`/`AddBalance`/`SubBalance` call `account.GetBalance`/`SetBalance`, which take `account.AccountsRWMutex`. The ordering `StateMutex → AccountsRWMutex` is already established (`blocks.EvaluateSCForBlock` holds `StateMutex` and calls `blocks.AddBalance` for DEX). Verify during implementation that no code path takes `AccountsRWMutex` and then enters the EVM (`StateMutex`); if one exists it must be reconciled. `account.SetBalance`/`GetBalance` are self-locking, so the bridge methods must NOT hold `AccountsRWMutex` themselves — they call the self-locking accessors.

### 6. Data flow

- Contract reads `address.balance` → `GetBalance` → native balance (read-only, no journal).
- Contract self-destructs → `AddBalance(beneficiary)` + `SubBalance(contract)` → two journaled native mutations, net supply-neutral; revert (on a failed enclosing call) restores both.
- On `RevertToSnapshot`, `balanceChange.revert` restores prior native balances.

### 7. Consensus impact

EVM balance writes now change native `account.Accounts` state and participate in `GetSupplyInAccounts`. SELFDESTRUCT moving value is a consensus-visible behavior change. Acceptable under the accepted genesis reset. All such changes are labeled `(CONSENSUS)` in commits.

### 8. Error handling

- Out-of-`int64` amounts: saturate + log (never wrap/corrupt). Unreachable with valid balances.
- `SubBalance` below zero: floor at 0 + log (a native balance must not go negative).
- No new panics; contract-triggered conditions degrade to safe saturation.

## Testing

- `GetBalance` reflects the native balance (set a native balance, assert `GetBalance` returns it as `big.Int`).
- `AddBalance`/`SubBalance` mutate the native balance and are reverted by `RevertToSnapshot` (set balance, snapshot, add, assert changed, revert, assert restored).
- **SELFDESTRUCT conserves total supply**: a `blocks`-level test — fund a contract, self-destruct to a beneficiary, assert beneficiary balance increased by exactly the contract's prior balance AND the contract balance is 0 AND `GetSupplyInAccounts` is unchanged.
- Self-destruct to self burns the balance (nets to zero, no inflation).
- `Empty` returns false for a zero-nonce/zero-code account that has a non-zero balance.
- Defensive: an out-of-int64 `AddBalance` saturates and does not wrap.

Tests run with `GOROOT=/home/wonabru/sdk/go1.24.0`.

## Files touched

- `core/stateDB/methods.go` — `GetBalance`/`AddBalance`/`SubBalance` bridge, `Empty` update, `bigToBaseUnits` helper.
- `core/stateDB/journal.go` — `balanceChange` entry.
- `core/stateDB/methods_test.go` — balance/revert/Empty tests.
- `core/evm/instructions.go` — `opSelfdestruct` supply-neutrality.
- `blocks/` — a supply-conservation integration test.

Note: `core/stateDB/methods.go` already imports `account`; the journal (`journal.go`) will need to import `account` for `balanceChange.revert`.

## Rollout / commit plan

Section-sized `OB-xx (CONSENSUS)` commits:
1. `GetBalance` read bridge + `Empty` EIP-161 + tests.
2. `AddBalance`/`SubBalance` write bridge + `balanceChange` journal + revert tests.
3. `opSelfdestruct` supply-neutrality + supply-conservation integration test.

Not "done" until `core/stateDB`, `core/evm`, and `blocks` build and their tests pass.

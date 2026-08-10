# EVM Phase 1 — State Persistence + Correctness Fixes

**Date:** 2026-07-03
**Branch:** `security-fixes` (EVM work continues here)
**Source:** `SECURITY_AUDIT.md` Section 5 (DB-*), reinterpreted against the actual architecture.
**Parent effort:** Full go-ethereum value-layer EVM (3 phases). This is **Phase 1 of 3**.

## Context

The EVM runs during block processing (`blocks.EvaluateSCForBlock` → `core/evm` `VM.Create`/`VM.Call`) against a single process-global `stateDB.StateAccount` (`blocks.State`). Findings and architecture established during design:

- **EVM state is never persisted to RocksDB.** `blocks.State` is in-memory only; only derived artifacts (output logs, contract addresses/code) are persisted. Contract code, storage slots, nonces, and token balances are lost on restart and can diverge between nodes.
- **QWD value is native** (`account.Accounts`, persisted, authoritative). Tokens are ERC-20 EVM contracts (balances in contract storage). DEX and staking are native Go. Value transfer in the EVM is currently disabled.
- **`ecrecover` is meaningless** — the chain uses post-quantum signatures (Falcon-512/MAYO-5), not secp256k1.
- Already implemented and working in `core/stateDB/methods.go`: `GetState/SetState`, `GetCode/SetCode`, nonces, `Snapshot`, `CreateAccount`, `Exist`. Genuinely stubbed or buggy: balances (Phase 2/3), refunds (Phase 3), access-list, `AddLog`, `Suicide`, and `RevertToSnapshot` (key-corruption bug).

Phase 1 makes the EVM a **persisted, correct compute layer**. It does not touch balances/value/gas (Phases 2–3). Phase 1 is foundational: persistence unblocks the later phases, and the correctness fixes are needed regardless of the value model.

## Goals

1. Persist EVM-owned state to RocksDB and restore it on startup, mirroring the native account persistence pattern.
2. Fix the genuine EVM correctness bugs that exist independent of the value model.
3. Add the EVM test coverage that is currently almost entirely absent.

## Non-goals (deferred to later phases)

- Bridging EVM `GetBalance/AddBalance/SubBalance` to native balances (Phase 2).
- Re-enabling value transfer, real gas pricing, and refunds (Phase 3).
- Binary (non-JSON) state serialization (later optimization).

## Design

### 1. State persistence (mirrors `account.StoreAccounts`/`LoadAccounts`)

The native system stores the whole account map per height under `AccountsDBPrefix+height` as one marshaled blob, and loads the latest (or a specific) height (`account/accountsStates.go`). The EVM persistence mirrors this exactly, for consistency and free height-based rollback.

- **`stateDB.StateAccount.Marshal() []byte` / `Unmarshal([]byte) error`** covering the EVM-owned, currently-lost state: `Codes`, `CodeHashes`, `StatesHashes` (storage slots), `Nonces`, `States` (preimages), `Accounts` (contract accounts), `Balances` (token balances), `Tokens`. Encoding is JSON (correctness first; matches existing complex-struct marshaling in the codebase). Native QWD balances are **not** included — they persist via the account system.
- **`StoreEVMState(height int64) error`** — marshal `blocks.State` and `Put` under a new 2-byte `common.EVMStateDBPrefix + GetByteInt64(height)`. Prefix value `{'E','V'}` (free against existing BI/TT/AC/SA/DA/PK/HB/BH and the output-log/address prefixes).
- **`LoadEVMState(height int64) error`** — `Get` and `Unmarshal`; `height < 0` loads the latest stored height (an EVM analogue of `LastHeightStoredInAccounts`, reusing the O(log n) search added in AC-M8).
- **Call sites:** `StoreEVMState` is called wherever `StoreAccounts` is called on block finalize (`services/nonceService/onmessage.go` block-success path; genesis in `genesis/genesis.go`). `LoadEVMState(-1)` is called at startup where the blockchain/accounts are loaded (`InitStateDB` and/or `services` load path), replacing the empty-state initialization.
- **Rollback:** `services/helperReset.go` already reverts EVM state in memory via `RevertToSnapshot` + `CleanupContractsAfterHeight`; add `LoadEVMState(targetHeight)` so a reset also restores persisted EVM state, keeping the in-memory and on-disk views consistent.

Prefix registration: add `EVMStateDBPrefix = [2]byte{'E', 'V'}` to `common/const.go`, distinct from all existing prefixes (BI/TT/AC/SA/DA/PK/HB/BH and the output-log/address prefixes).

### 2. Correctness fixes

Each is independently testable and lives in `core/stateDB` or `core/evm`.

- **`RevertToSnapshot` (DB-H3, `methods.go`):** the current journal keys storage restores by the preimage *value* hash instead of the original slot key, corrupting storage on revert. Replace the snapshot mechanism with an explicit journal of reversible operations. Minimum: record `(address, slotKey, previousValue)` on each `SetState` and, on revert to snapshot `n`, replay the journal entries after `n` in reverse, restoring each slot to `previousValue`. Also revert code/nonce/suicide changes recorded after `n`. `Snapshot()` returns the current journal length.
- **`AddLog` (DB-C6, `methods.go`):** append the `*types.Log` to a per-execution slice on `StateAccount`; expose it so `EvaluateSC` can collect logs (feeding the existing `OutputLogs` persistence rather than being discarded). Logs are reverted with snapshots.
- **`Suicide`/`HasSuicided` (DB-H2, `methods.go`):** mark the address destroyed (record in a `suicided` set), zero its code/storage view, and journal it for revert; `HasSuicided` reflects the set. Actual deletion applied on commit/finalize.
- **Access list (DB-C5, `methods.go`):** implement EIP-2929 warm/cold tracking — `PrepareAccessList` seeds sender/recipient/precompiles/tx-access-list; `AddressInAccessList`/`SlotInAccessList` reflect real membership; `AddAddressToAccessList`/`AddSlotToAccessList` add and are journaled for revert. (Affects gas only, which is cosmetic until Phase 3, but correctness matters for determinism.)
- **Memory (DB-H7/H8, `core/evm/memory.go`):** `GetPtr`/`GetCopy` take signed `int64` offsets; guard against negative offset/size before slicing. `Set`/`Set32` currently `panic` on empty store — return an error or grow safely instead of panicking (a crafted contract must not crash the node).
- **`opCreate` nonce (DB-M2, `core/evm/instructions.go`):** `Create` is called with a hardcoded nonce `23`, causing address collisions. Pass the caller account's real nonce (from `StateDB.GetNonce`), matching go-ethereum `CreateAddress` semantics.
- **ABI panics (DB-M6/M7, `core/abi/type.go`, `core/abi/pack.go`):** `GetType`/`packNum` `panic` on unexpected kinds; return an error up the `Unpack`/`Pack` path so malformed ABI data cannot crash the node.
- **`dataCopy` precompile (DB-M5, `core/evm/contracts.go`):** returns the input slice directly; return a copy so callers cannot mutate shared memory.
- **`ecrecover` (DB-C3, `core/evm/contracts.go`):** secp256k1 recovery is meaningless on this chain. Make it fail loudly — return an error / empty result rather than a deterministic garbage address — so contracts that depend on it cannot silently misbehave. Keep the precompile registered at `0x01` for ABI compatibility.
- **`Empty` (EIP-161) and `DB-H1`:** `Empty` currently ignores balance; align it once balances exist (note the coupling to Phase 2). For concurrency, the StateDB is externally serialized by `blocks.StateMutex` during execution; document that contract, and add internal guards only on accessors used outside the execution lock (persistence entry points), avoiding double-lock with `StateMutex`.

### 3. Data flow

- **Execution (unchanged):** `EvaluateSCForBlock` locks `StateMutex`, runs `VM.Create/Call` against `blocks.State`, collects logs/addresses.
- **New commit step:** after `EvaluateSmartContracts` succeeds for a block, `StoreEVMState(height)` persists the state alongside `StoreAccounts(height)`.
- **New load step:** at startup, `LoadEVMState(-1)` restores the latest persisted EVM state before serving/syncing.
- **Revert:** on chain reset to height `h`, `LoadEVMState(h)` restores on-disk state and the in-memory `RevertToSnapshot`/cleanup aligns the memory view.

### 4. Error handling

- Persistence errors are returned up the block-finalize path and logged; a failed `StoreEVMState` fails block commit (consistent with `StoreAccounts` behavior).
- Contract-triggered conditions (bad memory offsets, malformed ABI, `ecrecover` misuse) become EVM errors / reverts, never node panics.

### 5. Testing

The EVM has almost no tests today. Phase 1 adds, under `core/stateDB` and `blocks`:

- **Persist→load round-trip:** populate a `StateAccount` (codes, storage, nonces, token balances, tokens), `Marshal`→`Unmarshal`, assert equality.
- **End-to-end persistence:** deploy a small ERC-20, call `transfer`, `StoreEVMState`, clear in-memory state, `LoadEVMState`, assert storage/balances survived.
- **`RevertToSnapshot`:** set multiple slots across snapshots, revert, assert each slot restored to the correct prior value (the DB-H3 regression test).
- **`AddLog`:** emit LOG opcodes, assert logs captured and reverted with snapshots.
- **`Suicide`:** self-destruct a contract, assert `HasSuicided` and post-commit deletion.
- **Memory bounds:** negative/oversized offsets return errors, no panic.
- **ABI:** malformed input returns an error, no panic.

Tests run with `GOROOT=/home/wonabru/sdk/go1.24.0` (CGO packages build in this environment).

## Consensus impact

`opCreate` nonce, `RevertToSnapshot`, `Suicide`, and access-list changes alter execution results and/or contract addresses. Phase 1 is therefore consensus-affecting. This is acceptable given the genesis reset already accepted for AC-H2. Every such change is labeled `(CONSENSUS)` in its commit, consistent with the rest of this branch.

## Rollout / commit plan

Section-sized commits, `OB-xx` convention:
1. `Marshal/Unmarshal` + `StoreEVMState/LoadEVMState` + prefix + call-site wiring (persistence).
2. `RevertToSnapshot` journal redesign (+ `AddLog`, `Suicide` reverts).
3. Access-list (EIP-2929).
4. `core/evm` correctness (memory, opCreate nonce, dataCopy, ecrecover).
5. `core/abi` panic→error.
6. Tests (folded into each commit where practical; a dedicated end-to-end persistence test commit).

Not "done" until `core/stateDB`, `core/evm`, `core/abi`, and `blocks` build and their tests pass.

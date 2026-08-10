# EVM Phase 1 — State Persistence + Correctness Fixes — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Persist the EVM's RocksDB state and fix its correctness bugs, so contract state survives restarts/agrees across nodes and contract execution can no longer corrupt storage or crash the node.

**Architecture:** Mirror the native `account.StoreAccounts`/`LoadAccounts` height-keyed snapshot pattern for the EVM `stateDB.StateAccount`, add `StoreEVMState`/`LoadEVMState`, wire them into the same block-finalize/startup/reset points, and repair the stubbed/buggy `StateDB` and `core/evm`/`core/abi` methods.

**Tech Stack:** Go 1.23.6, RocksDB (via `database.MainDB`), go-ethereum-derived `core/evm`, `core/stateDB`, `core/abi`.

## Global Constraints

- Build/test with `GOROOT=/home/wonabru/sdk/go1.24.0` (avoids the local go1.25.6/go1.24.0 toolchain mismatch). Example: `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./core/stateDB/`.
- Work on branch `security-fixes`. Commit per task, `OB-xx` message convention. End commit messages with `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- Consensus-affecting changes (Tasks 3, 4, 5, 7's opCreate) must say `(CONSENSUS)` in the commit subject.
- Address type: `common.Address` has field `ByteValue [20]byte`; `common.AddressLength == 20`. Hash: `common.Hash` (32 bytes); `common.EmptyHash()` returns the zero hash.
- Persist only committed state; never serialize transient snapshot/journal fields.

---

## File Structure

- `common/const.go` — add `EVMStateDBPrefix = [2]byte{'E','V'}` (Task 1).
- `core/stateDB/persistence.go` (new) — `Marshal`/`Unmarshal`, `StoreEVMState`/`LoadEVMState`, `LastHeightStoredInEVMState` (Tasks 1–2).
- `core/stateDB/persistence_test.go` (new) — round-trip + store/load tests (Tasks 1–2).
- `core/stateDB/methods.go` — snapshot/journal redesign, `AddLog`, `Suicide`, access list (Tasks 3–5).
- `core/stateDB/journal.go` (new) — change-entry types for revert (Task 3).
- `core/stateDB/methods_test.go` (new) — revert/log/suicide/accesslist tests (Tasks 3–5).
- `core/evm/memory.go` — bounds guards (Task 6).
- `core/evm/memory_test.go` (new) — bounds tests (Task 6).
- `core/evm/instructions.go` — `opCreate` real nonce (Task 7).
- `core/evm/contracts.go` — `dataCopy` copy, `ecrecover` fail-loud (Task 7).
- `core/evm/contracts_test.go` (new) — precompile tests (Task 7).
- `core/abi/type.go`, `core/abi/pack.go` — panic→error (Task 8).
- `blocks/evaluate.go`, `services/nonceService/onmessage.go`, `genesis/genesis.go`, `services/helperReset.go` — wiring (Task 2).

---

## Task 1: EVM state serialization + round-trip test

**Files:**
- Modify: `common/const.go` (add prefix, near line 79)
- Create: `core/stateDB/persistence.go`
- Create: `core/stateDB/persistence_test.go`

**Interfaces:**
- Produces: `func (sa *StateAccount) Marshal() ([]byte, error)`, `func (sa *StateAccount) Unmarshal(b []byte) error`, `common.EVMStateDBPrefix [2]byte`.

- [ ] **Step 1: Add the DB prefix**

In `common/const.go`, after the `OutputAddressesHashesDBPrefix` line, add:

```go
	EVMStateDBPrefix                 = [2]byte{'E', 'V'}
```

- [ ] **Step 2: Write the failing round-trip test**

Create `core/stateDB/persistence_test.go`:

```go
package stateDB

import (
	"testing"

	"github.com/qwid-org/qwid-node/common"
)

func sampleState() StateAccount {
	sa := CreateStateDB()
	var a [common.AddressLength]byte
	a[0] = 0xAB
	sa.Codes[a] = []byte{0x60, 0x00, 0x60, 0x00}
	sa.CodeHashes[a] = common.Hash{0x11}
	sa.Nonces[a] = 7
	sa.StatesHashes[a] = map[common.Hash]common.Hash{{0x01}: {0x02}}
	sa.Balances[a] = map[[common.AddressLength]byte]int64{a: 500}
	sa.Tokens[a] = TokenInfo{Name: "Tok", Symbols: "TK", Decimals: 8}
	return sa
}

func TestStateMarshalRoundTrip(t *testing.T) {
	sa := sampleState()
	b, err := sa.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got StateAccount
	got = CreateStateDB()
	if err := got.Unmarshal(b); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	var a [common.AddressLength]byte
	a[0] = 0xAB
	if string(got.Codes[a]) != string(sa.Codes[a]) {
		t.Fatal("code mismatch")
	}
	if got.Nonces[a] != 7 {
		t.Fatalf("nonce mismatch: %d", got.Nonces[a])
	}
	if got.StatesHashes[a][common.Hash{0x01}] != (common.Hash{0x02}) {
		t.Fatal("storage slot mismatch")
	}
	if got.Balances[a][a] != 500 {
		t.Fatal("token balance mismatch")
	}
	if got.Tokens[a].Symbols != "TK" {
		t.Fatal("token info mismatch")
	}
}
```

- [ ] **Step 3: Run the test to confirm it fails**

Run: `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./core/stateDB/ -run TestStateMarshalRoundTrip`
Expected: FAIL / build error — `Marshal` undefined.

- [ ] **Step 4: Implement Marshal/Unmarshal**

Create `core/stateDB/persistence.go`:

```go
package stateDB

import (
	"encoding/json"

	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/database"
	"github.com/qwid-org/qwid-node/logger"
)

// persistedState is the subset of StateAccount written to disk. Transient
// snapshot/journal fields are intentionally excluded — they are execution-scoped
// and meaningless across a restart.
type persistedState struct {
	Accounts     map[[common.AddressLength]byte]account.Account                      `json:"accounts"`
	Codes        map[[common.AddressLength]byte][]byte                               `json:"codes"`
	CodeHashes   map[[common.AddressLength]byte]common.Hash                          `json:"codeHashes"`
	StatesHashes map[[common.AddressLength]byte]map[common.Hash]common.Hash          `json:"statesHashes"`
	Nonces       map[[common.AddressLength]byte]uint64                               `json:"nonces"`
	States       map[common.Hash][]byte                                              `json:"states"`
	Balances     map[[common.AddressLength]byte]map[[common.AddressLength]byte]int64 `json:"balances"`
	Tokens       map[[common.AddressLength]byte]TokenInfo                            `json:"tokens"`
}

func (sa *StateAccount) Marshal() ([]byte, error) {
	return json.Marshal(persistedState{
		Accounts:     sa.Accounts,
		Codes:        sa.Codes,
		CodeHashes:   sa.CodeHashes,
		StatesHashes: sa.StatesHashes,
		Nonces:       sa.Nonces,
		States:       sa.States,
		Balances:     sa.Balances,
		Tokens:       sa.Tokens,
	})
}

func (sa *StateAccount) Unmarshal(b []byte) error {
	var ps persistedState
	if err := json.Unmarshal(b, &ps); err != nil {
		return err
	}
	sa.Accounts = nonNilAccounts(ps.Accounts)
	sa.Codes = nonNilBytes(ps.Codes)
	sa.CodeHashes = nonNilHashes(ps.CodeHashes)
	sa.StatesHashes = nonNilStorage(ps.StatesHashes)
	sa.Nonces = nonNilNonces(ps.Nonces)
	sa.States = nonNilPreimages(ps.States)
	sa.Balances = nonNilBalances(ps.Balances)
	sa.Tokens = nonNilTokens(ps.Tokens)
	return nil
}

func nonNilAccounts(m map[[common.AddressLength]byte]account.Account) map[[common.AddressLength]byte]account.Account {
	if m == nil {
		return map[[common.AddressLength]byte]account.Account{}
	}
	return m
}
func nonNilBytes(m map[[common.AddressLength]byte][]byte) map[[common.AddressLength]byte][]byte {
	if m == nil {
		return map[[common.AddressLength]byte][]byte{}
	}
	return m
}
func nonNilHashes(m map[[common.AddressLength]byte]common.Hash) map[[common.AddressLength]byte]common.Hash {
	if m == nil {
		return map[[common.AddressLength]byte]common.Hash{}
	}
	return m
}
func nonNilStorage(m map[[common.AddressLength]byte]map[common.Hash]common.Hash) map[[common.AddressLength]byte]map[common.Hash]common.Hash {
	if m == nil {
		return map[[common.AddressLength]byte]map[common.Hash]common.Hash{}
	}
	return m
}
func nonNilNonces(m map[[common.AddressLength]byte]uint64) map[[common.AddressLength]byte]uint64 {
	if m == nil {
		return map[[common.AddressLength]byte]uint64{}
	}
	return m
}
func nonNilPreimages(m map[common.Hash][]byte) map[common.Hash][]byte {
	if m == nil {
		return map[common.Hash][]byte{}
	}
	return m
}
func nonNilBalances(m map[[common.AddressLength]byte]map[[common.AddressLength]byte]int64) map[[common.AddressLength]byte]map[[common.AddressLength]byte]int64 {
	if m == nil {
		return map[[common.AddressLength]byte]map[[common.AddressLength]byte]int64{}
	}
	return m
}
func nonNilTokens(m map[[common.AddressLength]byte]TokenInfo) map[[common.AddressLength]byte]TokenInfo {
	if m == nil {
		return map[[common.AddressLength]byte]TokenInfo{}
	}
	return m
}

// Store/Load are added in Task 2 (they use database + logger, imported above).
var _ = database.MainDB
var _ = logger.GetLogger
```

- [ ] **Step 5: Run the test to confirm it passes**

Run: `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./core/stateDB/ -run TestStateMarshalRoundTrip -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add common/const.go core/stateDB/persistence.go core/stateDB/persistence_test.go
git commit -m "OB-91 EVM: StateAccount Marshal/Unmarshal + EV prefix

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 2: StoreEVMState/LoadEVMState + block-finalize/startup wiring

**Files:**
- Modify: `core/stateDB/persistence.go` (add store/load)
- Modify: `core/stateDB/persistence_test.go` (add store/load test)
- Modify: `blocks/evaluate.go` (`InitStateDB` loads latest; add commit helper)
- Modify: `services/nonceService/onmessage.go` (commit after block success)
- Modify: `genesis/genesis.go` (commit after genesis)
- Modify: `services/helperReset.go` (DB-based revert)

**Interfaces:**
- Consumes: `Marshal`/`Unmarshal` (Task 1), `common.EVMStateDBPrefix`, `common.GetByteInt64`, `database.MainDB.Put/Get`.
- Produces: `func (sa *StateAccount) Store(height int64) error`, `func (sa *StateAccount) Load(height int64) error`, `func (sa *StateAccount) LastStoredHeight() (int64, error)`.

- [ ] **Step 1: Write the failing store/load test**

Append to `core/stateDB/persistence_test.go`:

```go
func TestStoreAndLoadEVMState(t *testing.T) {
	// Requires database.MainDB to be initialized by the test harness; skip if not.
	sa := sampleState()
	if err := sa.Store(5); err != nil {
		t.Skipf("DB not available in this test context: %v", err)
	}
	var loaded StateAccount
	loaded = CreateStateDB()
	if err := loaded.Load(5); err != nil {
		t.Fatalf("Load: %v", err)
	}
	var a [common.AddressLength]byte
	a[0] = 0xAB
	if loaded.Nonces[a] != 7 {
		t.Fatalf("nonce not persisted: %d", loaded.Nonces[a])
	}
}
```

- [ ] **Step 2: Run to confirm it fails**

Run: `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./core/stateDB/ -run TestStoreAndLoadEVMState`
Expected: FAIL — `Store` undefined.

- [ ] **Step 3: Implement Store/Load/LastStoredHeight**

Replace the two `var _ =` lines at the end of `core/stateDB/persistence.go` with:

```go
// Store persists the committed EVM state under EVMStateDBPrefix+height.
func (sa *StateAccount) Store(height int64) error {
	b, err := sa.Marshal()
	if err != nil {
		return err
	}
	prefix := append(common.EVMStateDBPrefix[:], common.GetByteInt64(height)...)
	if err := database.MainDB.Put(prefix, b); err != nil {
		logger.GetLogger().Println("cannot store EVM state", err)
		return err
	}
	return nil
}

// Load restores EVM state for a height (height < 0 => latest stored).
func (sa *StateAccount) Load(height int64) error {
	if height < 0 {
		h, err := sa.LastStoredHeight()
		if err != nil {
			return err
		}
		height = h
	}
	prefix := append(common.EVMStateDBPrefix[:], common.GetByteInt64(height)...)
	b, err := database.MainDB.Get(prefix)
	if err != nil || b == nil {
		return err
	}
	return sa.Unmarshal(b)
}

// LastStoredHeight finds the highest stored EVM-state height via exponential +
// binary search (heights are contiguous), mirroring account.LastHeightStoredInAccounts.
func (sa *StateAccount) LastStoredHeight() (int64, error) {
	exists := func(h int64) (bool, error) {
		prefix := append(common.EVMStateDBPrefix[:], common.GetByteInt64(h)...)
		return database.MainDB.IsKey(prefix)
	}
	if ok, err := exists(0); err != nil {
		return -1, err
	} else if !ok {
		return -1, nil
	}
	lo, hi := int64(0), int64(1)
	for {
		ok, err := exists(hi)
		if err != nil {
			return lo, err
		}
		if !ok {
			break
		}
		lo = hi
		hi *= 2
	}
	for hi-lo > 1 {
		mid := lo + (hi-lo)/2
		ok, err := exists(mid)
		if err != nil {
			return lo, err
		}
		if ok {
			lo = mid
		} else {
			hi = mid
		}
	}
	return lo, nil
}
```

- [ ] **Step 4: Run the store/load test**

Run: `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./core/stateDB/ -run TestStoreAndLoadEVMState -v`
Expected: PASS or SKIP (skips if `database.MainDB` isn't initialized in the unit context; the end-to-end wiring is exercised by the blocks-level test in Step 7).

- [ ] **Step 5: Load latest state in InitStateDB**

In `blocks/evaluate.go`, find `InitStateDB` (creates `State = stateDB.CreateStateDB()`). After the `CreateStateDB()` assignment add:

```go
	// Phase 1: restore persisted EVM state so contracts survive restarts.
	if err := State.Load(-1); err != nil {
		logger.GetLogger().Println("could not load persisted EVM state (starting empty):", err)
	}
```

Add a package-level commit helper in `blocks/evaluate.go`:

```go
// CommitEVMState persists the current EVM state for a block height. Call it
// wherever native accounts are stored on block finalize.
func CommitEVMState(height int64) error {
	StateMutex.Lock()
	defer StateMutex.Unlock()
	return State.Store(height)
}
```

- [ ] **Step 6: Call CommitEVMState on block finalize + genesis**

In `services/nonceService/onmessage.go`, in the block-success path where `account.StoreAccounts(newBlock.GetHeader().Height)` is called, add immediately after it:

```go
				if err := blocks.CommitEVMState(newBlock.GetHeader().Height); err != nil {
					logger.GetLogger().Println("cannot store EVM state", err)
				}
```

In `genesis/genesis.go`, after the genesis block's `account.StoreAccounts(...)` call, add:

```go
	if err := blocks.CommitEVMState(genesisBlock.GetHeader().Height); err != nil {
		logger.GetLogger().Println("cannot store genesis EVM state", err)
	}
```

In `services/helperReset.go`, in the reset function alongside the existing `State.RevertToSnapshot`/`CleanupContractsAfterHeight`, add a DB-level restore:

```go
	if err := blocks.State.Load(height); err != nil {
		logger.GetLogger().Println("could not reload EVM state on reset:", err)
	}
```

- [ ] **Step 7: Write an end-to-end persistence test**

Create `blocks/evm_persistence_test.go`:

```go
package blocks

import (
	"testing"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
)

// TestEVMStatePersistsAcrossReload deploys nothing but exercises the
// store/reload path directly on blocks.State.
func TestEVMStatePersistsAcrossReload(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	InitStateDB()

	var a [common.AddressLength]byte
	a[0] = 0xCD
	StateMutex.Lock()
	State.Codes[a] = []byte{0x01, 0x02, 0x03}
	State.Nonces[a] = 42
	State.StatesHashes[a] = map[common.Hash]common.Hash{{0x0A}: {0x0B}}
	StateMutex.Unlock()

	if err := CommitEVMState(100); err != nil {
		t.Skipf("DB not available: %v", err)
	}
	// Wipe in-memory state, then reload from DB.
	InitStateDB()
	if err := State.Load(100); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if State.Nonces[a] != 42 {
		t.Fatalf("nonce not persisted: %d", State.Nonces[a])
	}
	if State.StatesHashes[a][common.Hash{0x0A}] != (common.Hash{0x0B}) {
		t.Fatal("storage slot not persisted")
	}
}
```

- [ ] **Step 8: Build everything, run the tests**

Run: `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go build ./... && GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./core/stateDB/ ./blocks/ -run 'EVM'`
Expected: build OK; tests PASS or SKIP (if no DB in unit context).

- [ ] **Step 9: Commit**

```bash
git add core/stateDB/persistence.go core/stateDB/persistence_test.go blocks/evaluate.go blocks/evm_persistence_test.go services/nonceService/onmessage.go genesis/genesis.go services/helperReset.go
git commit -m "OB-92 EVM: persist state to RocksDB, wire commit/load/reset

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 3: Fix RevertToSnapshot key corruption (DB-H3) via a change journal (CONSENSUS)

**Files:**
- Create: `core/stateDB/journal.go`
- Modify: `core/stateDB/methods.go` (`StateAccount` struct field, `SetState`, `RevertToSnapshot`, `Snapshot`)
- Create: `core/stateDB/methods_test.go`

**Interfaces:**
- Produces: `changeEntry` interface with `revert(*StateAccount)`; `slotChange` type. `Snapshot()` returns `int`; `RevertToSnapshot(int)`.
- Consumes: existing `SnapShotNum int` field (repurposed as journal index).

**Background:** The current `RevertToSnapshot` (methods.go:217-228) ranges `for a, h := range sa.SnapShotPreimage[s]` where `h` is the stored *old value*, then uses it as the storage *slot key* — corrupting storage. `SnapShotPreimage` never recorded the slot key. Fix: record the slot key in a typed change entry.

- [ ] **Step 1: Write the failing revert test**

Create `core/stateDB/methods_test.go`:

```go
package stateDB

import (
	"testing"

	"github.com/qwid-org/qwid-node/common"
)

func addr(b byte) common.Address {
	var a common.Address
	a.ByteValue[0] = b
	return a
}

func TestRevertToSnapshotRestoresSlots(t *testing.T) {
	sa := CreateStateDB()
	a := addr(0x01)
	key := common.Hash{0xAA}

	sa.SetState(a, key, common.Hash{0x01}) // v1
	snap := sa.Snapshot()
	sa.SetState(a, key, common.Hash{0x02}) // v2
	sa.SetState(a, key, common.Hash{0x03}) // v3

	if sa.GetState(a, key) != (common.Hash{0x03}) {
		t.Fatalf("pre-revert value wrong: %v", sa.GetState(a, key))
	}
	sa.RevertToSnapshot(snap)
	if sa.GetState(a, key) != (common.Hash{0x01}) {
		t.Fatalf("revert did not restore original slot value, got %v", sa.GetState(a, key))
	}
}

func TestRevertDeletesNewlyCreatedSlot(t *testing.T) {
	sa := CreateStateDB()
	a := addr(0x02)
	key := common.Hash{0xBB}
	snap := sa.Snapshot()
	sa.SetState(a, key, common.Hash{0x09})
	sa.RevertToSnapshot(snap)
	if sa.GetState(a, key) != (common.Hash{}) {
		t.Fatalf("newly created slot not removed on revert: %v", sa.GetState(a, key))
	}
}
```

- [ ] **Step 2: Run to confirm it fails**

Run: `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./core/stateDB/ -run TestRevert`
Expected: FAIL — `TestRevertToSnapshotRestoresSlots` restores the wrong value (DB-H3 bug).

- [ ] **Step 3: Add the journal types**

Create `core/stateDB/journal.go`:

```go
package stateDB

import "github.com/qwid-org/qwid-node/common"

// changeEntry is one reversible mutation recorded during execution.
type changeEntry interface {
	revert(sa *StateAccount)
}

// slotChange restores a storage slot to its prior value (or removes it if it
// did not exist before).
type slotChange struct {
	addr    [common.AddressLength]byte
	key     common.Hash
	prev    common.Hash
	existed bool
}

func (c slotChange) revert(sa *StateAccount) {
	m, ok := sa.StatesHashes[c.addr]
	if !ok {
		return
	}
	if !c.existed {
		delete(m, c.key)
		return
	}
	m[c.key] = c.prev
}
```

- [ ] **Step 4: Replace SnapShotPreimage with a journal**

In `core/stateDB/methods.go`:

1. In the `StateAccount` struct, replace the field
   `SnapShotPreimage    map[int]map[[common.AddressLength]byte]common.Hash `json:"snapShotPreimage"``
   with
   `journal             []changeEntry` (no json tag — transient).

2. In `CreateStateDB`, replace `sa.SnapShotPreimage = map[int]map[[common.AddressLength]byte]common.Hash{}` with `sa.journal = nil` and keep `sa.SnapShotNum = 0`.

3. Replace `SetState` (currently lines 161-173) with:

```go
func (sa *StateAccount) SetState(a common.Address, h common.Hash, h2 common.Hash) {
	m, ok := sa.StatesHashes[a.ByteValue]
	if !ok {
		m = map[common.Hash]common.Hash{}
		sa.StatesHashes[a.ByteValue] = m
	}
	prev, existed := m[h]
	sa.journal = append(sa.journal, slotChange{addr: a.ByteValue, key: h, prev: prev, existed: existed})
	sa.SnapShotNum = len(sa.journal)
	m[h] = h2
}
```

4. Replace `RevertToSnapshot` (lines 217-228) and `Snapshot` (230-232) with:

```go
func (sa *StateAccount) RevertToSnapshot(sn int) {
	if sn < 0 {
		sn = 0
	}
	for i := len(sa.journal) - 1; i >= sn; i-- {
		sa.journal[i].revert(sa)
	}
	sa.journal = sa.journal[:sn]
	sa.SnapShotNum = sn
}

func (sa *StateAccount) Snapshot() int {
	return len(sa.journal)
}
```

- [ ] **Step 5: Run the revert tests**

Run: `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./core/stateDB/ -run TestRevert -v`
Expected: PASS (both tests).

- [ ] **Step 6: Build the dependents (SnapShotPreimage removed)**

Run: `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go build ./core/... ./blocks/... ./services/...`
Expected: build OK. If any code referenced `SnapShotPreimage` directly, replace those reads with the journal (grep first: `grep -rn SnapShotPreimage`). `GetSnapShotNum`/`SetSnapShotNum` still exist and now record `len(journal)` per height for `helperReset`.

- [ ] **Step 7: Commit**

```bash
git add core/stateDB/journal.go core/stateDB/methods.go core/stateDB/methods_test.go
git commit -m "OB-93 DB-H3 (CONSENSUS): fix RevertToSnapshot storage-key corruption via change journal

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 4: Implement AddLog and Suicide with revert (DB-C6, DB-H2) (CONSENSUS)

**Files:**
- Modify: `core/stateDB/journal.go` (log + suicide change entries)
- Modify: `core/stateDB/methods.go` (`StateAccount` fields, `AddLog`, `Suicide`, `HasSuicided`, `GetLogs`)
- Modify: `core/stateDB/methods_test.go` (tests)

**Interfaces:**
- Consumes: `changeEntry` (Task 3), `types.Log` (`core/types`).
- Produces: `func (sa *StateAccount) GetLogs() []*types.Log`, `func (sa *StateAccount) ClearLogs()`.

- [ ] **Step 1: Write failing tests**

Append to `core/stateDB/methods_test.go`:

```go
func TestAddLogAndRevert(t *testing.T) {
	sa := CreateStateDB()
	sa.ClearLogs()
	snap := sa.Snapshot()
	sa.AddLog(&types.Log{Address: addr(0x03).ByteValue})
	if len(sa.GetLogs()) != 1 {
		t.Fatalf("log not captured: %d", len(sa.GetLogs()))
	}
	sa.RevertToSnapshot(snap)
	if len(sa.GetLogs()) != 0 {
		t.Fatalf("log not reverted: %d", len(sa.GetLogs()))
	}
}

func TestSuicide(t *testing.T) {
	sa := CreateStateDB()
	a := addr(0x04)
	sa.CreateAccount(a)
	if sa.HasSuicided(a) {
		t.Fatal("fresh account reported suicided")
	}
	if !sa.Suicide(a) {
		t.Fatal("Suicide returned false for existing account")
	}
	if !sa.HasSuicided(a) {
		t.Fatal("HasSuicided false after Suicide")
	}
}
```

Add `"github.com/qwid-org/qwid-node/core/types"` to the test imports.

- [ ] **Step 2: Run to confirm failure**

Run: `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./core/stateDB/ -run 'TestAddLog|TestSuicide'`
Expected: FAIL — `GetLogs`/`ClearLogs` undefined; `HasSuicided` always false.

- [ ] **Step 3: Add log + suicide change entries**

Append to `core/stateDB/journal.go`:

```go
// logChange removes the last-added log on revert.
type logChange struct{}

func (logChange) revert(sa *StateAccount) {
	if n := len(sa.logs); n > 0 {
		sa.logs = sa.logs[:n-1]
	}
}

// suicideChange unmarks a suicide on revert.
type suicideChange struct {
	addr [common.AddressLength]byte
}

func (c suicideChange) revert(sa *StateAccount) {
	delete(sa.suicided, c.addr)
}
```

- [ ] **Step 4: Add fields + implement methods**

In `core/stateDB/methods.go`:

1. Add imports if missing: `types` is already imported.
2. Add to the `StateAccount` struct:

```go
	logs     []*types.Log                       // transient
	suicided map[[common.AddressLength]byte]bool // transient
```

3. In `CreateStateDB`, add `sa.suicided = map[[common.AddressLength]byte]bool{}`.
4. Replace `AddLog` (methods.go:234-236) with:

```go
func (sa *StateAccount) AddLog(l *types.Log) {
	sa.journal = append(sa.journal, logChange{})
	sa.SnapShotNum = len(sa.journal)
	sa.logs = append(sa.logs, l)
}

// GetLogs returns the logs accumulated during the current execution.
func (sa *StateAccount) GetLogs() []*types.Log { return sa.logs }

// ClearLogs resets the per-execution log buffer (call before running a tx).
func (sa *StateAccount) ClearLogs() { sa.logs = nil }
```

5. Replace `Suicide`/`HasSuicided` (methods.go:175-180) with:

```go
func (sa *StateAccount) Suicide(a common.Address) bool {
	if _, ok := sa.Accounts[a.ByteValue]; !ok {
		return false
	}
	if sa.suicided == nil {
		sa.suicided = map[[common.AddressLength]byte]bool{}
	}
	if !sa.suicided[a.ByteValue] {
		sa.journal = append(sa.journal, suicideChange{addr: a.ByteValue})
		sa.SnapShotNum = len(sa.journal)
		sa.suicided[a.ByteValue] = true
	}
	return true
}

func (sa *StateAccount) HasSuicided(a common.Address) bool {
	return sa.suicided[a.ByteValue]
}
```

- [ ] **Step 5: Run tests**

Run: `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./core/stateDB/ -run 'TestAddLog|TestSuicide' -v`
Expected: PASS.

- [ ] **Step 6: Collect logs in EvaluateSC**

In `blocks/evaluate.go`, in `EvaluateSC` after `VM.Call`/`VM.Create` returns, set the tx's output logs from the StateDB and clear for the next tx. Locate where `t.OutputLogs` is assigned; ensure logs come from `State.GetLogs()` and call `State.ClearLogs()` before each tx execution. (Grep `OutputLogs` in `blocks/evaluate.go`; wire `State.GetLogs()` in and `State.ClearLogs()` before the `VM.*` call.)

- [ ] **Step 7: Build + commit**

Run: `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go build ./... && GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./core/stateDB/`

```bash
git add core/stateDB/journal.go core/stateDB/methods.go core/stateDB/methods_test.go blocks/evaluate.go
git commit -m "OB-94 DB-C6/DB-H2 (CONSENSUS): implement AddLog and Suicide with revert

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 5: Implement EIP-2929 access list (DB-C5) (CONSENSUS)

**Files:**
- Modify: `core/stateDB/journal.go` (access-list change entries)
- Modify: `core/stateDB/methods.go` (fields + the five access-list methods)
- Modify: `core/stateDB/methods_test.go` (tests)

**Interfaces:**
- Consumes: `changeEntry`, `types.AccessList` (`core/types`).

- [ ] **Step 1: Write failing test**

Append to `core/stateDB/methods_test.go`:

```go
func TestAccessList(t *testing.T) {
	sa := CreateStateDB()
	a := addr(0x05)
	if sa.AddressInAccessList(a) {
		t.Fatal("address unexpectedly warm before add")
	}
	sa.AddAddressToAccessList(a)
	if !sa.AddressInAccessList(a) {
		t.Fatal("address not warm after add")
	}
	slot := common.Hash{0xCC}
	adOk, slOk := sa.SlotInAccessList(a, slot)
	if !adOk || slOk {
		t.Fatalf("slot state wrong before add: addr=%v slot=%v", adOk, slOk)
	}
	sa.AddSlotToAccessList(a, slot)
	adOk, slOk = sa.SlotInAccessList(a, slot)
	if !adOk || !slOk {
		t.Fatal("slot not warm after add")
	}
}
```

- [ ] **Step 2: Run to confirm failure**

Run: `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./core/stateDB/ -run TestAccessList`
Expected: FAIL — current stubs return `true` unconditionally.

- [ ] **Step 3: Add access-list change entries**

Append to `core/stateDB/journal.go`:

```go
type accessAddrChange struct{ addr [common.AddressLength]byte }

func (c accessAddrChange) revert(sa *StateAccount) { delete(sa.accessAddrs, c.addr) }

type accessSlotChange struct {
	addr [common.AddressLength]byte
	slot common.Hash
}

func (c accessSlotChange) revert(sa *StateAccount) {
	if m, ok := sa.accessSlots[c.addr]; ok {
		delete(m, c.slot)
	}
}
```

- [ ] **Step 4: Implement the methods**

In `core/stateDB/methods.go`:

1. Add to `StateAccount`:

```go
	accessAddrs map[[common.AddressLength]byte]bool                       // transient
	accessSlots map[[common.AddressLength]byte]map[common.Hash]bool       // transient
```

2. In `CreateStateDB`, add:

```go
	sa.accessAddrs = map[[common.AddressLength]byte]bool{}
	sa.accessSlots = map[[common.AddressLength]byte]map[common.Hash]bool{}
```

3. Replace the five access-list methods (methods.go:195-215) with:

```go
func (sa *StateAccount) PrepareAccessList(sender common.Address, dest *common.Address, precompiles []common.Address, txAccesses types.AccessList) {
	sa.accessAddrs = map[[common.AddressLength]byte]bool{}
	sa.accessSlots = map[[common.AddressLength]byte]map[common.Hash]bool{}
	sa.addAddrNoJournal(sender)
	if dest != nil {
		sa.addAddrNoJournal(*dest)
	}
	for _, p := range precompiles {
		sa.addAddrNoJournal(p)
	}
	for _, tuple := range txAccesses {
		var a common.Address
		copy(a.ByteValue[:], tuple.Address.Bytes())
		sa.addAddrNoJournal(a)
		for _, k := range tuple.StorageKeys {
			var h common.Hash
			copy(h[:], k[:])
			sa.addSlotNoJournal(a, h)
		}
	}
}

func (sa *StateAccount) addAddrNoJournal(a common.Address) {
	sa.accessAddrs[a.ByteValue] = true
}

func (sa *StateAccount) addSlotNoJournal(a common.Address, slot common.Hash) {
	m, ok := sa.accessSlots[a.ByteValue]
	if !ok {
		m = map[common.Hash]bool{}
		sa.accessSlots[a.ByteValue] = m
	}
	m[slot] = true
}

func (sa *StateAccount) AddressInAccessList(addr common.Address) bool {
	return sa.accessAddrs[addr.ByteValue]
}

func (sa *StateAccount) SlotInAccessList(addr common.Address, slot common.Hash) (bool, bool) {
	addrOk := sa.accessAddrs[addr.ByteValue]
	slotOk := false
	if m, ok := sa.accessSlots[addr.ByteValue]; ok {
		slotOk = m[slot]
	}
	return addrOk, slotOk
}

func (sa *StateAccount) AddAddressToAccessList(addr common.Address) {
	if !sa.accessAddrs[addr.ByteValue] {
		sa.journal = append(sa.journal, accessAddrChange{addr: addr.ByteValue})
		sa.SnapShotNum = len(sa.journal)
		sa.accessAddrs[addr.ByteValue] = true
	}
}

func (sa *StateAccount) AddSlotToAccessList(addr common.Address, slot common.Hash) {
	sa.AddAddressToAccessList(addr)
	m, ok := sa.accessSlots[addr.ByteValue]
	if !ok || !m[slot] {
		sa.journal = append(sa.journal, accessSlotChange{addr: addr.ByteValue, slot: slot})
		sa.SnapShotNum = len(sa.journal)
		sa.addSlotNoJournal(addr, slot)
	}
}
```

Note: check `types.AccessTuple` field/method names in `core/types/access_list_tx.go` (`tuple.Address` is a `common.Address` from go-ethereum's types with a `.Bytes()` method; `tuple.StorageKeys` are `common.Hash`). Adjust the copy calls to the actual field types found there.

- [ ] **Step 5: Run + build + commit**

Run: `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./core/stateDB/ -run TestAccessList -v && GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go build ./...`
Expected: PASS, build OK.

```bash
git add core/stateDB/journal.go core/stateDB/methods.go core/stateDB/methods_test.go
git commit -m "OB-95 DB-C5 (CONSENSUS): real EIP-2929 access list

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 6: Fix EVM memory bounds (DB-H7, DB-H8)

**Files:**
- Modify: `core/evm/memory.go` (`Set`, `Set32`, `GetCopy`, `GetPtr`)
- Create: `core/evm/memory_test.go`

- [ ] **Step 1: Write failing tests**

Create `core/evm/memory_test.go`:

```go
package vm

import "testing"

func TestGetCopyNegativeOffset(t *testing.T) {
	m := NewMemory()
	m.Resize(32)
	if got := m.GetCopy(-1, 4); got != nil {
		t.Fatalf("expected nil for negative offset, got %v", got)
	}
}

func TestGetPtrNegativeOffset(t *testing.T) {
	m := NewMemory()
	m.Resize(32)
	if got := m.GetPtr(-1, 4); got != nil {
		t.Fatalf("expected nil for negative offset, got %v", got)
	}
}

func TestSetOnEmptyStoreDoesNotPanic(t *testing.T) {
	m := NewMemory()
	// Previously panicked; must be a safe no-op / bounded write now.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Set panicked: %v", r)
		}
	}()
	m.Set(0, 4, []byte{1, 2, 3, 4})
}
```

- [ ] **Step 2: Run to confirm failure**

Run: `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./core/evm/ -run 'TestGetCopy|TestGetPtr|TestSetOn'`
Expected: FAIL — `Set` panics; negative offset indexes incorrectly.

- [ ] **Step 3: Add bounds guards**

In `core/evm/memory.go`:

Replace the `Set` body's panic branch:

```go
		if offset+size > uint64(len(m.store)) {
			panic("invalid memory: store empty")
		}
```
with
```go
		if offset+size > uint64(len(m.store)) {
			// Store must be resized before Set; if not, skip rather than crash.
			return
		}
```

Replace the `Set32` panic branch:

```go
	if offset+32 > uint64(len(m.store)) {
		panic("invalid memory: store empty")
	}
```
with
```go
	if offset+32 > uint64(len(m.store)) {
		return
	}
```

Replace `GetCopy`'s guard `if len(m.store) > int(offset) {` with:

```go
	if offset < 0 || size < 0 || int64(len(m.store)) < offset+size {
		return nil
	}
	cpy = make([]byte, size)
	copy(cpy, m.store[offset:offset+size])
	return
```

Replace `GetPtr`'s guard `if len(m.store) > int(offset) {` with:

```go
	if offset < 0 || size < 0 || int64(len(m.store)) < offset+size {
		return nil
	}
	return m.store[offset : offset+size]
```

- [ ] **Step 4: Run + commit**

Run: `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./core/evm/ -run 'TestGetCopy|TestGetPtr|TestSetOn' -v && GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go build ./core/...`
Expected: PASS, build OK.

```bash
git add core/evm/memory.go core/evm/memory_test.go
git commit -m "OB-96 DB-H7/DB-H8: guard EVM memory against negative offsets and panics

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 7: opCreate real nonce, dataCopy copy, ecrecover fail-loud (DB-M2, DB-M5, DB-C3) (CONSENSUS)

**Files:**
- Modify: `core/evm/instructions.go:610` (`opCreate` nonce)
- Modify: `core/evm/contracts.go` (`dataCopy.Run`, `ecrecover.Run`)
- Create: `core/evm/contracts_test.go`

- [ ] **Step 1: Fix opCreate nonce (DB-M2)**

In `core/evm/instructions.go`, line ~610, replace:

```go
	res, addr, returnGas, suberr := interpreter.evm.Create(scope.Contract, input, gas, bigVal, 23)
```
with:

```go
	callerAddr := scope.Contract.Address()
	nonce := interpreter.evm.StateDB.GetNonce(callerAddr)
	res, addr, returnGas, suberr := interpreter.evm.Create(scope.Contract, input, gas, bigVal, nonce)
```

(Confirm `scope.Contract.Address()` returns `common.Address` and `evm.StateDB.GetNonce` takes it. If `Create`'s 5th arg is `uint64`, `GetNonce` already returns `uint64` — matches.)

- [ ] **Step 2: Fix dataCopy (DB-M5) + write test**

In `core/evm/contracts.go`, replace `dataCopy.Run` (line ~243):

```go
func (c *dataCopy) Run(in []byte) ([]byte, error) {
	out := make([]byte, len(in))
	copy(out, in)
	return out, nil
}
```

Create `core/evm/contracts_test.go`:

```go
package vm

import "testing"

func TestDataCopyReturnsCopy(t *testing.T) {
	in := []byte{1, 2, 3}
	out, err := (&dataCopy{}).Run(in)
	if err != nil {
		t.Fatal(err)
	}
	out[0] = 9
	if in[0] != 1 {
		t.Fatal("dataCopy returned a reference to the input, not a copy")
	}
}

func TestEcrecoverFailsLoud(t *testing.T) {
	// secp256k1 recovery is meaningless on this post-quantum chain; the
	// precompile must not return a deterministic garbage address.
	out, err := (&ecrecover{}).Run(make([]byte, 128))
	if err == nil && len(out) != 0 {
		t.Fatalf("ecrecover returned data (%x) instead of empty/err", out)
	}
}
```

- [ ] **Step 3: Fix ecrecover (DB-C3)**

In `core/evm/contracts.go`, replace the body of `ecrecover.Run` (line ~165-200) with:

```go
func (c *ecrecover) Run(input []byte) ([]byte, error) {
	// This chain uses post-quantum signatures (Falcon-512/MAYO-5), not
	// secp256k1, so ECDSA public-key recovery is not meaningful. Return an
	// empty result rather than a deterministic garbage address, so contracts
	// cannot rely on it (DB-C3). Gas is still charged via RequiredGas.
	return nil, nil
}
```

(Returning `nil, nil` yields empty output, which Solidity's `ecrecover` maps to the zero address / failure — callers that check for the zero address will correctly treat it as invalid.)

- [ ] **Step 4: Run tests + build**

Run: `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./core/evm/ -run 'TestDataCopy|TestEcrecover' -v && GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go build ./...`
Expected: PASS, build OK.

- [ ] **Step 5: Commit**

```bash
git add core/evm/instructions.go core/evm/contracts.go core/evm/contracts_test.go
git commit -m "OB-97 DB-M2/M5/C3 (CONSENSUS): opCreate real nonce, dataCopy copy, ecrecover fail-loud

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 8: ABI panic → error (DB-M6, DB-M7)

**Files:**
- Modify: `core/abi/type.go:258` (`GetType`), and its callers on the `Unpack` path
- Modify: `core/abi/pack.go:83` (`packNum`), and its callers on the `Pack` path
- Modify: `core/abi/*_test.go` (add error-path test)

**Note:** Changing `GetType`/`packNum` to return errors ripples through their callers. Prefer the smallest change that removes the panic: if the function signature is hard to change, recover the panic at the outermost `Unpack`/`Pack` boundary and convert it to an error.

- [ ] **Step 1: Write failing test**

Create `core/abi/panic_test.go`:

```go
package abi

import "testing"

// TestUnpackDoesNotPanicOnBadType ensures malformed ABI type data returns an
// error rather than panicking (DB-M6).
func TestUnpackDoesNotPanicOnBadType(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Unpack panicked: %v", r)
		}
	}()
	// A Type with an unsupported kind should not crash GetType.
	var ty Type
	ty.T = 99 // invalid kind
	_ = safeGetType(ty)
}
```

- [ ] **Step 2: Add a recover wrapper (smallest safe change)**

In `core/abi/type.go`, add near `GetType`:

```go
// safeGetType calls GetType but converts its panic into a zero value, so
// malformed ABI type data cannot crash the node (DB-M6). Callers that need the
// error should check for the zero reflect.Type.
func safeGetType(t Type) (rt reflect.Type) {
	defer func() { _ = recover() }()
	return t.GetType()
}
```

At the `Unpack`/`Pack` entry points (`abi.go` `Unpack`, `pack.go` `Pack`), wrap the body in a deferred recover that returns an error:

```go
func (abi ABI) Unpack(name string, data []byte) (out []interface{}, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("abi unpack panic recovered: %v", r)
		}
	}()
	// ... existing body ...
}
```

Apply the same deferred-recover to `Pack` (guards `packNum`'s `panic("abi: fatal error")`, DB-M7). Ensure `fmt` is imported.

- [ ] **Step 3: Run + build + commit**

Run: `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./core/abi/ && GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go build ./...`
Expected: existing ABI tests still PASS; new test PASS; build OK.

```bash
git add core/abi/type.go core/abi/pack.go core/abi/abi.go core/abi/panic_test.go
git commit -m "OB-98 DB-M6/M7: recover ABI Pack/Unpack panics into errors

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Final verification

- [ ] Run the full build: `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go build ./...` → exit 0.
- [ ] Run the new/affected tests: `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./core/stateDB/ ./core/evm/ ./core/abi/ ./blocks/` → PASS (blocks EVM tests may SKIP without a DB).
- [ ] Confirm no code still references the removed `SnapShotPreimage` field: `grep -rn SnapShotPreimage` → no hits.
- [ ] Update `SECURITY_AUDIT.md` marking DB-C3, DB-C5, DB-C6, DB-H2, DB-H3, DB-H7, DB-H8, DB-M2, DB-M5, DB-M6, DB-M7 addressed in Phase 1 (DB-C1/C2/C4 remain for Phases 2–3).

## Deferred to later phases (not in this plan)
- DB-C1 (balance bridge) → Phase 2.
- DB-C2 (value transfer), DB-C4 (refunds), real gas pricing → Phase 3.
- Binary state encoding (JSON used here) → optimization.

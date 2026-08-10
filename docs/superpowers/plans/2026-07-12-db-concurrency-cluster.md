# Database Concurrency Cluster Implementation Plan (DB-H4/H5/H6 + DB-M8)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the RocksDB wrapper's pointer-lifecycle locking correct: atomic `Close`, no reentrant double-lock, mutating `Delete` under the write lock, all ops nil-safe after close, and no manual LOCK-file deletion.

**Architecture:** The `BlockchainDB.mutex` (`sync.RWMutex`) guards the `d.db` pointer; RocksDB is itself thread-safe. Fix the four coupled findings so every op holds the lock + nil-checks `d.db`, and `Close`/`CloseDB` are atomic and reentrancy-free.

**Tech Stack:** Go 1.23.6; `database` package; grocksdb (RocksDB, CGO).

## Global Constraints
- Build/test with `GOROOT=/home/wonabru/sdk/go1.24.0`. Example: `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./database/`.
- Branch `security-fixes`. Commit `OB-xx` (NOT `(CONSENSUS)` — node-local). End messages with `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- `BlockchainDB{ db *gorocksdb.DB; mutex sync.RWMutex }`; global `MainDB *BlockchainDB`. Receiver name is `d` in `Get`/`Close`, `db` elsewhere — match the existing receiver per function.
- Do NOT change the mutex model or make locking finer-grained. Node-local reliability only; no consensus/wire/format change.
- Tests use `InitInMemory()` and `t.Skip` if RocksDB/CGO is unavailable.

## File Structure
- `database/DbRocksDB.go` — `Close` rewrite (Task 1), `Delete`+nil-checks (Task 2), `InitPermanent` LOCK removal (Task 3).
- `database/blockchaindb.go` — `CloseDB` (Task 1).
- `database/db_concurrency_test.go` (new) — tests across tasks.

---

## Task 1: DB-H4 + DB-M8 — atomic `Close` + reentrancy-free `CloseDB`

**Files:** Modify `database/DbRocksDB.go` (`Close`, imports), `database/blockchaindb.go` (`CloseDB`); test `database/db_concurrency_test.go` (new).

- [ ] **Step 1: Write the failing tests** — create `database/db_concurrency_test.go`:

```go
package database

import (
	"sync"
	"testing"
	"time"
)

func newMemDB(t *testing.T) *BlockchainDB {
	t.Helper()
	db := &BlockchainDB{}
	mem, err := db.InitInMemory()
	if err != nil {
		t.Skipf("in-memory RocksDB unavailable: %v", err)
	}
	return mem
}

func TestCloseIdempotentNoDeadlock(t *testing.T) {
	db := newMemDB(t)
	done := make(chan struct{})
	go func() { db.Close(); db.Close(); close(done) }() // double close must not hang/panic
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close hung (deadlock)")
	}
}

func TestCloseDBNoDeadlockNilsMainDB(t *testing.T) {
	db := newMemDB(t)
	saved := MainDB
	MainDB = db
	defer func() { MainDB = saved }()
	done := make(chan struct{})
	go func() { _ = CloseDB(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("CloseDB hung (reentrant double-lock deadlock)")
	}
	if MainDB != nil {
		t.Fatal("MainDB should be nil after CloseDB")
	}
}
```

- [ ] **Step 2: Run to verify it fails/flakes** — `GOROOT=… go test ./database/ -run 'TestClose' -v`. The old `Close` uses goroutine timeouts; `CloseDB` double-locks so `Close` takes its 1s timeout path — the test may pass slowly or flake. (The real proof is Step 4's clean, fast pass.)

- [ ] **Step 3: Rewrite `Close` (`database/DbRocksDB.go`)** — replace the entire goroutine/timeout `Close()` body with:

```go
// Close flushes and closes the database atomically under the mutex. It blocks
// until any in-flight operation releases its (R)lock, then closes — so no op can
// ever race a nil-ing d.db (DB-H4). Idempotent.
func (d *BlockchainDB) Close() {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	if d.db == nil {
		return
	}
	fo := gorocksdb.NewDefaultFlushOptions()
	defer fo.Destroy()
	if err := d.db.Flush(fo); err != nil {
		logger.GetLogger().Printf("Error flushing database on close: %v", err)
	}
	d.db.Close()
	d.db = nil
	logger.GetLogger().Println("Database closed")
}
```
Then remove the now-unused `"time"` import from `database/DbRocksDB.go` (it was used ONLY in the old `Close` timeouts). If the build reports `time` still used elsewhere, keep it; otherwise remove it.

- [ ] **Step 4: Simplify `CloseDB` (`database/blockchaindb.go`)** — replace with (no pre-lock; `Close` self-locks, so the reentrant double-`Lock` / DB-M8 is gone):

```go
func CloseDB() error {
	if MainDB != nil {
		MainDB.Close() // acquires the mutex itself
		MainDB = nil
	}
	return nil
}
```

- [ ] **Step 5: Run + build** — `GOROOT=… go test ./database/ -run 'TestClose' -v && GOROOT=… go build ./...` → PASS quickly (no multi-second timeout), build OK.
- [ ] **Step 6: Commit** — `OB-119 DB-H4/DB-M8: atomic Close() under the lock, reentrancy-free CloseDB()` + Co-Authored-By.

---

## Task 2: DB-H5 — `Delete` write-lock + nil-checks on all ops (+ race test)

**Files:** Modify `database/DbRocksDB.go` (`Delete`, `Put`, `IsKey`, `LoadAll`, `LoadAllKeys`); test `database/db_concurrency_test.go`.

- [ ] **Step 1: Failing tests** — append to `database/db_concurrency_test.go`:

```go
import "sync/atomic" // add to the import block

func TestOpsReturnErrorAfterClose(t *testing.T) {
	db := newMemDB(t)
	db.Close()
	if err := db.Put([]byte("k"), []byte("v")); err == nil {
		t.Fatal("Put after close must error, not panic")
	}
	if err := db.Delete([]byte("k")); err == nil {
		t.Fatal("Delete after close must error, not panic")
	}
	if _, err := db.Get([]byte("k")); err == nil {
		t.Fatal("Get after close must error")
	}
	if _, err := db.IsKey([]byte("k")); err == nil {
		t.Fatal("IsKey after close must error")
	}
	if _, err := db.LoadAll([]byte("p")); err == nil {
		t.Fatal("LoadAll after close must error")
	}
	if _, err := db.LoadAllKeys([]byte("p")); err == nil {
		t.Fatal("LoadAllKeys after close must error")
	}
}

func TestConcurrentOpsVsCloseNoPanic(t *testing.T) {
	db := newMemDB(t)
	var panicked int32
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			defer func() {
				if recover() != nil {
					atomic.StoreInt32(&panicked, 1)
				}
			}()
			_ = db.Put([]byte{byte(i)}, []byte{1})
			_, _ = db.Get([]byte{byte(i)})
			_ = db.Delete([]byte{byte(i)})
			_, _ = db.IsKey([]byte{byte(i)})
		}(i)
	}
	db.Close() // concurrent with the ops
	wg.Wait()
	if atomic.LoadInt32(&panicked) == 1 {
		t.Fatal("an op panicked while racing Close (unsafe d.db access)")
	}
}
```

- [ ] **Step 2: Run to verify it fails** — `GOROOT=… go test ./database/ -run 'TestOpsReturnErrorAfterClose|TestConcurrentOpsVsClose' -race` → FAIL/panic (Delete/Put/etc. deref nil `d.db` after close).

- [ ] **Step 3: Fix `Delete` (write lock + nil-check)** — in `database/DbRocksDB.go`:
```go
func (db *BlockchainDB) Delete(key []byte) error {
	if db == nil {
		return fmt.Errorf("database is nil")
	}
	if len(key) == 0 {
		return errors.New("key cannot be empty")
	}
	db.mutex.Lock()          // DB-H5: write lock (was RLock)
	defer db.mutex.Unlock()
	if db.db == nil {        // DB-H5: guard closed DB (was missing)
		return fmt.Errorf("database is closed")
	}
	wo := gorocksdb.NewDefaultWriteOptions()
	defer wo.Destroy()
	return db.db.Delete(wo, key)
}
```

- [ ] **Step 4: Add the `db.db == nil` guard to the other ops** — immediately after each function's existing lock acquisition (keep their existing lock type: `Put`→`Lock`, `IsKey`/`LoadAll`/`LoadAllKeys`→`RLock`), insert the closed-DB guard with the correct return arity:
  - `Put` (after `db.mutex.Lock()`): `if db.db == nil { return fmt.Errorf("database is closed") }`
  - `IsKey` (after `db.mutex.RLock()`): `if db.db == nil { return false, fmt.Errorf("database is closed") }`
  - `LoadAll` (after `db.mutex.RLock()`): `if db.db == nil { return nil, fmt.Errorf("database is closed") }`
  - `LoadAllKeys` (after `db.mutex.RLock()`): `if db.db == nil { return nil, fmt.Errorf("database is closed") }`
  (`Get` already has this guard — leave it.)

- [ ] **Step 5: Run + build** — `GOROOT=… go test ./database/ -race -v && GOROOT=… go build ./...` → PASS (no panic, no data race), build OK.
- [ ] **Step 6: Commit** — `OB-119 DB-H5: Delete under write lock + closed-DB nil guards on all ops` + Co-Authored-By.

---

## Task 3: DB-H6 — remove LOCK-file deletion; rely on RocksDB's lock

**Files:** Modify `database/DbRocksDB.go` (`InitPermanent`); test `database/db_concurrency_test.go`.

- [ ] **Step 1: Remove the manual LOCK-file deletion** — in `InitPermanent`, delete the block that stats `dbPath` and `os.Remove`s the `LOCK` file (the `lockFile := filepath.Join(dbPath, "LOCK")` … `os.Remove(lockFile)` section). RocksDB's own OS advisory lock handles single-instance + stale-lock-after-crash. If removing this makes `os` or `filepath` unused, drop those imports too (check the rest of the file first — they are likely still used elsewhere).

- [ ] **Step 2: Wrap the `OpenDb` error** — where `db.db, err = gorocksdb.OpenDb(opts, dbPath)` is followed by the error check, make the error operator-clear:
```go
	db.db, err = gorocksdb.OpenDb(opts, dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database at %s (another node instance may be running on this data dir, or it is corrupt): %w", dbPath, err)
	}
```

- [ ] **Step 3: Test — no LOCK removal + second-open fails** — append to `database/db_concurrency_test.go`:
```go
import "os" // add if not present

func TestInitPermanentNoLockRemovalAndSecondOpenFails(t *testing.T) {
	dir := t.TempDir()
	a := &BlockchainDB{}
	first, err := a.InitPermanent(dir)
	if err != nil {
		t.Skipf("RocksDB unavailable: %v", err)
	}
	defer first.Close()
	// LOCK file must still exist (we no longer delete it)
	if _, err := os.Stat(dir + "/LOCK"); err != nil {
		t.Fatalf("RocksDB LOCK file should exist while the DB is open: %v", err)
	}
	// A second open on the same live directory must FAIL (RocksDB single-instance lock),
	// not corrupt the DB.
	b := &BlockchainDB{}
	if _, err := b.InitPermanent(dir); err == nil {
		t.Fatal("second InitPermanent on a live DB dir should fail (lock held), got nil error")
	}
}
```

- [ ] **Step 4: Run + build** — `GOROOT=… go test ./database/ -run TestInitPermanentNoLockRemoval -v && GOROOT=… go build ./...` → PASS (skips if RocksDB unavailable; otherwise the second open errors). Also grep-confirm no `os.Remove(*LOCK*)` remains in `database/`.
- [ ] **Step 5: Commit** — `OB-119 DB-H6: stop deleting RocksDB LOCK file; rely on its single-instance lock + clearer open error` + Co-Authored-By.

---

## Final verification
- [ ] `GOROOT=… go build ./...` → exit 0.
- [ ] `GOROOT=… go test ./database/ -race` → PASS (or CGO-skips; the pure assertions run).
- [ ] Update `SECURITY_AUDIT.md` reconciliation: move **DB-H4, DB-H5, DB-H6, DB-M8** to FIXED (atomic Close, Delete write-lock + nil guards, no LOCK-file deletion).

## Deferred (not in this plan)
- The `MainDB = nil` global-pointer write on the shutdown path (pre-existing; benign because every method nil-checks its receiver first). Remaining OPEN reconciliation items (CW-H2, NP-H2/H6/H10, WH-H3, the mediums, deferred-by-design DB-C4 / DEX / RPC pooling).

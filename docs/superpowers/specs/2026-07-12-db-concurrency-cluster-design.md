# Database Concurrency Cluster — DB-H4, DB-H5, DB-H6 (+ DB-M8)

**Date:** 2026-07-12
**Branch:** `security-fixes`
**Source:** `SECURITY_AUDIT.md` reconciliation — four coupled RocksDB-layer concurrency/integrity findings.

## Context

The DB abstraction is `BlockchainDB` (`database/DbRocksDB.go`), a global singleton `database.MainDB`, wrapping a `*gorocksdb.DB` behind a `sync.RWMutex`. **RocksDB is itself thread-safe** for Get/Put/Delete; the Go mutex exists only to guard the **`d.db` pointer lifecycle** (open/close/nil) — so the correct discipline is: every data op holds the lock and nil-checks `d.db`; `Close`/`Init` (which replace the pointer) hold it and are the only writers of `d.db`. The four findings are all violations of that discipline.

### Ground truth (from exploration)
```go
type BlockchainDB struct {
	db    *gorocksdb.DB
	mutex sync.RWMutex   // non-reentrant
}
var MainDB *BlockchainDB
```
- Op locking: `Get`/`IsKey`/`LoadAll`/`LoadAllKeys` → `RLock`; `Put` → `Lock`; **`Delete` → `RLock` and no `d.db==nil` check** (DB-H5). Only `Get` currently nil-checks `d.db`.
- `Close()` (`DbRocksDB.go:98-164`): spawns goroutines with a 1s inner + 5s outer timeout; on timeout runs `d.db.Close(); d.db = nil` **without the mutex** (DB-H4).
- `CloseDB()` (`blockchaindb.go:35-47`): `MainDB.mutex.Lock(); MainDB.Close(); MainDB.mutex.Unlock()` — pre-locks, then `Close()` re-`Lock()`s the same non-reentrant mutex → never acquires → the 1s timeout fires **every time** → always takes the unprotected path (DB-M8 driving DB-H4).
- `InitPermanent()` (`DbRocksDB.go:42-50`): unconditionally `os.Remove(dbPath/LOCK)` before `gorocksdb.OpenDb` (DB-H6).
- `MainDB` is hit by ~10–15 concurrent goroutines (RPC, sync, tx, nonce, block processing, account/state stores). `CloseDB()` is a deferred shutdown call (`cmd/mining/main.go:43`).

## Decisions (confirmed)
1. **`Close()` blocks** until in-flight ops finish, then closes atomically — the timeout/forced-cleanup machinery is removed (it bounded shutdown by corrupting the DB).
2. **Remove the manual LOCK-file deletion** and rely on RocksDB's built-in OS-level (`flock`) single-instance lock (stale locks from a crash are auto-released by the OS; a live instance's lock makes a second `OpenDb` fail cleanly).

## Design

### DB-H5 — `Delete` uses the write lock + nil-check; add nil-checks to all ops

`Delete` becomes (matching `Put`'s existing write-lock pattern) and nil-checks `d.db`:
```go
func (db *BlockchainDB) Delete(key []byte) error {
	if db == nil { return fmt.Errorf("database is nil") }
	if len(key) == 0 { return errors.New("key cannot be empty") }
	db.mutex.Lock()          // DB-H5: write lock (was RLock)
	defer db.mutex.Unlock()
	if db.db == nil { return fmt.Errorf("database is closed") }  // was missing
	wo := gorocksdb.NewDefaultWriteOptions()
	defer wo.Destroy()
	return db.db.Delete(wo, key)
}
```
Additionally, add the same `if <recv>.db == nil { return …"database is closed" }` guard (immediately after acquiring the lock) to every op that lacks it — `Put`, `IsKey`, `LoadAll`, `LoadAllKeys` — so no op can dereference `d.db` after `Close()` nils it under the lock. (`Get` already has this guard; keep it. Keep `Get`/`IsKey`/`LoadAll*` on `RLock`; keep `Put` on `Lock`.)

### DB-H4 + DB-M8 — simple, correct `Close`/`CloseDB`

Replace the entire goroutine/timeout `Close()` with the atomic pattern:
```go
func (d *BlockchainDB) Close() {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	if d.db == nil {
		return // already closed / never opened
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
This blocks until any in-flight op releases the (R)lock, then closes under the exclusive lock — no unprotected mutation, so no op can race a nil-ing `d.db`. `Close()` is idempotent (nil-check).

`CloseDB()` no longer pre-locks (Close self-locks, so the reentrant double-`Lock` is gone):
```go
func CloseDB() error {
	if MainDB != nil {
		MainDB.Close() // acquires the mutex itself
		MainDB = nil
	}
	return nil
}
```
(Note: `MainDB = nil` after `Close()` is a plain pointer write on the shutdown path; the shutdown sequence is single-threaded relative to setting the global — unchanged from before. The important fix is that `Close()` runs its DB teardown under its own lock.)

### DB-H6 — remove the LOCK-file deletion; rely on RocksDB's lock

Delete the `os.Stat(dbPath)` → `os.Remove(lockFile)` block in `InitPermanent` (`DbRocksDB.go:42-50`). Do NOT delete the RocksDB `LOCK` file. On `gorocksdb.OpenDb` failure, wrap the error with a clear operator hint:
```go
db.db, err = gorocksdb.OpenDb(opts, dbPath)
if err != nil {
	return nil, fmt.Errorf("failed to open database at %s (another node instance may be running on this data dir, or the dir is corrupt): %w", dbPath, err)
}
```
Rationale: RocksDB takes an OS advisory lock on `LOCK`; a crashed process's lock is released by the OS automatically (crash recovery still works without manual removal), while a live process's lock correctly blocks a concurrent open — the exact single-instance guarantee the manual removal was defeating. No separate pidfile/flock is added (redundant with RocksDB's own lock).

## Non-goals
- Changing the mutex model (still a single `RWMutex` guarding the pointer) or making per-op locking finer-grained (RocksDB's internal concurrency is sufficient; the current coarse lock is safe once the ops are consistent).
- A bounded/timed shutdown (removed — blocking close is correct); a higher-level shutdown deadline, if ever wanted, belongs to the caller, not to a force-close that corrupts data.
- Any consensus/wire/format change. This is node-local reliability.

## Error handling / determinism
- Node-local; no consensus impact.
- After `Close()`, all ops return a clean `"database is closed"` error instead of panicking.
- Concurrent `Close()` calls are serialized and idempotent (second sees `d.db == nil`).

## Testing

Where a DB instance is needed, use `InitInMemory()` (CGO/RocksDB) and `t.Skip` if it is unavailable; pure-logic assertions run regardless.

- **DB-H5 lock/nil:** after `Close()`, `Delete`/`Put`/`IsKey`/`LoadAll`/`LoadAllKeys` on the closed DB return the `"database is closed"` error and do NOT panic. (In-memory DB; skip if unavailable.)
- **DB-H4/M8 no deadlock, no double-close panic:** `CloseDB()` (or `db.Close()`) completes without hanging; calling `Close()` twice is safe (idempotent). Assert `MainDB == nil` after `CloseDB()`.
- **DB-H4 race (`-race`):** spawn N goroutines doing `Get`/`Put`/`Delete` on an in-memory DB while another goroutine calls `Close()`; assert no panic and no data race (ops either succeed or get `"database is closed"`). This is the core regression — it would fail under the old unprotected-fallback `Close`.
- **DB-H6:** assert (by code inspection / a focused test) that `InitPermanent` no longer references/removes a `LOCK` file, and that a second `OpenDb` on a directory already opened by a live handle returns an error (open the same in-memory/temp path twice → the second fails). If a real second-open test is impractical, assert the removed-code fact and the wrapped error message.

Tests run with `GOROOT=/home/wonabru/sdk/go1.24.0`.

## Files touched
- `database/DbRocksDB.go` — `Delete` (Lock+nil-check), nil-checks on `Put`/`IsKey`/`LoadAll`/`LoadAllKeys`, rewritten `Close`, removed LOCK deletion + wrapped `OpenDb` error in `InitPermanent`.
- `database/blockchaindb.go` — simplified `CloseDB`.
- `database/db_concurrency_test.go` (new) — the tests above.

## Rollout / commit plan
`OB-xx` commits (node-local, not `(CONSENSUS)`):
1. DB-H5: `Delete`→`Lock`+nil-check and add nil-checks to `Put`/`IsKey`/`LoadAll`/`LoadAllKeys` (+ closed-DB tests).
2. DB-H4/DB-M8: rewrite `Close()` (atomic, blocking) + simplify `CloseDB()` (+ no-deadlock/idempotent/race tests).
3. DB-H6: remove LOCK-file deletion + wrap `OpenDb` error (+ second-open/removed-code test).

Not "done" until `database` builds and the tests pass, and `SECURITY_AUDIT.md` reconciliation moves DB-H4/H5/H6 and DB-M8 to FIXED.

## Deferred (follow-ups)
- The remaining OPEN reconciliation items (CW-H2 key zeroing, NP-H2/H6/H10, WH-H3, the mediums, deferred-by-design DB-C4 / DEX carve-outs / RPC pooling).

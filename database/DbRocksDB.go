package database

import (
	"errors"
	"fmt"
	"github.com/qwid-org/qwid-node/logger"
	"os"
	"sync"

	gorocksdb "github.com/linxGnu/grocksdb"
	commoneth "github.com/qwid-org/qwid-node/common"
)

type BlockchainDB struct {
	db    *gorocksdb.DB
	mutex sync.RWMutex
}

func (db *BlockchainDB) GetLdb() *gorocksdb.DB {
	if db == nil {
		return nil
	}
	return db.db
}

// Block-cache sizes. They differ on purpose: the writer is the node itself,
// while the reader is a SEPARATE process (the explorer opens the same data as a
// secondary) that commonly runs on the same host. Giving both the same cache
// would quietly double the memory a single machine needs to run a node and its
// explorer, so the reader gets half.
const (
	writerBlockCacheBytes uint64 = 256 * 1024 * 1024
	readerBlockCacheBytes uint64 = 128 * 1024 * 1024
)

// applyBloomAndCache installs a bloom filter policy and a block cache.
//
// Without a filter policy every NEGATIVE lookup (IsKey/Get of an absent key)
// walks the index of every SST file; the sync census asks "is this transaction
// in the DB" for THOUSANDS of absent hashes per block, and on a grown database
// that took ~10ms per lookup - blocks with many missing transactions needed 30s
// to census while blocks with few were instant. A 10-bit bloom answers
// "definitely not here" from memory.
//
// Filters are written into SST files, so they appear as new files are written
// and old ones are rewritten by compaction. A read-only or secondary opener
// creates no files at all: it gets no filters of its own, and instead READS the
// ones the writer already stored — which requires naming the same policy here,
// since RocksDB ignores a filter it cannot match to the configured policy. The
// block cache helps it either way.
func applyBloomAndCache(opts *gorocksdb.Options, cacheBytes uint64) {
	bbto := gorocksdb.NewDefaultBlockBasedTableOptions()
	bbto.SetFilterPolicy(gorocksdb.NewBloomFilterFull(10))
	bbto.SetBlockCache(gorocksdb.NewLRUCache(cacheBytes))
	opts.SetBlockBasedTableFactory(bbto)
}

func (db *BlockchainDB) InitPermanent(dbPath string) (*BlockchainDB, error) {
	if db == nil {
		return nil, fmt.Errorf("database is nil")
	}
	var err error
	db.mutex.Lock()
	defer db.mutex.Unlock()

	// Create the database directory if it doesn't exist
	if err := os.MkdirAll(dbPath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create database directory: %w", err)
	}

	opts := gorocksdb.NewDefaultOptions()
	opts.SetCreateIfMissing(true)
	opts.SetErrorIfExists(false) // Don't error if database exists

	// Set max open files to prevent "too many open files" error
	opts.SetMaxOpenFiles(1000)

	// Set write buffer size and max write buffer number
	opts.SetWriteBufferSize(64 * 1024 * 1024) // 64MB
	opts.SetMaxWriteBufferNumber(3)

	applyBloomAndCache(opts, writerBlockCacheBytes)

	db.db, err = gorocksdb.OpenDb(opts, dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database at %s (another node instance may be running on this data dir, or it is corrupt): %w", dbPath, err)
	}

	return db, nil
}

// InitReadOnly opens the database without taking the primary write lock, so a
// diagnostic tool can inspect it while a node is running. It prefers a RocksDB
// secondary instance (supported alongside a live primary) and falls back to a
// plain read-only open when the secondary directory cannot be used.
func (db *BlockchainDB) InitReadOnly(dbPath string, secondaryPath string) (*BlockchainDB, error) {
	if db == nil {
		return nil, fmt.Errorf("database is nil")
	}
	db.mutex.Lock()
	defer db.mutex.Unlock()

	opts := gorocksdb.NewDefaultOptions()
	opts.SetCreateIfMissing(false)
	opts.SetMaxOpenFiles(1000)
	applyBloomAndCache(opts, readerBlockCacheBytes)

	if secondaryPath != "" {
		if err := os.MkdirAll(secondaryPath, 0755); err == nil {
			sdb, serr := gorocksdb.OpenDbAsSecondary(opts, dbPath, secondaryPath)
			if serr == nil {
				db.db = sdb
				return db, nil
			}
			logger.GetLogger().Println("cannot open db as secondary, falling back to read-only:", serr)
		}
	}

	rdb, err := gorocksdb.OpenDbForReadOnly(opts, dbPath, false)
	if err != nil {
		return nil, fmt.Errorf("failed to open database read-only at %s: %w", dbPath, err)
	}
	db.db = rdb
	return db, nil
}

func (db *BlockchainDB) InitInMemory() (*BlockchainDB, error) {
	if db == nil {
		return nil, fmt.Errorf("database is nil")
	}
	var err error
	db.mutex.Lock()
	defer db.mutex.Unlock()
	opts := gorocksdb.NewDefaultOptions()
	opts.SetCreateIfMissing(true)
	opts.SetEnv(gorocksdb.NewMemEnv())
	db.db, err = gorocksdb.OpenDb(opts, "qwid_node")
	if err != nil {
		return nil, err
	}
	return db, nil
}

func (db *BlockchainDB) GetNode(hash commoneth.Hash) ([]byte, error) {
	if db == nil {
		return nil, fmt.Errorf("database is nil")
	}
	return db.Get(hash[:])
}

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

func (db *BlockchainDB) Put(k []byte, v []byte) error {
	if db == nil {
		return fmt.Errorf("database is nil")
	}
	if len(k) == 0 {
		return errors.New("key cannot be empty")
	}

	// RLock, not Lock: the mutex guards the LIFECYCLE of the db handle (Close
	// nil-ing db.db under the write lock, DB-H4), not the database contents —
	// RocksDB is internally thread-safe for concurrent Put/Get/Delete. Taking
	// the exclusive lock here serialized every DB operation in the process
	// behind every write: during sync catch-up the incoming "bx" transaction
	// stream (hundreds of Puts per second) starved the block-apply goroutine's
	// thousands of reads (Go's RWMutex is writer-preferring), slowing block
	// application ~60x until the receive loops stopped.
	db.mutex.RLock()
	defer db.mutex.RUnlock()

	if db.db == nil {
		return fmt.Errorf("database is closed")
	}

	wo := gorocksdb.NewDefaultWriteOptions()
	defer wo.Destroy()

	// Make a copy of the value to ensure it's not modified after the Put
	valueCopy := make([]byte, len(v))
	copy(valueCopy, v)

	err := db.db.Put(wo, k, valueCopy)
	if err != nil {
		return fmt.Errorf("failed to put key-value pair: %w", err)
	}
	return nil
}

func (db *BlockchainDB) LoadAllKeys(prefix []byte) ([][]byte, error) {
	if db == nil {
		return nil, fmt.Errorf("database is nil")
	}
	if len(prefix) == 0 {
		return nil, errors.New("prefix cannot be empty")
	}
	db.mutex.RLock()
	defer db.mutex.RUnlock()

	if db.db == nil {
		return nil, fmt.Errorf("database is closed")
	}

	ro := gorocksdb.NewDefaultReadOptions()
	defer ro.Destroy()

	iter := db.db.NewIterator(ro)
	defer iter.Close()

	keys := [][]byte{}
	for iter.Seek(prefix); iter.ValidForPrefix(prefix); iter.Next() {
		key := make([]byte, len(iter.Key().Data()))
		copy(key, iter.Key().Data())
		keys = append(keys, key)
	}

	if err := iter.Err(); err != nil {
		return nil, err
	}
	return keys, nil
}

func (db *BlockchainDB) LoadAll(prefix []byte) ([][]byte, error) {
	if db == nil {
		return nil, fmt.Errorf("database is nil")
	}
	if len(prefix) == 0 {
		return nil, errors.New("prefix cannot be empty")
	}
	db.mutex.RLock()
	defer db.mutex.RUnlock()

	if db.db == nil {
		return nil, fmt.Errorf("database is closed")
	}

	ro := gorocksdb.NewDefaultReadOptions()
	defer ro.Destroy()

	iter := db.db.NewIterator(ro)
	defer iter.Close()

	values := [][]byte{}
	for iter.Seek(prefix); iter.ValidForPrefix(prefix); iter.Next() {
		value := make([]byte, len(iter.Value().Data()))
		copy(value, iter.Value().Data())
		values = append(values, value)
	}

	if err := iter.Err(); err != nil {
		return nil, err
	}
	return values, nil
}

func (d *BlockchainDB) Get(key []byte) ([]byte, error) {
	if d == nil {
		return nil, fmt.Errorf("database is nil")
	}

	d.mutex.RLock()
	defer d.mutex.RUnlock()

	if d.db == nil {
		return nil, fmt.Errorf("database is closed")
	}

	ro := gorocksdb.NewDefaultReadOptions()
	defer ro.Destroy()

	value, err := d.db.Get(ro, key)
	if err != nil {
		return nil, err
	}
	defer value.Free()

	if !value.Exists() {
		return nil, fmt.Errorf("key not found")
	}

	// Make a copy of the data to ensure it's not modified after the Get
	data := make([]byte, len(value.Data()))
	copy(data, value.Data())
	return data, nil
}

func (db *BlockchainDB) IsKey(key []byte) (bool, error) {
	if db == nil {
		return false, fmt.Errorf("database is nil")
	}
	if len(key) == 0 {
		return false, errors.New("key cannot be empty")
	}
	db.mutex.RLock()
	defer db.mutex.RUnlock()
	if db.db == nil {
		return false, fmt.Errorf("database is closed")
	}
	ro := gorocksdb.NewDefaultReadOptions()
	defer ro.Destroy()
	// GetPinned, not Get: an existence check must not copy the value into Go
	// memory. Snapshot values here run to megabytes, and this is called in a loop
	// over heights.
	value, err := db.db.GetPinned(ro, key)
	if err != nil {
		return false, err
	}
	defer value.Destroy()
	return value.Exists(), nil
}

func (db *BlockchainDB) Delete(key []byte) error {
	if db == nil {
		return fmt.Errorf("database is nil")
	}
	if len(key) == 0 {
		return errors.New("key cannot be empty")
	}
	// RLock for the same reason as Put: the mutex only protects the handle
	// against Close/Init, and RocksDB deletes are thread-safe. (The DB-H5 fix
	// this line carried was the missing closed-DB guard below, which stays.)
	db.mutex.RLock()
	defer db.mutex.RUnlock()
	if db.db == nil { // DB-H5: guard closed DB (was missing)
		return fmt.Errorf("database is closed")
	}
	wo := gorocksdb.NewDefaultWriteOptions()
	defer wo.Destroy()
	return db.db.Delete(wo, key)
}

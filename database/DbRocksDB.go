package database

import (
	"errors"
	"fmt"
	"github.com/wonabru/qwid-node/logger"
	"os"
	"sync"

	gorocksdb "github.com/linxGnu/grocksdb"
	commoneth "github.com/wonabru/qwid-node/common"
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

	db.mutex.Lock()
	defer db.mutex.Unlock()

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
	db.mutex.Lock() // DB-H5: write lock (was RLock)
	defer db.mutex.Unlock()
	if db.db == nil { // DB-H5: guard closed DB (was missing)
		return fmt.Errorf("database is closed")
	}
	wo := gorocksdb.NewDefaultWriteOptions()
	defer wo.Destroy()
	return db.db.Delete(wo, key)
}

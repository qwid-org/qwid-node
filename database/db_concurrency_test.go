package database

import (
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

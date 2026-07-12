package database

import (
	"sync"
	"sync/atomic"
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

package database

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestBatchCommitAppliesAllOps verifies a batch applies its buffered Puts and
// Deletes atomically on CommitBatch, and that nothing lands before commit.
func TestBatchCommitAppliesAllOps(t *testing.T) {
	db := tempDB(t)

	// Seed a key that the batch will delete.
	require.NoError(t, db.Put([]byte("k-del"), []byte("old")))

	b := NewBatch()
	b.Put([]byte("k1"), []byte("v1"))
	b.Put([]byte("k2"), []byte("v2"))
	b.Delete([]byte("k-del"))
	require.Equal(t, 3, b.Count())

	// Before commit, nothing from the batch is visible.
	if v, _ := db.Get([]byte("k1")); len(v) != 0 {
		t.Fatalf("k1 must not exist before CommitBatch, got %q", v)
	}
	if v, _ := db.Get([]byte("k-del")); string(v) != "old" {
		t.Fatalf("k-del must still hold the pre-batch value before commit, got %q", v)
	}

	require.NoError(t, db.CommitBatch(b))

	// After commit, all ops are applied.
	v1, err := db.Get([]byte("k1"))
	require.NoError(t, err)
	require.Equal(t, "v1", string(v1))
	v2, err := db.Get([]byte("k2"))
	require.NoError(t, err)
	require.Equal(t, "v2", string(v2))
	if v, _ := db.Get([]byte("k-del")); len(v) != 0 {
		t.Fatalf("k-del must be deleted after commit, got %q", v)
	}
}

// TestBatchKeyValueReuseIsSafe confirms the caller may reuse/mutate the slices
// passed to Put after the call (RocksDB copies them into the batch immediately).
func TestBatchKeyValueReuseIsSafe(t *testing.T) {
	db := tempDB(t)

	key := []byte("kkkk")
	val := []byte("vvvv")
	b := NewBatch()
	b.Put(key, val)
	// Mutate the backing arrays after buffering.
	for i := range key {
		key[i] = 'x'
	}
	for i := range val {
		val[i] = 'y'
	}
	require.NoError(t, db.CommitBatch(b))

	got, err := db.Get([]byte("kkkk"))
	require.NoError(t, err)
	require.Equal(t, "vvvv", string(got), "the value buffered before mutation must be what lands")
}

// TestCommitBatchNilAndEmpty confirms committing a nil or empty batch is a no-op.
func TestCommitBatchNilAndEmpty(t *testing.T) {
	db := tempDB(t)
	require.NoError(t, db.CommitBatch(nil))
	require.NoError(t, db.CommitBatch(NewBatch()))
}

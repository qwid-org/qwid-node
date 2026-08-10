package database

import (
	"encoding/binary"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func heightKey(h int64) []byte {
	b := make([]byte, 10)
	copy(b, []byte("HT"))
	binary.BigEndian.PutUint64(b[2:], uint64(h))
	return b
}

func tempDB(t *testing.T) *BlockchainDB {
	t.Helper()
	db := &BlockchainDB{}
	pdb, err := db.InitPermanent(filepath.Join(t.TempDir(), "blockchain"))
	require.NoError(t, err)
	t.Cleanup(pdb.Close)
	return pdb
}

func TestLastContiguousHeight(t *testing.T) {
	db := tempDB(t)

	got, err := LastContiguousHeight(db, heightKey)
	require.NoError(t, err)
	assert.Equal(t, int64(-1), got, "empty database has no stored height")

	for h := int64(0); h <= 137; h++ {
		require.NoError(t, db.Put(heightKey(h), []byte{byte(h)}))
	}
	got, err = LastContiguousHeight(db, heightKey)
	require.NoError(t, err)
	assert.Equal(t, int64(137), got)

	// A single stored height is the boundary case the exponential probe must not
	// overshoot.
	db2 := tempDB(t)
	require.NoError(t, db2.Put(heightKey(0), []byte{1}))
	got, err = LastContiguousHeight(db2, heightKey)
	require.NoError(t, err)
	assert.Equal(t, int64(0), got)
}

func TestLastContiguousHeightNilDB(t *testing.T) {
	got, err := LastContiguousHeight(nil, heightKey)
	require.NoError(t, err)
	assert.Equal(t, int64(-1), got)
}

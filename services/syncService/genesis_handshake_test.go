package syncServices

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/database"
	"github.com/qwid-org/qwid-node/message"
)

// withTempDB points database.MainDB at a throwaway RocksDB so these tests never
// touch the operator's real blockchain database.
func withTempDB(t *testing.T) {
	t.Helper()
	db := &database.BlockchainDB{}
	pdb, err := db.InitPermanent(filepath.Join(t.TempDir(), "blockchain"))
	if err != nil {
		t.Skipf("RocksDB unavailable: %v", err)
	}
	saved := database.MainDB
	database.MainDB = pdb
	t.Cleanup(func() {
		pdb.Close()
		database.MainDB = saved
	})
}

// withGenesisHash pins the node's genesis hash for one test, so the check does
// not depend on whatever chain the suite's database happens to hold.
func withGenesisHash(t *testing.T, h []byte) {
	t.Helper()
	saved := localGenesisHash
	localGenesisHash = h
	t.Cleanup(func() { localGenesisHash = saved })
}

func TestWithGenesisHashRestores(t *testing.T) {
	original := localGenesisHash

	t.Run("inner", func(t *testing.T) {
		withGenesisHash(t, []byte{1, 2, 3})
		if !bytes.Equal(localGenesisHash, []byte{1, 2, 3}) {
			t.Fatal("withGenesisHash did not set the hash")
		}
	})

	if !bytes.Equal(localGenesisHash, original) {
		t.Fatalf("withGenesisHash did not restore the hash: got %x, want %x", localGenesisHash, original)
	}
}

// TestGenerateSyncMsgHeightCarriesGenesis: a peer cannot check our chain against
// its own unless we say which chain we are on.
func TestGenerateSyncMsgHeightCarriesGenesis(t *testing.T) {
	withTempDB(t)

	want := bytes.Repeat([]byte{0xab}, 32)
	withGenesisHash(t, want)

	// Set up height and store a block hash so generateSyncMsgHeight can load it.
	height := int64(42)
	savedHeight := common.GetHeight()
	defer common.SetHeight(savedHeight)
	common.SetHeight(height)

	// Store the hash at the block-by-height key so LoadHashOfBlock can find it.
	blockHash := bytes.Repeat([]byte{0xcd}, 32)
	key := append(common.BlockByHeightDBPrefix[:], common.GetByteInt64(height)...)
	err := database.MainDB.Put(key, blockHash)
	if err != nil {
		t.Fatalf("failed to store block hash: %v", err)
	}

	raw := generateSyncMsgHeight()
	if len(raw) == 0 {
		t.Fatal("generateSyncMsgHeight produced empty bytes")
	}

	isValid, amsg := message.CheckValidMessage(raw)
	if !isValid {
		t.Fatal("generateSyncMsgHeight produced a message that does not validate")
	}
	txn := amsg.(message.TransactionsMessage).GetTransactionsBytes()

	got := txn[[2]byte{'G', 'B'}]
	if len(got) != 1 {
		t.Fatalf("GB entries = %d, expected 1", len(got))
	}
	if !bytes.Equal(got[0], want) {
		t.Fatalf("GB = %x, expected %x", got[0], want)
	}
}

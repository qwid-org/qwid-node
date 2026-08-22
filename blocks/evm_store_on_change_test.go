package blocks

import (
	"path/filepath"
	"testing"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/database"
	"github.com/qwid-org/qwid-node/logger"
)

// TestCommitEVMStateIfChanged: the block-apply paths call this every block, but
// a snapshot may be written only for blocks that actually touched contract
// state - otherwise the EV keyspace grows with chain length again.
func TestCommitEVMStateIfChanged(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

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

	InitStateDB() // fresh state; Load(-1) fails on the empty DB, which is fine

	// Contract-free block: nothing marked, nothing stored.
	if err := CommitEVMStateIfChanged(7); err != nil {
		t.Fatalf("CommitEVMStateIfChanged(7): %v", err)
	}
	if h, err := State.LastStoredHeight(); err != nil || h != -1 {
		t.Fatalf("snapshot zapisany mimo braku zmian: LastStoredHeight = %d, %v", h, err)
	}

	// Block with contract activity: EvaluateSCForBlock marks the state.
	var a [common.AddressLength]byte
	a[0] = 0xAA
	StateMutex.Lock()
	State.Nonces[a] = 9
	State.MarkChanged()
	StateMutex.Unlock()
	if err := CommitEVMStateIfChanged(8); err != nil {
		t.Fatalf("CommitEVMStateIfChanged(8): %v", err)
	}
	if h, err := State.LastStoredHeight(); err != nil || h != 8 {
		t.Fatalf("no snapshot was written after a change: LastStoredHeight = %d, %v", h, err)
	}

	// Next contract-free block: the flag was cleared by the store, so no new key.
	if err := CommitEVMStateIfChanged(9); err != nil {
		t.Fatalf("CommitEVMStateIfChanged(9): %v", err)
	}
	if h, err := State.LastStoredHeight(); err != nil || h != 8 {
		t.Fatalf("a snapshot was written for a block with no contract activity: LastStoredHeight = %d, %v", h, err)
	}
}

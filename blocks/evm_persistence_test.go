package blocks

import (
	"testing"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
)

// TestEVMStatePersistsAcrossReload deploys nothing but exercises the
// store/reload path directly on blocks.State.
func TestEVMStatePersistsAcrossReload(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	InitStateDB()

	var a [common.AddressLength]byte
	a[0] = 0xCD
	StateMutex.Lock()
	State.Codes[a] = []byte{0x01, 0x02, 0x03}
	State.Nonces[a] = 42
	State.StatesHashes[a] = map[common.Hash]common.Hash{{0x0A}: {0x0B}}
	StateMutex.Unlock()

	if err := CommitEVMState(100); err != nil {
		t.Skipf("DB not available: %v", err)
	}
	// Wipe in-memory state, then reload from DB.
	InitStateDB()
	if err := State.Load(100); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if State.Nonces[a] != 42 {
		t.Fatalf("nonce not persisted: %d", State.Nonces[a])
	}
	if State.StatesHashes[a][common.Hash{0x0A}] != (common.Hash{0x0B}) {
		t.Fatal("storage slot not persisted")
	}
}

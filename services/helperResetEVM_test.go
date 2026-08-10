package services

import (
	"testing"

	"github.com/qwid-org/qwid-node/blocks"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/core/stateDB"
	"github.com/qwid-org/qwid-node/logger"
)

// withFreshEVMState swaps blocks.State for an empty one and restores the
// original afterwards.
func withFreshEVMState(t *testing.T) {
	t.Helper()
	blocks.StateMutex.Lock()
	saved := blocks.State
	blocks.State = stateDB.CreateStateDB()
	blocks.StateMutex.Unlock()
	t.Cleanup(func() {
		blocks.StateMutex.Lock()
		blocks.State = saved
		blocks.StateMutex.Unlock()
	})
}

func evmNonceAt(addrByte byte) uint64 {
	var a [common.AddressLength]byte
	a[0] = addrByte
	blocks.StateMutex.RLock()
	defer blocks.StateMutex.RUnlock()
	return blocks.State.Nonces[a]
}

func setEVMNonce(addrByte byte, n uint64) {
	var a [common.AddressLength]byte
	a[0] = addrByte
	blocks.StateMutex.Lock()
	blocks.State.Nonces[a] = n
	blocks.StateMutex.Unlock()
}

// TestRevertVMToBlockHeightUsesClosestSnapshot reproduces the production log
// "could not reload EVM state on reset: key not found": the rewind target has
// no snapshot of its own because that block held no contract transaction. The
// closest snapshot below is exact - the state did not change since - so it must
// be loaded, and the snapshots of the abandoned branch above must be pruned.
func TestRevertVMToBlockHeightUsesClosestSnapshot(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	withTempDB(t)
	withFreshEVMState(t)

	// Contract activity at heights 3 and 7; heights 4-6 change nothing.
	setEVMNonce(0xAA, 3)
	blocks.StateMutex.Lock()
	err := blocks.State.Store(3)
	blocks.StateMutex.Unlock()
	if err != nil {
		t.Fatalf("Store(3): %v", err)
	}
	setEVMNonce(0xAA, 7)
	blocks.StateMutex.Lock()
	err = blocks.State.Store(7)
	blocks.StateMutex.Unlock()
	if err != nil {
		t.Fatalf("Store(7): %v", err)
	}

	// Rewind to 5: no snapshot at 5, closest is 3.
	if !RevertVMToBlockHeight(5) {
		t.Fatal("RevertVMToBlockHeight(5) zwrócił false")
	}
	if got := evmNonceAt(0xAA); got != 3 {
		t.Fatalf("stan EVM po rewindzie: nonce = %d, oczekiwano 3 (snapshot z wysokości 3)", got)
	}

	// The snapshot at 7 belongs to the abandoned branch and must be gone.
	blocks.StateMutex.RLock()
	last, err := blocks.State.LastStoredHeight()
	blocks.StateMutex.RUnlock()
	if err != nil || last != 3 {
		t.Fatalf("LastStoredHeight po rewindzie = %d, %v; oczekiwano 3 (snapshot 7 usunięty)", last, err)
	}
}

// TestRevertVMToBlockHeightWithoutAnySnapshot: a database from before EVM
// snapshots existed. The in-memory state must survive (wiping it would lose all
// contract state built during sync) and be marked changed, so the next applied
// block persists a full snapshot and later rewinds have a base.
func TestRevertVMToBlockHeightWithoutAnySnapshot(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	withTempDB(t)
	withFreshEVMState(t)

	setEVMNonce(0xBB, 42)

	if !RevertVMToBlockHeight(5) {
		t.Fatal("RevertVMToBlockHeight(5) zwrócił false")
	}
	if got := evmNonceAt(0xBB); got != 42 {
		t.Fatalf("stan EVM w pamięci został wyczyszczony mimo braku snapshotu: nonce = %d", got)
	}
	blocks.StateMutex.RLock()
	changed := blocks.State.ChangedSinceStore()
	blocks.StateMutex.RUnlock()
	if !changed {
		t.Fatal("po nieudanym wczytaniu stan musi być oznaczony jako zmieniony, " +
			"żeby następny blok zapisał pełny snapshot")
	}
}

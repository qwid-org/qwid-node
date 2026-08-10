package stateDB

import (
	"path/filepath"
	"testing"

	"github.com/wonabru/qwid-node/common"
	"github.com/wonabru/qwid-node/database"
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

// stateWithNonce is a minimal distinguishable state: the nonce identifies which
// snapshot a Load actually restored.
func stateWithNonce(n uint64) StateAccount {
	sa := CreateStateDB()
	var a [common.AddressLength]byte
	a[0] = 0xEE
	sa.Nonces[a] = n
	return sa
}

func nonceOf(sa *StateAccount) uint64 {
	var a [common.AddressLength]byte
	a[0] = 0xEE
	return sa.Nonces[a]
}

// TestSnapshotHeightsWithGaps: store-on-change leaves gaps at contract-free
// heights, so none of the lookups may assume contiguity. The old
// LastStoredHeight binary search did, and a gap at height 1 made it report
// genesis as the latest snapshot on every restart.
func TestSnapshotHeightsWithGaps(t *testing.T) {
	withTempDB(t)

	for _, h := range []int64{0, 5, 12} {
		sa := stateWithNonce(uint64(h + 100))
		if err := sa.Store(h); err != nil {
			t.Fatalf("Store(%d): %v", h, err)
		}
	}

	sa := CreateStateDB()
	if got, err := sa.LastStoredHeight(); err != nil || got != 12 {
		t.Fatalf("LastStoredHeight() = %d, %v; oczekiwano 12 mimo dziur 1-4 i 6-11", got, err)
	}
	if got, err := sa.ClosestStoredHeight(11); err != nil || got != 5 {
		t.Fatalf("ClosestStoredHeight(11) = %d, %v; oczekiwano 5", got, err)
	}
	if got, err := sa.ClosestStoredHeight(4); err != nil || got != 0 {
		t.Fatalf("ClosestStoredHeight(4) = %d, %v; oczekiwano 0", got, err)
	}
	if got, err := sa.ClosestStoredHeight(12); err != nil || got != 12 {
		t.Fatalf("ClosestStoredHeight(12) = %d, %v; oczekiwano 12 (dokładne trafienie)", got, err)
	}

	loaded := CreateStateDB()
	h, err := loaded.LoadAtOrBelow(11)
	if err != nil || h != 5 {
		t.Fatalf("LoadAtOrBelow(11) = %d, %v; oczekiwano 5", h, err)
	}
	if nonceOf(&loaded) != 105 {
		t.Fatalf("LoadAtOrBelow(11) wczytał zawartość innego snapshotu: nonce=%d, oczekiwano 105", nonceOf(&loaded))
	}
}

// TestLoadAtOrBelowNothingStored: with no snapshot at all the caller must get a
// clear error, not a silent partial load.
func TestLoadAtOrBelowNothingStored(t *testing.T) {
	withTempDB(t)
	sa := CreateStateDB()
	if _, err := sa.LoadAtOrBelow(100); err == nil {
		t.Fatal("LoadAtOrBelow bez żadnego snapshotu musi zwrócić błąd")
	}
	if got, err := sa.LastStoredHeight(); err != nil || got != -1 {
		t.Fatalf("LastStoredHeight() = %d, %v; oczekiwano -1", got, err)
	}
}

// TestRemoveStoredAbove: a rewind prunes the abandoned branch's snapshots, or a
// restart would resurrect state from a chain that no longer exists.
func TestRemoveStoredAbove(t *testing.T) {
	withTempDB(t)

	for _, h := range []int64{0, 5, 12, 20} {
		sa := stateWithNonce(uint64(h + 100))
		if err := sa.Store(h); err != nil {
			t.Fatalf("Store(%d): %v", h, err)
		}
	}
	sa := CreateStateDB()
	if err := sa.RemoveStoredAbove(5); err != nil {
		t.Fatalf("RemoveStoredAbove(5): %v", err)
	}
	if got, err := sa.LastStoredHeight(); err != nil || got != 5 {
		t.Fatalf("po RemoveStoredAbove(5) LastStoredHeight() = %d, %v; oczekiwano 5", got, err)
	}
	// The kept snapshots must still load.
	loaded := CreateStateDB()
	if h, err := loaded.LoadAtOrBelow(100); err != nil || h != 5 {
		t.Fatalf("LoadAtOrBelow(100) po pruningu = %d, %v; oczekiwano 5", h, err)
	}
}

// TestChangedSinceStoreLifecycle: the flag drives store-on-change, so its
// transitions ARE the persistence contract - set by MarkChanged, cleared by a
// successful Store or Load.
func TestChangedSinceStoreLifecycle(t *testing.T) {
	withTempDB(t)

	sa := stateWithNonce(1)
	if sa.ChangedSinceStore() {
		t.Fatal("świeży stan nie może być oznaczony jako zmieniony")
	}
	sa.MarkChanged()
	if !sa.ChangedSinceStore() {
		t.Fatal("MarkChanged nie ustawił flagi")
	}
	if err := sa.Store(3); err != nil {
		t.Fatalf("Store: %v", err)
	}
	if sa.ChangedSinceStore() {
		t.Fatal("udany Store musi wyzerować flagę - inaczej każdy blok zapisywałby snapshot")
	}

	sa.MarkChanged()
	if err := sa.Load(3); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if sa.ChangedSinceStore() {
		t.Fatal("udany Load musi wyzerować flagę - pamięć jest wtedy równa dyskowi")
	}
}

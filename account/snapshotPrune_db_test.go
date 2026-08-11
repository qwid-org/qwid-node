package account

import (
	"testing"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/database"
	"github.com/qwid-org/qwid-node/logger"
)

// Retention against a real database: the policy tests decide which heights may
// go, these check that the right keys actually disappear, that the meta key
// survives, and that a lookup still finds usable state afterwards.

func putSnapshot(t *testing.T, prefix [2]byte, height int64) {
	t.Helper()
	key := append(prefix[:], common.GetByteInt64(height)...)
	if err := database.MainDB.Put(key, []byte{1}); err != nil {
		t.Fatalf("put snapshot %d: %v", height, err)
	}
}

func snapshotExists(t *testing.T, prefix [2]byte, height int64) bool {
	t.Helper()
	key := append(prefix[:], common.GetByteInt64(height)...)
	ok, err := database.MainDB.IsKey(key)
	return err == nil && ok
}

func TestPruneRemovesOldSnapshotsAndKeepsTheRest(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	withHistoryTempDB(t)

	prefix := common.AccountsDBPrefix
	tip := int64(100_000)
	recent := tip - 10
	oldCheckpoint := common.SnapshotCheckpointInterval * 2
	oldOrdinary := oldCheckpoint + 5 // below the window, not a checkpoint

	for _, h := range []int64{0, oldOrdinary, oldCheckpoint, recent, tip} {
		putSnapshot(t, prefix, h)
	}
	setLastStoredHeightMeta(prefix, tip)

	removed, err := pruneSnapshots(prefix, tip)
	if err != nil {
		t.Fatalf("pruneSnapshots: %v", err)
	}
	if removed != 1 {
		t.Fatalf("removed %d snapshots, want 1", removed)
	}

	if snapshotExists(t, prefix, oldOrdinary) {
		t.Error("an old ordinary snapshot survived pruning")
	}
	for _, h := range []int64{0, oldCheckpoint, recent, tip} {
		if !snapshotExists(t, prefix, h) {
			t.Errorf("height %d was pruned but must be kept", h)
		}
	}
}

// The meta key lives under the same prefix and is 6 bytes where a snapshot key
// is 10. Deleting it would make the node load state from far below its tip on
// the next restart.
func TestPruneLeavesTheHeightMetaKeyAlone(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	withHistoryTempDB(t)

	prefix := common.AccountsDBPrefix
	tip := int64(100_000)
	putSnapshot(t, prefix, tip)
	putSnapshot(t, prefix, 42) // prunable
	setLastStoredHeightMeta(prefix, tip)

	if _, err := pruneSnapshots(prefix, tip); err != nil {
		t.Fatalf("pruneSnapshots: %v", err)
	}

	got, ok := lastStoredHeightMeta(prefix)
	if !ok {
		t.Fatal("the snapshot-height meta key was destroyed by pruning")
	}
	if got != tip {
		t.Fatalf("meta height = %d, want %d", got, tip)
	}
}

func TestClosestStoredSnapshotHeightFindsNearestBelow(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	withHistoryTempDB(t)

	prefix := common.AccountsDBPrefix
	for _, h := range []int64{0, 5_000, 9_000} {
		putSnapshot(t, prefix, h)
	}

	cases := map[int64]int64{
		9_500: 9_000, // between snapshots
		9_000: 9_000, // exact hit
		4_999: 0,     // only genesis below
		0:     0,
	}
	for ask, want := range cases {
		got, err := ClosestStoredSnapshotHeight(prefix, ask)
		if err != nil {
			t.Fatalf("ClosestStoredSnapshotHeight(%d): %v", ask, err)
		}
		if got != want {
			t.Errorf("asking for %d returned %d, want %d", ask, got, want)
		}
	}
}

func TestClosestStoredSnapshotHeightReportsNothingBelow(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	withHistoryTempDB(t)

	prefix := common.AccountsDBPrefix
	putSnapshot(t, prefix, 5_000)

	got, err := ClosestStoredSnapshotHeight(prefix, 4_999)
	if err != nil {
		t.Fatalf("ClosestStoredSnapshotHeight: %v", err)
	}
	if got != -1 {
		t.Fatalf("returned %d with nothing at or below, want -1", got)
	}
}

// After pruning, a rewind target anywhere below the tip must still resolve to
// some stored height — that is the whole safety argument for deleting anything.
func TestEveryRewindTargetStillResolvesAfterPruning(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	withHistoryTempDB(t)

	prefix := common.AccountsDBPrefix
	tip := common.SnapshotCheckpointInterval * 3
	for h := int64(0); h <= tip; h += 100 {
		putSnapshot(t, prefix, h)
	}

	if _, err := pruneSnapshots(prefix, tip); err != nil {
		t.Fatalf("pruneSnapshots: %v", err)
	}

	for _, target := range []int64{
		1, common.SnapshotCheckpointInterval - 1,
		common.SnapshotCheckpointInterval + 1,
		tip - common.SnapshotRetentionBlocks - 1,
		tip,
	} {
		got, err := ClosestStoredSnapshotHeight(prefix, target)
		if err != nil {
			t.Fatalf("lookup for %d: %v", target, err)
		}
		if got < 0 {
			t.Fatalf("a rewind to %d has no snapshot at or below it after pruning", target)
		}
	}
}

package account

import (
	"sort"
	"testing"

	"github.com/qwid-org/qwid-node/common"
)

// Account and staking snapshots are written as one full copy of the state under
// key prefix+height, on the live path once per block, and nothing ever removed
// them. Database size was therefore state-size x block-count and grew without
// bound: a node running since early August reached 1.2 TB where a freshly
// synced one held 4 GB.
//
// Pruning has to leave the node able to rewind. Two things depend on finding a
// snapshot: consistentRewindTarget walks down looking for a restorable height,
// and a restart loads the newest one. So the policy keeps a dense recent window
// for ordinary rewinds and sparse checkpoints below it so a deep rewind still
// lands somewhere.

func TestRetentionKeepsTheRecentWindow(t *testing.T) {
	tip := int64(100_000)
	heights := []int64{
		tip,
		tip - 1,
		tip - common.SnapshotRetentionBlocks + 1, // inside the window
		tip - common.SnapshotRetentionBlocks,     // the window edge
	}

	drop := snapshotsToPrune(heights, tip)

	if len(drop) != 0 {
		t.Fatalf("pruned %v from inside the retention window", drop)
	}
}

func TestRetentionDropsOldNonCheckpoints(t *testing.T) {
	tip := int64(100_000)
	old := tip - common.SnapshotRetentionBlocks - 1
	if old%common.SnapshotCheckpointInterval == 0 {
		old-- // make sure it is not a checkpoint
	}

	drop := snapshotsToPrune([]int64{old}, tip)

	if len(drop) != 1 || drop[0] != old {
		t.Fatalf("expected height %d to be pruned, got %v", old, drop)
	}
}

// Checkpoints are what a deep rewind lands on. Losing them would leave a node
// unable to rebuild any state older than the recent window.
func TestRetentionAlwaysKeepsCheckpoints(t *testing.T) {
	tip := int64(1_000_000)
	checkpoints := []int64{
		0,
		common.SnapshotCheckpointInterval,
		common.SnapshotCheckpointInterval * 7,
	}

	drop := snapshotsToPrune(checkpoints, tip)

	if len(drop) != 0 {
		t.Fatalf("pruned checkpoints %v", drop)
	}
}

// Genesis must survive whatever else goes: it is the only height from which a
// node can rebuild everything.
func TestRetentionNeverPrunesGenesis(t *testing.T) {
	drop := snapshotsToPrune([]int64{0}, 10_000_000)

	for _, h := range drop {
		if h == 0 {
			t.Fatal("genesis snapshot was pruned")
		}
	}
}

// Nothing above the tip may be touched — those belong to the rewind path, which
// removes them deliberately, and confusing the two would delete state the node
// is about to use.
func TestRetentionIgnoresHeightsAboveTheTip(t *testing.T) {
	tip := int64(50_000)

	drop := snapshotsToPrune([]int64{tip + 1, tip + 500}, tip)

	if len(drop) != 0 {
		t.Fatalf("pruned heights above the tip: %v", drop)
	}
}

// The property that matters: after pruning, every height from genesis to the
// tip still has a reachable snapshot at or below it, and never further than one
// checkpoint interval away.
func TestAfterPruningEveryHeightStillHasASnapshotBelow(t *testing.T) {
	tip := int64(200_000)
	all := make([]int64, 0, tip/10+1)
	for h := int64(0); h <= tip; h += 10 { // snapshots every 10 blocks
		all = append(all, h)
	}

	drop := snapshotsToPrune(all, tip)
	dropped := make(map[int64]bool, len(drop))
	for _, h := range drop {
		dropped[h] = true
	}
	kept := make([]int64, 0, len(all))
	for _, h := range all {
		if !dropped[h] {
			kept = append(kept, h)
		}
	}
	sort.Slice(kept, func(i, j int) bool { return kept[i] < kept[j] })

	if len(kept) == 0 {
		t.Fatal("pruning removed every snapshot")
	}
	if kept[0] != 0 {
		t.Fatalf("lowest kept snapshot is %d, want genesis", kept[0])
	}
	for i := 1; i < len(kept); i++ {
		if gap := kept[i] - kept[i-1]; gap > common.SnapshotCheckpointInterval {
			t.Fatalf("gap of %d blocks between kept snapshots %d and %d — a rewind "+
				"into that range has nothing to land on", gap, kept[i-1], kept[i])
		}
	}
	// And the whole point: far fewer than we started with.
	if len(kept) >= len(all)/2 {
		t.Fatalf("kept %d of %d snapshots — pruning is not reclaiming anything",
			len(kept), len(all))
	}
}

func TestRetentionHandlesEmptyInput(t *testing.T) {
	if drop := snapshotsToPrune(nil, 1000); len(drop) != 0 {
		t.Fatalf("pruned %v from an empty set", drop)
	}
}

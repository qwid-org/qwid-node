package stateDB

import (
	"sort"
	"testing"

	"github.com/qwid-org/qwid-node/common"
)

// S6-04: EVM snapshots are store-on-change, so a missing height means "same
// as the closest snapshot below". Pruning must keep, for every point a rewind
// may land on, the snapshot that state is read from.
func TestEVMSnapshotsToPruneKeepsTheStateOfEveryCheckpoint(t *testing.T) {
	savedW, savedC := common.SnapshotRetentionBlocks, common.SnapshotCheckpointInterval
	common.SnapshotRetentionBlocks, common.SnapshotCheckpointInterval = 100, 50
	defer func() { common.SnapshotRetentionBlocks, common.SnapshotCheckpointInterval = savedW, savedC }()

	tip := int64(300) // dense window: >= 200
	heights := []int64{3, 10, 40, 49, 51, 60, 99, 120, 140, 160, 199, 205, 250, 320}
	drop := evmSnapshotsToPrune(heights, tip)
	sort.Slice(drop, func(i, j int) bool { return drop[i] < drop[j] })

	// kept: 3 (earliest state), 49 (state at checkpoint 50), 99 (at 100),
	// 140 (at 150), 199 (state at the window floor and at checkpoint 200 side),
	// everything >= 200.
	want := []int64{10, 40, 51, 60, 120, 160}
	if len(drop) != len(want) {
		t.Fatalf("drop=%v want %v", drop, want)
	}
	for i := range want {
		if drop[i] != want[i] {
			t.Fatalf("drop=%v want %v", drop, want)
		}
	}
}

func TestEVMSnapshotsToPruneNeverDropsWithinWindow(t *testing.T) {
	if d := evmSnapshotsToPrune([]int64{5, 6, 7}, 7); len(d) != 0 {
		t.Fatalf("young chain must keep everything: %v", d)
	}
}

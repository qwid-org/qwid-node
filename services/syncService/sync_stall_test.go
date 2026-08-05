package syncServices

import (
	"testing"
	"time"

	"github.com/wonabru/qwid-node/common"
)

// resetProgress puts the stall tracker back to its zero value and restores the
// node height afterwards, so these tests do not leak state into each other.
func resetProgress(t *testing.T) {
	t.Helper()
	savedHeight := common.GetHeight()
	savedSyncing := common.IsSyncing.Load()
	savedProgress := progress
	t.Cleanup(func() {
		common.SetHeight(savedHeight)
		common.IsSyncing.Store(savedSyncing)
		progress = savedProgress
	})
	progress = syncProgress{height: -1}
}

// TestStallWatchdogIgnoresAdvancingHeight: a sync that is importing blocks must
// never be rewound, however long it runs.
func TestStallWatchdogIgnoresAdvancingHeight(t *testing.T) {
	resetProgress(t)
	common.IsSyncing.Store(true)

	now := time.Now()
	for i := int64(0); i < 10; i++ {
		common.SetHeight(500 + i)
		now = now.Add(2 * SyncStallTimeout)
		checkSyncStall(now)
		if got := common.GetHeight(); got != 500+i {
			t.Fatalf("height changed to %d while sync was progressing", got)
		}
	}
}

// TestStallWatchdogIgnoresSyncedNode: standing still while caught up is the
// normal state of a healthy node, not a stall.
func TestStallWatchdogIgnoresSyncedNode(t *testing.T) {
	resetProgress(t)
	common.IsSyncing.Store(false)
	common.SetHeight(500)

	now := time.Now()
	checkSyncStall(now)
	checkSyncStall(now.Add(10 * SyncStallTimeout))

	if got := common.GetHeight(); got != 500 {
		t.Fatalf("height changed to %d on a node that is not syncing", got)
	}
}

// TestStallWatchdogWaitsForTimeout: a short pause in progress is not a stall.
func TestStallWatchdogWaitsForTimeout(t *testing.T) {
	resetProgress(t)
	common.IsSyncing.Store(true)
	common.SetHeight(500)

	now := time.Now()
	checkSyncStall(now)
	checkSyncStall(now.Add(SyncStallTimeout - time.Second))

	if got := common.GetHeight(); got != 500 {
		t.Fatalf("height changed to %d before the stall timeout elapsed", got)
	}
}

// TestStallWatchdogArmsClockOnFirstCall makes sure the tracker starts counting
// from the first observation rather than from the zero time, which would make
// every fresh node look stalled immediately.
func TestStallWatchdogArmsClockOnFirstCall(t *testing.T) {
	resetProgress(t)
	common.IsSyncing.Store(true)
	common.SetHeight(500)

	now := time.Now()
	checkSyncStall(now)

	if progress.height != 500 {
		t.Fatalf("tracked height = %d, want 500", progress.height)
	}
	if progress.since != now {
		t.Fatalf("clock not armed on first observation: %v", progress.since)
	}
}

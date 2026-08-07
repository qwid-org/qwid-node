package account

import (
	"github.com/wonabru/qwid-node/common"
	"github.com/wonabru/qwid-node/database"
	"github.com/wonabru/qwid-node/logger"
)

// Snapshot-height metadata.
//
// Accounts and staking snapshots used to exist at EVERY height, so the highest
// stored height could be found with a contiguity-assuming binary search
// (LastContiguousHeight). Since snapshots are written once per sync batch,
// heights have gaps and that search stops at the first gap - a node restarted
// after a clean shutdown would then load a snapshot far below its chain tip
// and run with stale balances. The authoritative answer is kept in a meta key
// instead, written after every successful snapshot store and lowered by the
// rewind when it removes snapshots. Databases from before this change have no
// meta key; the contiguity search is still correct for them (their snapshots
// ARE contiguous) and the first new store writes the meta key.
//
// The meta key is prefix+"LAST" (6 bytes) - snapshot keys are prefix+height
// (10+ bytes), so the keyspaces cannot collide.

func storedHeightMetaKey(prefix [2]byte) []byte {
	return append(prefix[:], []byte("LAST")...)
}

// lastStoredHeightMeta returns the recorded highest stored snapshot height for
// prefix, or ok=false when the database predates the meta key.
func lastStoredHeightMeta(prefix [2]byte) (int64, bool) {
	b, err := database.MainDB.Get(storedHeightMetaKey(prefix))
	if err != nil || len(b) != 8 {
		return -1, false
	}
	return common.GetInt64FromByte(b), true
}

func setLastStoredHeightMeta(prefix [2]byte, height int64) {
	if err := database.MainDB.Put(storedHeightMetaKey(prefix), common.GetByteInt64(height)); err != nil {
		logger.GetLogger().Println("cannot store snapshot height meta:", err)
	}
}

// raiseLastStoredHeightMeta records height as the highest stored snapshot
// height if it exceeds the current record. Called after a successful snapshot
// store; the store-then-meta order means a crash in between leaves the meta a
// batch low, which only makes the next lookup start slightly deeper - never at
// a height without a snapshot.
func raiseLastStoredHeightMeta(prefix [2]byte, height int64) {
	if cur, ok := lastStoredHeightMeta(prefix); ok && cur >= height {
		return
	}
	setLastStoredHeightMeta(prefix, height)
}

// SetLastStoredSnapshotHeights lowers the recorded snapshot heights to height.
// The rewind calls this after removing every snapshot above its target, so the
// meta never points into the removed range.
func SetLastStoredSnapshotHeights(height int64) {
	setLastStoredHeightMeta(common.AccountsDBPrefix, height)
	setLastStoredHeightMeta(common.StakingAccountsDBPrefix, height)
}

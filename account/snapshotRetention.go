package account

import (
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/database"
	"github.com/qwid-org/qwid-node/logger"
)

// Snapshot retention.
//
// StoreAccounts/StoreStakingAccounts write one full copy of the state under
// prefix+height, and on the live path that happens every block. Nothing ever
// removed an old copy, so database size was state-size x block-count with no
// upper bound — a node running since early August held 1.2 TB where a freshly
// synced one held 4 GB. (Most of that particular 1.2 TB is worse still: before
// f0c233c the account state carried each account's full transaction history, so
// snapshot size itself grew with the chain and the total was quadratic.)
//
// The policy keeps:
//
//   - every snapshot within SnapshotRetentionBlocks of the tip, which is what
//     ordinary rewinds and restarts use;
//   - every SnapshotCheckpointInterval-th height below that, so a deep rewind
//     still has somewhere to land;
//   - genesis, always — it is the only height a node can rebuild everything
//     from.
//
// Nothing at or above the tip is touched. Removing snapshots above the tip is
// the rewind's job (ResetAccountsAndBlocksSync), and the two must not be
// confused: this runs while the chain is moving forward.

// snapshotsToPrune returns the subset of heights that retention allows to be
// deleted, given the current chain tip. Pure, so the policy can be reasoned
// about without a database.
func snapshotsToPrune(heights []int64, tip int64) []int64 {
	drop := make([]int64, 0, len(heights))
	windowFloor := tip - common.SnapshotRetentionBlocks
	for _, h := range heights {
		switch {
		case h <= 0: // genesis
			continue
		case h >= windowFloor: // dense recent window (and anything above the tip)
			continue
		case h%common.SnapshotCheckpointInterval == 0: // checkpoint
			continue
		}
		drop = append(drop, h)
	}
	return drop
}

// storedSnapshotHeights lists every height that has a snapshot under prefix.
// Keys are prefix+height(8 bytes); the meta key prefix+"LAST" is 6 bytes and is
// skipped by the length check.
func storedSnapshotHeights(prefix [2]byte) ([]int64, error) {
	keys, err := database.MainDB.LoadAllKeys(prefix[:])
	if err != nil {
		return nil, err
	}
	heights := make([]int64, 0, len(keys))
	for _, k := range keys {
		if len(k) != len(prefix)+8 {
			continue
		}
		heights = append(heights, common.GetInt64FromByte(k[len(prefix):]))
	}
	return heights, nil
}

// ClosestStoredSnapshotHeight returns the highest height at or below the given
// one that still has a snapshot under prefix, or -1 when there is none.
//
// Reads used to demand an exact height, which was fine only because a snapshot
// existed at every block. Once old ones are pruned that assumption breaks, so
// every caller that needs "the state as of around here" has to ask for the
// nearest one at or below and then use the height it actually got.
func ClosestStoredSnapshotHeight(prefix [2]byte, height int64) (int64, error) {
	heights, err := storedSnapshotHeights(prefix)
	if err != nil {
		return -1, err
	}
	best := int64(-1)
	for _, h := range heights {
		if h <= height && h > best {
			best = h
		}
	}
	return best, nil
}

// pruneSnapshots deletes the snapshots under prefix that retention allows to go,
// returning how many were removed.
func pruneSnapshots(prefix [2]byte, tip int64) (int, error) {
	heights, err := storedSnapshotHeights(prefix)
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, h := range snapshotsToPrune(heights, tip) {
		key := append(prefix[:], common.GetByteInt64(h)...)
		if err := database.MainDB.Delete(key); err != nil {
			return removed, err
		}
		removed++
	}
	return removed, nil
}

// PruneStateSnapshots applies retention to the account, staking and DEX
// keyspaces. Errors are logged rather than returned: failing to reclaim disk
// space must never stop a node from following the chain.
func PruneStateSnapshots(tip int64) {
	for _, p := range []struct {
		name   string
		prefix [2]byte
	}{
		{"accounts", common.AccountsDBPrefix},
		{"staking", common.StakingAccountsDBPrefix},
		{"dex", common.DexAccountsDBPrefix},
	} {
		removed, err := pruneSnapshots(p.prefix, tip)
		if err != nil {
			logger.GetLogger().Println("snapshot pruning failed for", p.name, ":", err)
			continue
		}
		if removed > 0 {
			logger.GetLogger().Printf("pruned %d %s snapshots below height %d",
				removed, p.name, tip-common.SnapshotRetentionBlocks)
		}
	}
}

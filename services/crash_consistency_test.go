package services

// Crash consistency (AUDIT_PLAN_2026-09-25 Phase 2, S9-03). A live block apply
// persists the state in SEPARATE writes: StoreBlock, then StoreAccounts,
// CommitEVMStateIfChanged, StoreStakingAccounts, StoreDexAccounts, and LAST
// the state commit marker (blocks.StoreStateCommit). A crash between these
// writes leaves the block and some snapshots in the DB but not the marker.
//
// This used to be a probe proving the gap: startup checked only the accounts
// and staking snapshots plus the supply invariant, so a height missing its DEX
// snapshot was accepted and the node resumed with stale pool reserves. Startup
// now requires the commit marker and a state (accounts, staking, DEX, EVM)
// that hashes to it, so such a height is rejected and the node rewinds to the
// last committed one.

import (
	"testing"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/database"
	"github.com/qwid-org/qwid-node/logger"
	"github.com/stretchr/testify/require"
)

// TestStartupConsistencyRejectsCrashBeforeDexSnapshot simulates a crash after
// StoreStakingAccounts but before StoreDexAccounts at the tip: the block and
// the accounts/staking snapshots of height 10 are stored, its DEX snapshot and
// commit marker are not. Startup must reject height 10 and accept height 9,
// the last height whose writes all landed.
func TestStartupConsistencyRejectsCrashBeforeDexSnapshot(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	withTempDB(t)

	// Heights 0..9 fully committed; height 10 written without its marker.
	storeLinkedChain(t, 10, func(h int64) bool { return h < 10 })
	dexAt10 := append(common.DexAccountsDBPrefix[:], common.GetByteInt64(10)...)
	require.NoError(t, database.MainDB.Delete(dexAt10))

	require.Error(t, checkBlockConsistency(10),
		"a height whose DEX snapshot and commit marker never landed must not be accepted")
	require.NoError(t, checkBlockConsistency(9),
		"the last fully committed height must remain a valid tip")
}

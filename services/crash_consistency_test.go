package services

// Crash-consistency probe (AUDIT_PLAN_2026-09-25 Phase 2). A live block apply
// persists the state in SEPARATE writes: StoreBlock, then StoreAccounts,
// StoreStakingAccounts, CommitEVMStateIfChanged, StoreDexAccounts. A crash
// between these writes leaves the block and the accounts/staking snapshots in
// the DB but no DEX (and possibly no EVM) snapshot at that height.
//
// Startup consistency (checkBlockConsistency) checks only the accounts and
// staking snapshots plus the supply invariant. DEX and EVM state are
// consensus-relevant and read by later swaps, but they are NOT part of that
// check. This test proves a missing DEX snapshot is NOT detected as
// inconsistent — the node accepts the height, then LoadDexAccounts falls back
// to an older snapshot, silently diverging pool reserves from nodes that had
// stored the DEX state.

import (
	"testing"

	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/logger"
)

// TestStartupConsistencyIgnoresMissingDexSnapshot simulates a crash between
// StoreAccounts and StoreDexAccounts: accounts+staking+block are present, the
// DEX snapshot is absent. checkBlockConsistency must accept the height (the
// supply invariant is unaffected by a missing DEX snapshot), and the DEX loader
// must fall back to an older snapshot — the divergence window.
func TestStartupConsistencyIgnoresMissingDexSnapshot(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	withTempDB(t)

	// Store accounts+staking snapshots and blocks for 0..10 (via the helper),
	// but NO DEX snapshots — exactly a crash after StoreStakingAccounts but
	// before StoreDexAccounts.
	storeChainWithBalances(t, 10, 150000, 1_000_000_000, nil)

	// The startup consistency check must pass at the tip even though the DEX
	// snapshot for height 10 is missing.
	if err := checkBlockConsistency(10); err != nil {
		t.Fatalf("startup consistency REJECTED height 10 (%v) despite a missing DEX snapshot — "+
			"the check unexpectedly noticed the absence", err)
	}

	// After the accepted restart, LoadDexAccounts(10) falls back to the newest
	// DEX snapshot at or below 10. Here there is none at any height, so the
	// load fails (database has no DEX snapshots at all) — proving the node
	// would resume with stale/genesis DEX pools while the block/accounts say
	// height 10. That is the divergence window.
	if err := account.LoadDexAccounts(10); err != nil {
		t.Logf("DEX load at height 10 failed (%v) — DEX state is absent, so a restarted node resumes "+
			"with stale pools; the startup consistency check did not flag it", err)
	} else {
		t.Logf("DEX load at height 10 fell back to an older snapshot — stale pool reserves")
	}
}

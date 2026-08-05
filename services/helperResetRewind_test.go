package services

import (
	"path/filepath"
	"testing"

	"github.com/wonabru/qwid-node/account"
	"github.com/wonabru/qwid-node/blocks"
	"github.com/wonabru/qwid-node/common"
	"github.com/wonabru/qwid-node/database"
	"github.com/wonabru/qwid-node/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// withTempDB points database.MainDB at a throwaway RocksDB instance so the test
// never touches the operator's real blockchain database.
func withTempDB(t *testing.T) {
	t.Helper()
	db := &database.BlockchainDB{}
	pdb, err := db.InitPermanent(filepath.Join(t.TempDir(), "blockchain"))
	require.NoError(t, err)

	saved := database.MainDB
	database.MainDB = pdb
	t.Cleanup(func() {
		pdb.Close()
		database.MainDB = saved
	})
}

// storeSnapshotsUpTo writes accounts and staking snapshots for heights 0..height.
func storeSnapshotsUpTo(t *testing.T, height int64) {
	t.Helper()
	account.Accounts = account.AccountsType{AllAccounts: map[[common.AddressLength]byte]account.Account{}}
	for i := 0; i < 256; i++ {
		account.StakingAccounts[i] = account.StakingAccountsType{
			AllStakingAccounts: map[[common.AddressLength]byte]account.StakingAccount{},
		}
	}
	for h := int64(0); h <= height; h++ {
		require.NoError(t, account.StoreAccounts(h))
		require.NoError(t, account.StoreStakingAccounts(h))
	}
}

func TestRestorableHeight(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	withTempDB(t)
	storeSnapshotsUpTo(t, 10)

	assert.Equal(t, int64(10), restorableHeight(10), "exact height with snapshots")
	assert.Equal(t, int64(10), restorableHeight(15), "walks down to the deepest stored snapshot")
	assert.Equal(t, int64(3), restorableHeight(3), "height below the tip is returned as-is")
}

func TestRestorableHeightWithoutSnapshots(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	withTempDB(t)

	assert.Equal(t, int64(-1), restorableHeight(5), "no snapshots at all is reported as unrestorable")
}

// TestResetRewindsHeightWhenSnapshotMissing is the regression test for the silent
// no-op rewind: ResetAccountsAndBlocksSync used to return without touching
// common.GetHeight() whenever the requested height had no accounts snapshot, so
// the next sync batch rediscovered the same fork forever.
func TestResetRewindsHeightWhenSnapshotMissing(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	withTempDB(t)
	blocks.InitStateDB()
	storeSnapshotsUpTo(t, 10)

	savedHeight := common.GetHeight()
	defer common.SetHeight(savedHeight)

	common.SetHeight(42)
	ResetAccountsAndBlocksSync(20) // no snapshot at 20, deepest stored is 10

	assert.Equal(t, int64(10), common.GetHeight(),
		"rewind must land on the deepest restorable height, not leave the height untouched")
}

func TestResetRewindsToRequestedHeight(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	withTempDB(t)
	blocks.InitStateDB()
	storeSnapshotsUpTo(t, 10)

	savedHeight := common.GetHeight()
	defer common.SetHeight(savedHeight)

	common.SetHeight(10)
	ResetAccountsAndBlocksSync(4)

	assert.Equal(t, int64(4), common.GetHeight())
}

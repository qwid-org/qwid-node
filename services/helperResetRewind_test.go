package services

import (
	"path/filepath"
	"testing"

	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/blocks"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/database"
	"github.com/qwid-org/qwid-node/logger"
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

// storeChainWithBalances writes, for every height 0..top, a block declaring a
// constant total supply plus the fees collected so far, and an accounts snapshot
// holding the remainder. That is exactly the invariant a healthy node keeps:
//
//	accounts + staked + rewarded + BlockFee == Supply
//
// Heights listed in broken get a snapshot that is two blocks' worth of fees too
// rich, reproducing what a rewind concurrent with a block application leaves
// behind.
func storeChainWithBalances(t *testing.T, top int64, feePerBlock int64, supply int64, broken map[int64]bool) {
	t.Helper()
	for i := 0; i < 256; i++ {
		account.StakingAccounts[i] = account.StakingAccountsType{
			AllStakingAccounts: map[[common.AddressLength]byte]account.StakingAccount{},
		}
	}
	addr := [common.AddressLength]byte{1, 2, 3}
	for h := int64(0); h <= top; h++ {
		fees := h * feePerBlock
		balance := supply - fees
		if broken[h] {
			balance += 2 * feePerBlock
		}
		account.Accounts = account.AccountsType{AllAccounts: map[[common.AddressLength]byte]account.Account{
			addr: {Address: addr, Balance: balance},
		}}
		require.NoError(t, account.StoreAccounts(h))
		require.NoError(t, account.StoreStakingAccounts(h))

		sig, err := common.GetSignatureFromBytes(make([]byte, common.SignatureLength(false)), common.EmptyAddress())
		require.NoError(t, err)
		bl := blocks.Block{
			BaseBlock: blocks.BaseBlock{
				BaseHeader: blocks.BaseHeader{
					DelegatedAccount: common.EmptyAddress(),
					OperatorAccount:  common.EmptyAddress(),
					Height:           h,
					Encryption1:      []byte{},
					Encryption2:      []byte{},
					SignatureMessage: []byte{1, 2, 3},
					Signature:        sig,
				},
				Supply:          supply,
				PriceOracleData: []byte{},
				RandOracleData:  []byte{},
			},
			TransactionsHashes: []common.Hash{},
			BlockFee:           fees,
		}
		bl.BlockHash = common.GetHashFromBytes([]byte{byte(h), byte(h >> 8), 0xbe, 0xef})
		require.NoError(t, bl.StoreBlock())
	}
}

// TestResetSkipsStateBreakingSupplyInvariant is the regression test for a node
// that could never sync again: a snapshot written while the state had been
// rewound under an in-flight block application makes every following block fail
// the supply check, and resetting to that same height replays the failure
// forever. The rewind must walk past such a height.
func TestResetSkipsStateBreakingSupplyInvariant(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	withTempDB(t)
	blocks.InitStateDB()
	storeChainWithBalances(t, 10, 150000, 1_000_000_000, map[int64]bool{9: true, 10: true})

	savedHeight := common.GetHeight()
	defer common.SetHeight(savedHeight)

	common.SetHeight(10)
	ResetAccountsAndBlocksSync(10)

	assert.Equal(t, int64(8), common.GetHeight(),
		"rewind must skip heights whose stored state cannot satisfy the supply invariant")

	delta, err := SupplyInvariantDelta(common.GetHeight())
	require.NoError(t, err)
	assert.Equal(t, int64(0), delta, "the height rewound to must be self-consistent")
}

// TestResetKeepsConsistentHeight guards the other direction: a healthy snapshot
// must not be rewound past just because the invariant is now checked.
func TestResetKeepsConsistentHeight(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	withTempDB(t)
	blocks.InitStateDB()
	storeChainWithBalances(t, 10, 150000, 1_000_000_000, nil)

	savedHeight := common.GetHeight()
	defer common.SetHeight(savedHeight)

	common.SetHeight(10)
	ResetAccountsAndBlocksSync(10)

	assert.Equal(t, int64(10), common.GetHeight())
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

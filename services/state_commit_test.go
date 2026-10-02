package services

import (
	"testing"

	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/blocks"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
	"github.com/stretchr/testify/require"
)

// storeLinkedChain stores blocks 0..top that link to each other, with every
// state snapshot at every height; commit says at which heights the state
// commit marker is written.
func storeLinkedChain(t *testing.T, top int64, commit func(h int64) bool) {
	t.Helper()
	blocks.InitStateDB()
	for i := 0; i < 256; i++ {
		account.StakingAccounts[i] = account.StakingAccountsType{AllStakingAccounts: map[[common.AddressLength]byte]account.StakingAccount{}}
	}
	account.DexAccounts = account.DexAccountsType{AllDexAccounts: map[[common.AddressLength]byte]account.DexAccount{}}
	addr := [common.AddressLength]byte{9, 9, 9}
	const supply = 1_000_000_000
	prev := common.Hash{}
	for h := int64(0); h <= top; h++ {
		account.Accounts = account.AccountsType{AllAccounts: map[[common.AddressLength]byte]account.Account{
			addr: {Address: addr, Balance: supply},
		}}
		require.NoError(t, account.StoreAccounts(h))
		require.NoError(t, account.StoreStakingAccounts(h))
		require.NoError(t, account.StoreDexAccounts(h))
		require.NoError(t, blocks.CommitEVMState(h))
		sig, err := common.GetSignatureFromBytes(make([]byte, common.SignatureLength(false)), common.EmptyAddress())
		require.NoError(t, err)
		bl := blocks.Block{
			BaseBlock: blocks.BaseBlock{
				BaseHeader: blocks.BaseHeader{PreviousHash: prev, Height: h, Encryption1: []byte{}, Encryption2: []byte{},
					SignatureMessage: []byte{1}, Signature: sig},
				Supply: supply, PriceOracleData: []byte{}, RandOracleData: []byte{},
			},
			TransactionsHashes: []common.Hash{},
		}
		bl.BlockHash, err = bl.CalcBlockHash()
		require.NoError(t, err)
		require.NoError(t, bl.StoreBlock())
		prev = bl.BlockHash
		if commit(h) {
			require.NoError(t, blocks.StoreStateCommit(h))
		}
	}
}

// S9-03: applying a block is several separate writes. The state commit
// marker is written last; a height without it - a crash between the writes -
// or whose stored state does not hash to it is not a consistent tip.
func TestStartupConsistencyRequiresStateCommit(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	withTempDB(t)
	storeLinkedChain(t, 5, func(int64) bool { return true })
	require.NoError(t, checkBlockConsistency(5), "a fully committed height")

	withTempDB(t)
	storeLinkedChain(t, 5, func(h int64) bool { return h < 5 })
	require.Error(t, checkBlockConsistency(5), "crash before the commit marker")
	require.NoError(t, checkBlockConsistency(4))

	withTempDB(t)
	storeLinkedChain(t, 5, func(int64) bool { return true })
	// A DEX snapshot that is not the state the height committed to (e.g. a
	// write torn by a crash, then an older marker) is caught by the root.
	pool := [common.AddressLength]byte{0xD, 0xE, 0x7}
	account.DexAccounts = account.DexAccountsType{AllDexAccounts: map[[common.AddressLength]byte]account.DexAccount{
		pool: {CoinPool: 5, TokenPool: 7},
	}}
	require.NoError(t, account.StoreDexAccounts(5))
	require.Error(t, checkBlockConsistency(5), "DEX snapshot differs from the committed state")
}

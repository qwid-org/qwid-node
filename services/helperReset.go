package services

import (
	"github.com/wonabru/qwid-node/account"
	"github.com/wonabru/qwid-node/blocks"
	"github.com/wonabru/qwid-node/common"
	"github.com/wonabru/qwid-node/logger"
	"github.com/wonabru/qwid-node/transactionsPool"
	"sync/atomic"
)

var QUIT = atomic.Bool{}

func init() {
	QUIT.Store(false)
}

func AdjustShiftInPastInReset(height int64) {
	common.ShiftToPastMutex.Lock()
	defer common.ShiftToPastMutex.Unlock()
	h := common.GetHeight()
	if height-h <= 0 {
		common.ShiftToPastInReset = 1
		return
	}
	common.ShiftToPastInReset += 2
	if common.ShiftToPastInReset > height {
		common.ShiftToPastInReset = height
	}
	if common.ShiftToPastInReset < 1 {
		common.ShiftToPastInReset = 1
	}
}

func RevertVMToBlockHeight(height int64) bool {
	blocks.StateMutex.Lock()
	defer blocks.StateMutex.Unlock()
	lastNum := 0
	for h, n := range blocks.State.HeightToSnapShotNum {
		if h > height {
			continue
		}
		if n > lastNum {
			lastNum = n
		}
	}

	blocks.State.RevertToSnapshot(lastNum)
	blocks.State.CleanupContractsAfterHeight(height)
	if err := blocks.State.Load(height); err != nil {
		logger.GetLogger().Println("could not reload EVM state on reset:", err)
	}
	return true
}

// restorableHeight walks down from height to the closest height whose accounts
// and staking snapshots are both present, so a rewind lands on a height whose
// state can actually be restored. Returns -1 when nothing is restorable.
func restorableHeight(height int64) int64 {
	for h := height; h >= 0; h-- {
		if account.AccountsStoredAtHeight(h) && account.StakingAccountsStoredAtHeight(h) {
			return h
		}
	}
	return -1
}

// SupplyInvariantDelta reports how far the stored state at `height` deviates
// from the supply the block at that height declares:
//
//	accounts + staked + rewarded + block.BlockFee - block.Supply
//
// This is the same invariant CheckBlockAndTransferFunds enforces before applying
// the next block, so a non-zero result means the snapshot is unusable as a base:
// every following block will be rejected with "block supply checking fails vs
// account balances" and the node can never move on.
//
// It LOADS the stored snapshots into the live in-memory state, so call it only
// from a path that is about to (re)load state anyway.
func SupplyInvariantDelta(height int64) (int64, error) {
	bl, err := blocks.LoadBlock(height)
	if err != nil {
		return 0, err
	}
	if err := account.LoadAccounts(height); err != nil {
		return 0, err
	}
	if err := account.LoadStakingAccounts(height); err != nil {
		return 0, err
	}
	staked, rewarded := blocks.GetSupplyInStakedAccounts()
	return blocks.GetSupplyInAccounts() + staked + rewarded + bl.BlockFee - bl.GetBlockSupply(), nil
}

// consistentRewindTarget walks down from height to the closest height that is
// both restorable and internally consistent, so a rewind cannot land on a
// snapshot that is guaranteed to reject every following block. Heights whose
// block is missing are accepted as-is: an unauditable height must not make the
// rewind impossible. The audit stops common.MaxStartupRewind blocks below the
// requested height, so a corruption older than that degrades to the previous
// behaviour instead of rewinding the node back towards genesis.
func consistentRewindTarget(height int64) int64 {
	floor := height - common.MaxStartupRewind
	for h := height; h >= 0; h-- {
		if !account.AccountsStoredAtHeight(h) || !account.StakingAccountsStoredAtHeight(h) {
			continue
		}
		if h < floor {
			logger.GetLogger().Println("no self-consistent state within", common.MaxStartupRewind,
				"blocks below", height, "- rewinding to", h, "without the supply check")
			return h
		}
		delta, err := SupplyInvariantDelta(h)
		if err != nil {
			// Cannot audit (no block stored at that height) - accept it.
			return h
		}
		if delta == 0 {
			return h
		}
		logger.GetLogger().Println("stored state at height", h, "breaks the block-supply invariant by",
			delta, "- rewinding further back")
	}
	return -1
}

// ResetAccountsAndBlocksSync rewinds the node to `height`, taking the block lock
// so no block application can be running concurrently. A rewind replaces the
// global account state: doing that under a block that is mid-apply makes that
// block persist the rewound state under its own height, which desynchronises
// balances from the fee ledger permanently. Callers that already hold
// common.BlockMutex must use ResetAccountsAndBlocksSyncLocked instead.
func ResetAccountsAndBlocksSync(height int64) {
	common.BlockMutex.Lock()
	defer common.BlockMutex.Unlock()
	ResetAccountsAndBlocksSyncLocked(height)
}

// ResetAccountsAndBlocksSyncLocked is ResetAccountsAndBlocksSync for callers that
// already hold common.BlockMutex.
func ResetAccountsAndBlocksSyncLocked(height int64) {
	logger.GetLogger().Println("reset to ", height)
	if height < 0 {
		logger.GetLogger().Println("try to reset from negative height")
		height = 0
	}

	// Land on a height whose state we can restore. Aborting here instead would
	// leave common.GetHeight() untouched, so the very next sync batch would
	// rediscover the same fork and the node would never make progress.
	target := consistentRewindTarget(height)
	if target < 0 {
		logger.GetLogger().Println("no restorable accounts snapshot at or below height", height,
			"- cannot rewind, staying in sync mode")
		common.IsSyncing.Store(true)
		return
	}
	if target != height {
		logger.GetLogger().Println("no state snapshot at height", height, "- rewinding to", target, "instead")
		height = target
	}

	if err := account.LoadAccounts(height); err != nil {
		logger.GetLogger().Println("cannot load accounts at height", height, ":", err,
			"- cannot rewind, staying in sync mode")
		common.IsSyncing.Store(true)
		return
	}
	if err := account.LoadStakingAccounts(height); err != nil {
		logger.GetLogger().Println("cannot load staking accounts at height", height, ":", err,
			"- cannot rewind, staying in sync mode")
		common.IsSyncing.Store(true)
		return
	}

	ha, err := account.LastHeightStoredInAccounts()
	if err != nil {
		logger.GetLogger().Println(err)
	}
	hsa, err := account.LastHeightStoredInStakingAccounts()
	if err != nil {
		logger.GetLogger().Println(err)
	}
	hb, err := blocks.LastHeightStoredInBlocks()
	if err != nil {
		logger.GetLogger().Println(err)
	}
	// A failure here leaves the encryption config as-is; that is recoverable and
	// must not abort the rewind, otherwise the height stays on the forked chain.
	if err := blocks.SetEncryptionFromBlock(height); err != nil {
		logger.GetLogger().Println("cannot set encryption from block", height, ":", err, "- continuing rewind")
	}
	hd, err := account.LastHeightStoredInDexAccounts()
	if err != nil {
		logger.GetLogger().Println(err)
	}

	if RevertVMToBlockHeight(height) == false {
		logger.GetLogger().Println("reverting VM to height ", height, " fails.")
	}

	for i := hb; i > height; i-- {
		err := blocks.RemoveBlockFromDB(i)
		if err != nil {
			logger.GetLogger().Println(err)
		}
	}
	for i := ha; i > height; i-- {
		err := account.RemoveAccountsFromDB(i)
		if err != nil {
			logger.GetLogger().Println(err)
		}
	}
	for i := hsa; i > height; i-- {
		err := account.RemoveStakingAccountsFromDB(i)
		if err != nil {
			logger.GetLogger().Println(err)
		}
	}
	for i := hd; i > height; i-- {
		err := account.RemoveDexAccountsFromDB(i)
		if err != nil {
			logger.GetLogger().Println(err)
		}
	}

	hm, err := transactionsPool.LastHeightStoredInMerleTrie()
	if err != nil {
		logger.GetLogger().Println(err)
	}
	for i := hm; i > height; i-- {
		err := transactionsPool.RemoveMerkleTrieFromDB(i)
		if err != nil {
			logger.GetLogger().Println(err)
		}
	}

	common.SetHeight(height)
	logger.GetLogger().Println("reset to ", height, " is successful")
}

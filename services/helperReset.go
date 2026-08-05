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

func ResetAccountsAndBlocksSync(height int64) {
	logger.GetLogger().Println("reset to ", height)
	if height < 0 {
		logger.GetLogger().Println("try to reset from negative height")
		height = 0
	}

	// Land on a height whose state we can restore. Aborting here instead would
	// leave common.GetHeight() untouched, so the very next sync batch would
	// rediscover the same fork and the node would never make progress.
	target := restorableHeight(height)
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

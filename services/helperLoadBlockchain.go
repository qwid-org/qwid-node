package services

import (
	"bufio"
	"bytes"
	"fmt"
	"os"

	"github.com/wonabru/qwid-node/account"
	"github.com/wonabru/qwid-node/blocks"
	"github.com/wonabru/qwid-node/common"
	"github.com/wonabru/qwid-node/logger"
	"github.com/wonabru/qwid-node/wallet"
)

// checkBlockConsistency validates block `height` against what is on disk without
// replaying it. A full re-verification is impossible here: CheckBlockAndTransactions
// requires the in-memory account state of the parent (height-1), which at startup
// is loaded at the tip, and it also removes the block's transactions from the pool
// (see the RemoveAllTransactionsRelatedToBlock defer in blocks/processBlock.go).
// Divergence from the network is not something a node can detect on its own
// anyway - the sync service resolves that against live peers.
func checkBlockConsistency(height int64) error {
	if height <= 0 {
		return nil
	}
	bl, err := blocks.LoadBlock(height)
	if err != nil {
		return fmt.Errorf("cannot load block %d: %w", height, err)
	}
	if bl.GetHeader().Height != height {
		return fmt.Errorf("block stored at %d declares height %d", height, bl.GetHeader().Height)
	}
	parent, err := blocks.LoadBlock(height - 1)
	if err != nil {
		return fmt.Errorf("cannot load parent block %d: %w", height-1, err)
	}
	if !bytes.Equal(bl.GetHeader().PreviousHash.GetBytes(), parent.BlockHash.GetBytes()) {
		return fmt.Errorf("block %d does not link to block %d", height, height-1)
	}
	hash, err := bl.CalcBlockHash()
	if err != nil {
		return fmt.Errorf("cannot compute hash of block %d: %w", height, err)
	}
	if !bytes.Equal(hash.GetBytes(), bl.BlockHash.GetBytes()) {
		return fmt.Errorf("stored hash of block %d does not match its content", height)
	}
	if !account.AccountsStoredAtHeight(height) {
		return fmt.Errorf("no accounts snapshot for height %d", height)
	}
	if !account.StakingAccountsStoredAtHeight(height) {
		return fmt.Errorf("no staking snapshot for height %d", height)
	}
	// The snapshot can exist and still be unusable: if it was written while the
	// state had been rewound under an in-flight block application, balances no
	// longer add up to the supply the block declares, and every following block
	// is rejected on that invariant with no way out. Detect it here so startup
	// rewinds to the last height that does add up. Loading the snapshots is a
	// side effect the caller relies on - see checkMainChain.
	delta, err := SupplyInvariantDelta(height)
	if err != nil {
		return fmt.Errorf("cannot check supply invariant at height %d: %w", height, err)
	}
	if delta != 0 {
		return fmt.Errorf("stored state at height %d breaks the block-supply invariant by %d", height, delta)
	}
	return nil
}

// activateWalletFromBlock selects the wallet matching the signature schemes the
// chain is using at `height`.
func activateWalletFromBlock(height int64) {
	bl, err := blocks.LoadBlock(height)
	if err != nil {
		logger.GetLogger().Println("cannot load block", height, "to select wallet:", err)
		return
	}
	sn1, sn2, _, _, err := bl.GetSigNames()
	if err != nil {
		logger.GetLogger().Println("cannot read signature schemes from block", height, ":", err)
		return
	}
	cw, err := wallet.GetCurrentWallet(sn1, sn2)
	if err != nil {
		logger.GetLogger().Println("cannot load wallet for signature schemes of block", height, ":", err)
		return
	}
	wallet.SetActiveWallet(cw)
}

// checkMainChain returns the height the node should start from. When the local
// tip is inconsistent it rewinds up to common.MaxStartupRewind blocks to the
// deepest consistent height; anything beyond that is left to the sync service.
// An error is returned only for genuinely unusable storage (no genesis block),
// which is the single case that still warrants wiping the database. It is paired
// with height -1 so a brand-new database falls through to genesis initialisation
// in cmd/mining rather than prompting the operator.
func checkMainChain() (int64, error) {
	if _, err := blocks.LoadBlock(0); err != nil {
		return -1, fmt.Errorf("cannot load genesis block: %w", err)
	}

	height, err := blocks.LastHeightStoredInBlocks()
	if err != nil {
		logger.GetLogger().Println(err)
	}
	logger.GetLogger().Println("blocks.LastHeightStoredInBlocks() height: ", height)
	if height <= 0 {
		// Only the genesis block is stored - a fresh node. Nothing to check.
		return height, nil
	}

	lowest := height - common.MaxStartupRewind
	if lowest < 1 {
		lowest = 1
	}
	for h := height; h >= lowest; h-- {
		if err := checkBlockConsistency(h); err != nil {
			logger.GetLogger().Println("startup consistency check failed:", err)
			continue
		}
		good := h
		if good != height {
			logger.GetLogger().Println("local chain tip inconsistent - rewinding from", height, "to", good)
			ResetAccountsAndBlocksSync(good)
			good = common.GetHeight()
		}
		if err := blocks.SetEncryptionFromBlock(good); err != nil {
			logger.GetLogger().Println("cannot set encryption from block", good, ":", err)
		}
		activateWalletFromBlock(good)
		return good, nil
	}

	target := lowest - 1
	if target < 0 {
		target = 0
	}
	logger.GetLogger().Println("no consistent chain tip within", common.MaxStartupRewind,
		"blocks below", height, "- rewinding to", target, "and leaving the rest to sync")
	ResetAccountsAndBlocksSync(target)
	h := common.GetHeight()
	if err := blocks.SetEncryptionFromBlock(h); err != nil {
		logger.GetLogger().Println("cannot set encryption from block", h, ":", err)
	}
	activateWalletFromBlock(h)
	return h, nil
}

func SetBlockHeightAfterCheck() {
	height, err := checkMainChain()
	// height < 0 means there is no chain in the database at all - a brand-new
	// node, which cmd/mining initialises from genesis. Only a database that has
	// content but cannot be used reaches the destructive prompt below.
	if err != nil && height >= 0 {
		logger.GetLogger().Println(err)
		// Get home directory
		homePath, err := os.UserHomeDir()
		if err != nil {
			logger.GetLogger().Fatal("failed to get home directory:", err)
		}
		fmt.Print("Should db with blockchain state should be removed and sync from beginning? Yes/[No]: ")
		reader := bufio.NewReader(os.Stdin)
		answer, _ := reader.ReadString('\n')
		logger.GetLogger().Println(answer)
		if len(answer) > 0 && (answer[0] == 'Y' || answer[0] == 'y') {
			// remove database related to blockckchain, NOT wallets
			os.RemoveAll(homePath + common.DefaultBlockchainHomePath)
			logger.GetLogger().Fatal("DB files related to chain was removed. run mining once more and sync with other nodes. wrong data stored in db")
		} else {
			logger.GetLogger().Fatal("DB files related to chain was NOT removed. Please run mining once more and sync with other nodes.")
		}
		return
	}
	common.SetHeight(height)
}

package transactionsPool

import (
	"fmt"

	"github.com/wonabru/qwid-node/common"
	"github.com/wonabru/qwid-node/logger"
	"github.com/wonabru/qwid-node/transactionsDefinition"
)

func RemoveBadTransactionByHash(hash []byte, height int64, tree *MerkleTree) error {
	PoolsTx.RemoveTransactionByHash(hash)
	RemoveEscrowTransaction(hash)
	PoolTxMultiSign.RemoveTransactionByHash(hash)

	// Try to load transaction from pool or confirmed DB before removing
	tx, err := transactionsDefinition.LoadFromDBPoolTx(common.TransactionPoolHashesDBPrefix[:], hash)
	if err != nil {
		tx, err = transactionsDefinition.LoadFromDBPoolTx(common.TransactionDBPrefix[:], hash)
	}

	// Store to bad transaction DB so other nodes can still sync it
	if err == nil && len(tx.GetBytes()) > 0 {
		err = tx.StoreToDBPoolTx(common.BadTransactionDBPrefix[:])
		if err != nil {
			logger.GetLogger().Println("failed to store bad transaction:", err)
		}
	}

	err = transactionsDefinition.RemoveTransactionFromDBbyHash(common.TransactionPoolHashesDBPrefix[:], hash)
	if err != nil {
		logger.GetLogger().Println(err)
	}
	// NOTE: Do NOT delete from confirmed DB (TransactionDBPrefix) - other nodes need these
	// transactions for sync. Only remove from pool DB.
	err = CheckTransactionInDBAndInMarkleTrie(hash, tree)
	if err == nil {
		logger.GetLogger().Println("transaction is in trie")
	}
	PoolsTx.BanTransactionByHash(hash)
	PoolTxEscrow.BanTransactionByHash(hash)
	PoolTxMultiSign.BanTransactionByHash(hash)
	return nil
}

// RemoveDuplicateTransactionByHash removes a confirmed transaction from all
// pending pools and bans it so it cannot be re-included in future blocks.
// The confirmed-DB record (TransactionDBPrefix) is preserved for sync.
func RemoveDuplicateTransactionByHash(hash []byte) {
	PoolsTx.RemoveTransactionByHash(hash)
	RemoveEscrowTransaction(hash)
	PoolTxMultiSign.RemoveTransactionByHash(hash)
	if err := transactionsDefinition.RemoveTransactionFromDBbyHash(common.TransactionPoolHashesDBPrefix[:], hash); err != nil {
		logger.GetLogger().Println("RemoveDuplicateTransactionByHash pool DB:", err)
	}
	PoolsTx.BanTransactionByHash(hash)
	PoolTxEscrow.BanTransactionByHash(hash)
	PoolTxMultiSign.BanTransactionByHash(hash)
}

func CheckTransactionInDBAndInMarkleTrie(hash []byte, tree *MerkleTree) error {
	if transactionsDefinition.CheckFromDBPoolTx(common.TransactionDBPrefix[:], hash) {
		dbTx, err := transactionsDefinition.LoadFromDBPoolTx(common.TransactionDBPrefix[:], hash)
		if err != nil {
			return err
		}
		h := dbTx.Height

		txHeight, err := FindTransactionInBlocks(hash, h)
		if err != nil {
			if !tree.IsTxHashInTree(hash) {
				return nil
			}
			return err
		}

		if txHeight <= 0 {
			logger.GetLogger().Println("transaction not in merkle tree. removing transaction: checkTransactionInDBAndInMarkleTrie")
		} else {
			// Remove from all pending pools and ban — confirmed transactions must
			// never appear in a new block proposal.
			RemoveDuplicateTransactionByHash(hash)
			return fmt.Errorf("transaction was previously added in chain: checkTransactionInDBAndInMarkleTrie")
		}
	}
	return nil
}

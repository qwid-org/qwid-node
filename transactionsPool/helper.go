package transactionsPool

import (
	"fmt"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/database"
	"github.com/qwid-org/qwid-node/logger"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
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

// MarkTxIncluded records that hash was committed in the block at height. Called
// once per transaction when a block is applied (QWID-2026-19).
func MarkTxIncluded(hash []byte, height int64) {
	if err := database.MainDB.Put(append(common.IncludedTxDBPrefix[:], hash...), common.GetByteInt64(height)); err != nil {
		logger.GetLogger().Println("cannot mark transaction as included:", err)
	}
}

// UnmarkTxIncluded removes the included mark for hash. Called for every
// transaction of a block that a rewind removes, so a genuinely reverted
// transaction becomes re-appliable on the canonical chain.
func UnmarkTxIncluded(hash []byte) {
	_ = database.MainDB.Delete(append(common.IncludedTxDBPrefix[:], hash...))
}

// IncludedTxHeight returns the height at which hash was committed, and whether
// it is currently marked as included.
func IncludedTxHeight(hash []byte) (int64, bool) {
	b, err := database.MainDB.Get(append(common.IncludedTxDBPrefix[:], hash...))
	if err != nil || len(b) < 8 {
		return 0, false
	}
	return common.GetInt64FromByte(b), true
}

// CheckTransactionInDBAndInMarkleTrie rejects a transaction that is already
// committed in a block on the current canonical chain.
//
// A transaction is a duplicate iff the included-index holds it — the index is
// written at block commit and cleared for any block a rewind removes, so its
// presence is authoritative REGARDLESS of the transaction's sender-declared
// height. The previous check searched only that declared height, and its merkle
// fallback compared raw hashes against hashed node data and so was structurally
// dead, so it never detected a replayed confirmed transaction: a producer could
// re-include any past transfer and every validator would re-execute it
// (QWID-2026-19). The tree parameter is retained for call-site compatibility;
// the answer no longer depends on it.
func CheckTransactionInDBAndInMarkleTrie(hash []byte, tree *MerkleTree) error {
	if h, ok := IncludedTxHeight(hash); ok {
		// Confirmed transactions must never reappear in a new block proposal.
		RemoveDuplicateTransactionByHash(hash)
		return fmt.Errorf("transaction was already included in block %d: checkTransactionInDBAndInMarkleTrie", h)
	}
	return nil
}

package transactionsPool

import (
	"github.com/wonabru/qwid-node/common"
	"github.com/wonabru/qwid-node/database"
	"github.com/wonabru/qwid-node/logger"
	"github.com/wonabru/qwid-node/transactionsDefinition"
)

// AddEscrowTransaction adds a delayed transaction to the escrow pool and mirrors
// it to the database. Escrow transactions can mature up to ~one week after being
// accepted, so the in-memory pool alone would lose pending escrows on a node
// restart and fail to settle them (a consensus divergence).
func AddEscrowTransaction(tx transactionsDefinition.Transaction) bool {
	ok := PoolTxEscrow.AddTransaction(tx, tx.GetHash())
	if ok {
		if err := tx.StoreToDBPoolTx(common.EscrowPoolDBPrefix[:]); err != nil {
			logger.GetLogger().Println("could not persist escrow transaction", err)
		}
	}
	return ok
}

// RemoveEscrowTransaction removes a transaction from the escrow pool and the
// database, used on settlement and on owner-authorized cancellation.
func RemoveEscrowTransaction(hash []byte) {
	PoolTxEscrow.RemoveTransactionByHash(hash)
	if err := transactionsDefinition.RemoveTransactionFromDBbyHash(common.EscrowPoolDBPrefix[:], hash); err != nil {
		logger.GetLogger().Println("could not delete persisted escrow transaction", err)
	}
}

// LoadEscrowPoolFromDB repopulates the in-memory escrow pool from persisted
// entries at node startup, so pending escrows survive restarts.
func LoadEscrowPoolFromDB() error {
	if database.MainDB == nil {
		return nil
	}
	values, err := database.MainDB.LoadAll(common.EscrowPoolDBPrefix[:])
	if err != nil {
		return err
	}
	for _, bt := range values {
		mt := &transactionsDefinition.Transaction{}
		tx, _, err := mt.GetFromBytes(bt)
		if err != nil {
			logger.GetLogger().Println("could not decode persisted escrow transaction", err)
			continue
		}
		PoolTxEscrow.AddTransaction(tx, tx.GetHash())
	}
	return nil
}

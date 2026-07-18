package transactionsPool

import (
	"bytes"
	"fmt"

	"github.com/wonabru/qwid-node/common"
	"github.com/wonabru/qwid-node/database"
	"github.com/wonabru/qwid-node/logger"
	"github.com/wonabru/qwid-node/transactionsDefinition"
)

var verifyPersistedEscrow = func(tx *transactionsDefinition.Transaction) bool {
	return tx.Verify(common.SigName(), common.SigName2(), common.IsPaused(), common.IsPaused2())
}

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
	keys, err := database.MainDB.LoadAllKeys(common.EscrowPoolDBPrefix[:])
	if err != nil {
		return err
	}
	values, err := database.MainDB.LoadAll(common.EscrowPoolDBPrefix[:])
	if err != nil {
		return err
	}
	if len(keys) != len(values) {
		return fmt.Errorf("escrow persistence key/value count mismatch: %d/%d", len(keys), len(values))
	}
	for i, bt := range values {
		mt := &transactionsDefinition.Transaction{}
		tx, rest, err := mt.GetFromBytes(bt)
		if err != nil {
			logger.GetLogger().Println("could not decode persisted escrow transaction", err)
			_ = database.MainDB.Delete(keys[i])
			continue
		}
		if len(rest) != 0 {
			logger.GetLogger().Println("persisted escrow transaction has trailing bytes")
			_ = database.MainDB.Delete(keys[i])
			continue
		}
		if err := tx.CalcHashAndSet(); err != nil || len(keys[i]) != len(common.EscrowPoolDBPrefix)+common.HashLength ||
			!bytes.Equal(keys[i][len(common.EscrowPoolDBPrefix):], tx.GetHash().GetBytes()) {
			logger.GetLogger().Println("persisted escrow transaction hash does not match database key")
			_ = database.MainDB.Delete(keys[i])
			continue
		}
		if !verifyPersistedEscrow(&tx) {
			logger.GetLogger().Println("persisted escrow transaction signature is invalid")
			_ = database.MainDB.Delete(keys[i])
			continue
		}
		PoolTxEscrow.AddTransaction(tx, tx.GetHash())
	}
	return nil
}

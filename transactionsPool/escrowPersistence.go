package transactionsPool

import (
	"bytes"
	"fmt"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/database"
	"github.com/qwid-org/qwid-node/logger"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
)

// persistedTxPauseFlags returns the pause flags used when re-verifying a
// transaction reloaded from the database on restart: none, for either scheme.
//
// The reason is consistency, not leniency. Only the DATABASE reload re-verifies;
// the in-memory pool of a node that has not restarted does not. Applying the
// pause gate here would therefore make a restarted node drop a pending escrow or
// multisig entry that every still-running node keeps and settles — the exact
// consensus divergence this persistence exists to prevent, now triggered by
// nothing more than who happened to restart.
//
// The scheme NAMES still apply, so the signature must still verify under a
// scheme the node knows. What is dropped is only the liveness gate, matching
// blocks.historicalProofPauseFlags for embedded oracle proofs.
func persistedTxPauseFlags() (bool, bool) {
	return false, false
}

var verifyPersistedEscrow = func(tx *transactionsDefinition.Transaction) bool {
	isPaused, isPaused2 := persistedTxPauseFlags()
	return tx.Verify(common.SigName(), common.SigName2(), isPaused, isPaused2)
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
			// QUARANTINE, do not delete. A signature that fails to verify here
			// is not necessarily corrupt: after a voted scheme replacement every
			// entry signed under the superseded scheme fails verification under
			// the now-current scheme, and deleting it permanently erased pending
			// settlements that still-running nodes go on to perform — a silent,
			// unrecoverable balance divergence (QWID-2026-36). Leaving it in the
			// pool DB unloaded preserves it until a restart with the correct
			// scheme installed can verify and load it; malformed entries
			// (decode/hash/trailing failures above) are still deleted.
			logger.GetLogger().Println("persisted escrow transaction signature did not verify under the current scheme; quarantining (kept, not loaded)")
			continue
		}
		PoolTxEscrow.AddTransaction(tx, tx.GetHash())
	}
	return nil
}

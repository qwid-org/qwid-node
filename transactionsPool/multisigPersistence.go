package transactionsPool

import (
	"bytes"
	"fmt"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/database"
	"github.com/qwid-org/qwid-node/logger"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
)

var verifyPersistedMultiSign = func(tx *transactionsDefinition.Transaction) bool {
	// See persistedTxPauseFlags in escrowPersistence.go for why the pause gate
	// is deliberately not applied to transactions reloaded from the database.
	isPaused, isPaused2 := persistedTxPauseFlags()
	return tx.Verify(common.SigName(), common.SigName2(), isPaused, isPaused2)
}

// MultiSignPoolKeyFor returns the grouping key the multisig pool orders by: a
// main transaction (MultiSignTx unset) groups under its own hash, a
// confirmation under the main transaction's hash. Keeping this derivation in
// one place lets the pool be rebuilt from persisted transactions alone.
func MultiSignPoolKeyFor(tx transactionsDefinition.Transaction) common.Hash {
	if bytes.Equal(tx.TxParam.MultiSignTx.GetBytes(), common.EmptyHash().GetBytes()) {
		return tx.GetHash()
	}
	return tx.TxParam.MultiSignTx
}

// AddMultiSignTransaction adds a transaction to the multisig pool and mirrors
// it to the database. The pool is consensus state rebuilt from applied blocks:
// the main tx enters when its block is applied and confirmations join it from
// later blocks until enough approvals settle the transfer. That can span an
// arbitrary number of blocks, so the in-memory pool alone lost pending
// multisigs on every restart - and a block carrying a confirmation then failed
// with "no main transaction in multi signature pool" forever.
func AddMultiSignTransaction(tx transactionsDefinition.Transaction) bool {
	ok := PoolTxMultiSign.AddTransaction(tx, MultiSignPoolKeyFor(tx))
	if ok {
		if err := tx.StoreToDBPoolTx(common.MultiSignPoolDBPrefix[:]); err != nil {
			logger.GetLogger().Println("could not persist multisig transaction", err)
		}
	}
	return ok
}

// RemoveMultiSignTransaction removes a transaction from the multisig pool and
// the database, used on settlement, expiry and owner-authorized cancellation.
func RemoveMultiSignTransaction(hash []byte) {
	PoolTxMultiSign.RemoveTransactionByHash(hash)
	if err := transactionsDefinition.RemoveTransactionFromDBbyHash(common.MultiSignPoolDBPrefix[:], hash); err != nil {
		logger.GetLogger().Println("could not delete persisted multisig transaction", err)
	}
}

// LoadMultiSignPoolFromDB repopulates the in-memory multisig pool from
// persisted entries at node startup, so pending multisig transfers survive
// restarts. Mirrors LoadEscrowPoolFromDB.
func LoadMultiSignPoolFromDB() error {
	if database.MainDB == nil {
		return nil
	}
	keys, err := database.MainDB.LoadAllKeys(common.MultiSignPoolDBPrefix[:])
	if err != nil {
		return err
	}
	values, err := database.MainDB.LoadAll(common.MultiSignPoolDBPrefix[:])
	if err != nil {
		return err
	}
	if len(keys) != len(values) {
		return fmt.Errorf("multisig persistence key/value count mismatch: %d/%d", len(keys), len(values))
	}
	loaded := 0
	for i, bt := range values {
		mt := &transactionsDefinition.Transaction{}
		tx, rest, err := mt.GetFromBytes(bt)
		if err != nil {
			logger.GetLogger().Println("could not decode persisted multisig transaction", err)
			_ = database.MainDB.Delete(keys[i])
			continue
		}
		if len(rest) != 0 {
			logger.GetLogger().Println("persisted multisig transaction has trailing bytes")
			_ = database.MainDB.Delete(keys[i])
			continue
		}
		if err := tx.CalcHashAndSet(); err != nil || len(keys[i]) != len(common.MultiSignPoolDBPrefix)+common.HashLength ||
			!bytes.Equal(keys[i][len(common.MultiSignPoolDBPrefix):], tx.GetHash().GetBytes()) {
			logger.GetLogger().Println("persisted multisig transaction hash does not match database key")
			_ = database.MainDB.Delete(keys[i])
			continue
		}
		if !verifyPersistedMultiSign(&tx) {
			logger.GetLogger().Println("persisted multisig transaction signature is invalid")
			_ = database.MainDB.Delete(keys[i])
			continue
		}
		PoolTxMultiSign.AddTransaction(tx, MultiSignPoolKeyFor(tx))
		loaded++
	}
	if loaded > 0 {
		logger.GetLogger().Println("restored", loaded, "multisig pool transaction(s) from the database")
	}
	return nil
}

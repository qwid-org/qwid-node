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
		journalPendingChange(journalEscrow, journalAdded, tx)
		if err := tx.StoreToDBPoolTx(common.EscrowPoolDBPrefix[:]); err != nil {
			logger.GetLogger().Println("could not persist escrow transaction", err)
		}
	}
	return ok
}

// RemoveEscrowTransaction removes a transaction from the escrow pool and the
// database, used on settlement and on owner-authorized cancellation.
func RemoveEscrowTransaction(hash []byte) {
	if tx, ok := PoolTxEscrow.GetTransactionByHash(hash); ok {
		journalPendingChange(journalEscrow, journalRemoved, tx)
	}
	PoolTxEscrow.RemoveTransactionByHash(hash)
	if err := transactionsDefinition.RemoveTransactionFromDBbyHash(common.EscrowPoolDBPrefix[:], hash); err != nil {
		logger.GetLogger().Println("could not delete persisted escrow transaction", err)
	}
}

// Outcome of checking one persisted pending-pool entry.
const (
	pendingEntryLoad       = iota // valid: load it
	pendingEntryDrop              // malformed: delete it
	pendingEntryQuarantine        // unverifiable now: keep it, do not load it
)

// checkPersistedPendingTx checks a persisted escrow or multisig entry stored
// under key (prefix + transaction hash).
//
// Block application resets a held transaction's Height to its inclusion block
// (S4-02, so the delay counts from inclusion) and keeps its original hash. The
// loaders used to recompute the hash from that modified body, found it
// different from the key and DELETED the entry - every pending escrow and
// multisig transfer was erased on every restart, and the node diverged from
// the network at the next settlement (audit 2026-10-07 F3-08). An entry whose
// body is not the signed one is now checked against the signed original, kept
// in the confirmed-transaction DB: the two may differ in Height and nothing
// else, and the original's signature must verify.
func checkPersistedPendingTx(key, bt []byte, prefixLen int, verify func(*transactionsDefinition.Transaction) bool) (transactionsDefinition.Transaction, int, string) {
	mt := &transactionsDefinition.Transaction{}
	tx, rest, err := mt.GetFromBytes(bt)
	if err != nil {
		return tx, pendingEntryDrop, fmt.Sprintf("cannot decode: %v", err)
	}
	if len(rest) != 0 {
		return tx, pendingEntryDrop, "trailing bytes"
	}
	if len(key) != prefixLen+common.HashLength || !bytes.Equal(key[prefixLen:], tx.GetHash().GetBytes()) {
		return tx, pendingEntryDrop, "hash does not match database key"
	}
	if tx.HashMatchesBody() {
		if !verify(&tx) {
			return tx, pendingEntryQuarantine, "signature does not verify under the current scheme"
		}
		return tx, pendingEntryLoad, ""
	}
	orig, err := transactionsDefinition.LoadFromDBPoolTx(common.TransactionDBPrefix[:], key[prefixLen:])
	if err != nil {
		return tx, pendingEntryQuarantine, fmt.Sprintf("signed original not found: %v", err)
	}
	held := tx
	held.Height = orig.Height
	if !bytes.Equal(held.GetBytes(), orig.GetBytes()) {
		return tx, pendingEntryQuarantine, "differs from its signed original in more than its height"
	}
	if !verify(&orig) {
		return tx, pendingEntryQuarantine, "signature does not verify under the current scheme"
	}
	return tx, pendingEntryLoad, ""
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
		tx, verdict, why := checkPersistedPendingTx(keys[i], bt, len(common.EscrowPoolDBPrefix), verifyPersistedEscrow)
		switch verdict {
		case pendingEntryDrop:
			logger.GetLogger().Println("persisted escrow transaction dropped:", why)
			_ = database.MainDB.Delete(keys[i])
			continue
		case pendingEntryQuarantine:
			// QUARANTINE, do not delete. A signature that fails to verify here
			// is not necessarily corrupt: after a voted scheme replacement every
			// entry signed under the superseded scheme fails verification under
			// the now-current scheme, and deleting it permanently erased pending
			// settlements that still-running nodes go on to perform — a silent,
			// unrecoverable balance divergence (QWID-2026-36). Leaving it in the
			// pool DB unloaded preserves it until a restart with the correct
			// scheme installed can verify and load it.
			logger.GetLogger().Println("persisted escrow transaction quarantined (kept, not loaded):", why)
			continue
		}
		PoolTxEscrow.AddTransaction(tx, tx.GetHash())
	}
	return nil
}

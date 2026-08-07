package account

import (
	"fmt"

	"github.com/wonabru/qwid-node/common"
	"github.com/wonabru/qwid-node/database"
	"github.com/wonabru/qwid-node/logger"
)

// The per-account transaction-history index.
//
// Every transaction used to append its hash to the sender's and recipient's
// in-state lists, so the accounts snapshot marshaled the whole chain's
// transaction history on every store. The history now lives here, outside the
// state: one key per (account, direction, sequence), value = the 32-byte tx
// hash. The account state keeps only SentCount/ReceivedCount.
//
// Rollback needs no index scans: a rewind restores the counters from the
// snapshot, readers never look at or past the counter, and re-applied
// transactions overwrite the entries above it in place.
//
// Key layout: prefix(2) | address(20) | sequence(8). Entries are addressed by
// exact sequence number (point lookups, never range scans), so the byte order
// of the sequence encoding is irrelevant; GetByteInt64 matches the rest of the
// codebase.

func txHistoryKey(prefix [2]byte, address [common.AddressLength]byte, seq int64) []byte {
	key := make([]byte, 0, len(prefix)+common.AddressLength+8)
	key = append(key, prefix[:]...)
	key = append(key, address[:]...)
	return append(key, common.GetByteInt64(seq)...)
}

// appendTxHistory writes hash as entry seq of the address's history for the
// given direction prefix.
func appendTxHistory(prefix [2]byte, address [common.AddressLength]byte, seq int64, hash common.Hash) error {
	return database.MainDB.Put(txHistoryKey(prefix, address, seq), hash.GetBytes())
}

// readTxHistory returns entries [from, to) of the address's history for the
// given direction prefix, oldest first. Entries that cannot be read are
// skipped: a hole in the index must not take wallet history queries down with
// it.
func readTxHistory(prefix [2]byte, address [common.AddressLength]byte, from, to int64) []common.Hash {
	if from < 0 {
		from = 0
	}
	hashes := make([]common.Hash, 0, to-from)
	for seq := from; seq < to; seq++ {
		b, err := database.MainDB.Get(txHistoryKey(prefix, address, seq))
		if err != nil || len(b) != common.HashLength {
			logger.GetLogger().Println("tx history index: cannot read entry", seq,
				"for", common.Bytes2Hex(address[:]), ":", err)
			continue
		}
		h := common.Hash{}
		copy(h[:], b)
		hashes = append(hashes, h)
	}
	return hashes
}

// GetTxHistorySent returns the account's most recent lastN sent-transaction
// hashes, oldest first (all of them when lastN <= 0).
func GetTxHistorySent(address [common.AddressLength]byte, lastN int64) []common.Hash {
	acc, ok := GetAccountByAddressBytes(address[:])
	if !ok {
		return nil
	}
	from := int64(0)
	if lastN > 0 && acc.SentCount > lastN {
		from = acc.SentCount - lastN
	}
	return readTxHistory(common.TxHistorySentDBPrefix, address, from, acc.SentCount)
}

// GetTxHistoryReceived returns the account's most recent lastN
// received-transaction hashes, oldest first (all of them when lastN <= 0).
func GetTxHistoryReceived(address [common.AddressLength]byte, lastN int64) []common.Hash {
	acc, ok := GetAccountByAddressBytes(address[:])
	if !ok {
		return nil
	}
	from := int64(0)
	if lastN > 0 && acc.ReceivedCount > lastN {
		from = acc.ReceivedCount - lastN
	}
	return readTxHistory(common.TxHistoryReceivedDBPrefix, address, from, acc.ReceivedCount)
}

// migrateTxHistoryLocked moves the in-state transaction-history lists of a
// pre-index snapshot into the DB index and clears them, so the next snapshot
// is slim. Callers hold AccountsRWMutex. Re-running on the same snapshot is
// harmless: entry writes are keyed by (address, sequence), so they overwrite
// themselves, and restoring an OLDER snapshot correctly rolls the counters
// back with re-applied transactions overwriting the tail.
func migrateTxHistoryLocked() {
	migratedAccounts, migratedHashes := 0, 0
	for address, acc := range Accounts.AllAccounts {
		if len(acc.TransactionsSender) == 0 && len(acc.TransactionsRecipient) == 0 {
			continue
		}
		for seq, hash := range acc.TransactionsSender {
			if err := appendTxHistory(common.TxHistorySentDBPrefix, address, int64(seq), hash); err != nil {
				logger.GetLogger().Println("tx history migration failed for",
					common.Bytes2Hex(address[:]), ":", err, "- keeping the in-state lists")
				return
			}
		}
		for seq, hash := range acc.TransactionsRecipient {
			if err := appendTxHistory(common.TxHistoryReceivedDBPrefix, address, int64(seq), hash); err != nil {
				logger.GetLogger().Println("tx history migration failed for",
					common.Bytes2Hex(address[:]), ":", err, "- keeping the in-state lists")
				return
			}
		}
		migratedHashes += len(acc.TransactionsSender) + len(acc.TransactionsRecipient)
		// The lists ARE the full history in the old format, so the counters
		// are their lengths, whatever a partially-written snapshot claims.
		acc.SentCount = int64(len(acc.TransactionsSender))
		acc.ReceivedCount = int64(len(acc.TransactionsRecipient))
		acc.TransactionsSender = nil
		acc.TransactionsRecipient = nil
		Accounts.AllAccounts[address] = acc
		migratedAccounts++
	}
	if migratedAccounts > 0 {
		logger.GetLogger().Println(fmt.Sprintf(
			"migrated tx history of %d account(s) (%d hashes) from the state snapshot to the DB index",
			migratedAccounts, migratedHashes))
	}
}

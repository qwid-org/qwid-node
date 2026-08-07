package account

import (
	"bytes"
	"fmt"
	"github.com/wonabru/qwid-node/logger"
	"sync"

	"github.com/wonabru/qwid-node/common"
	"github.com/wonabru/qwid-node/database"
)

type AccountsType struct {
	AllAccounts map[[common.AddressLength]byte]Account `json:"all_accounts"`
	Height      int64                                  `json:"height"`
}

var Accounts AccountsType
var AccountsRWMutex sync.RWMutex

// AddTransactionsSender records hashTxn as the sender's next history entry.
// The hash goes to the DB index at the account's current sequence number; the
// state keeps only the counter, so snapshots stay O(number of accounts). The
// counter moves only after the index write succeeded - on failure the entry is
// re-written when the transaction is re-applied.
func AddTransactionsSender(address [common.AddressLength]byte, hashTxn common.Hash) {
	AccountsRWMutex.Lock()
	defer AccountsRWMutex.Unlock()
	acc, isOK := Accounts.AllAccounts[address]
	if !isOK {
		// Create new account
		acc = Account{
			Balance: 0,
			Address: address,
		}
		logger.GetLogger().Println("AddTransactionsSender: created new account for", common.Bytes2Hex(address[:]))
	}
	if err := appendTxHistory(common.TxHistorySentDBPrefix, address, acc.SentCount, hashTxn); err != nil {
		logger.GetLogger().Println("cannot store sender tx history entry:", err)
	} else {
		acc.SentCount++
	}
	Accounts.AllAccounts[address] = acc
}

// AddTransactionsRecipient is AddTransactionsSender for the receiving side.
func AddTransactionsRecipient(address [common.AddressLength]byte, hashTxn common.Hash) {
	AccountsRWMutex.Lock()
	defer AccountsRWMutex.Unlock()
	acc, isOK := Accounts.AllAccounts[address]
	if !isOK {
		// Create new account for recipient
		acc = Account{
			Balance: 0,
			Address: address,
		}
		logger.GetLogger().Println("AddTransactionsRecipient: created new account for", common.Bytes2Hex(address[:]))
	}
	if err := appendTxHistory(common.TxHistoryReceivedDBPrefix, address, acc.ReceivedCount, hashTxn); err != nil {
		logger.GetLogger().Println("cannot store recipient tx history entry:", err)
	} else {
		acc.ReceivedCount++
	}
	Accounts.AllAccounts[address] = acc
}

// error is not checked one should do the checking before
func SetBalance(address [common.AddressLength]byte, balance int64) {
	AccountsRWMutex.Lock()
	defer AccountsRWMutex.Unlock()
	acc := Accounts.AllAccounts[address]
	acc.Balance = balance
	acc.Address = address
	Accounts.AllAccounts[address] = acc
}

// error is not checked one should do the checking before
func GetBalance(address [common.AddressLength]byte) int64 {
	AccountsRWMutex.RLock()
	defer AccountsRWMutex.RUnlock()
	return Accounts.AllAccounts[address].Balance
}

// Marshal converts AccountsType to a binary format.
func (at AccountsType) Marshal() []byte {
	var buffer bytes.Buffer
	// Number of accounts
	accountCount := len(at.AllAccounts)
	buffer.Write(common.GetByteInt64(int64(accountCount)))

	// Iterate over map and marshal each account
	for address, acc := range at.AllAccounts {
		buffer.Write(address[:])                               // Write address
		buffer.Write(common.BytesToLenAndBytes(acc.Marshal())) // Marshal and write account
	}
	buffer.Write(common.GetByteInt64(at.Height))
	return buffer.Bytes()
}

// Unmarshal decodes AccountsType from a binary format.
func (at *AccountsType) Unmarshal(data []byte) error {
	if len(data) < 16 {
		return fmt.Errorf("not enough data to unmarshal accounts: need at least 16, have %d", len(data))
	}
	// Number of accounts
	accountCount := common.GetInt64FromByte(data[:8])

	at.AllAccounts = make(map[[common.AddressLength]byte]Account, accountCount)

	data = data[8:]
	// Read each account
	for i := int64(0); i < accountCount; i++ {
		var address [common.AddressLength]byte
		var acc Account
		copy(address[:], data[:20])
		data = data[20:]

		bs, leftBs, err := common.BytesWithLenToBytes(data)
		if err != nil {
			return err
		}
		data = leftBs[:]
		if err := acc.Unmarshal(bs); err != nil {
			return fmt.Errorf("failed to unmarshal account: %w", err)
		}

		at.AllAccounts[address] = acc
	}
	if len(data) != 8 {
		return fmt.Errorf("error with unmarshal account")
	}
	at.Height = common.GetInt64FromByte(data)
	return nil
}

func StoreAccounts(height int64) error {
	if height < 0 {
		height = common.GetHeight()
	}
	AccountsRWMutex.Lock()
	defer AccountsRWMutex.Unlock()
	k := Accounts.Marshal()
	hb := common.GetByteInt64(height)
	prefix := append(common.AccountsDBPrefix[:], hb...)
	err := database.MainDB.Put(prefix, k[:])
	if err != nil {
		logger.GetLogger().Println("cannot store accounts", err)
		return err
	}
	raiseLastStoredHeightMeta(common.AccountsDBPrefix, height)
	return nil
}

func RemoveAccountsFromDB(height int64) error {
	hb := common.GetByteInt64(height)
	prefix := append(common.AccountsDBPrefix[:], hb...)
	err := database.MainDB.Delete(prefix)
	if err != nil {
		logger.GetLogger().Println("cannot remove account", err)
		return err
	}
	return nil
}

func LoadAccounts(height int64) error {
	var err error
	AccountsRWMutex.Lock()
	defer AccountsRWMutex.Unlock()
	if height < 0 {
		height, err = LastHeightStoredInAccounts()
		if err != nil {
			logger.GetLogger().Println(err)
		}
	}

	hb := common.GetByteInt64(height)
	prefix := append(common.AccountsDBPrefix[:], hb...)
	b, err := database.MainDB.Get(prefix)
	if err != nil || b == nil {
		logger.GetLogger().Println("cannot load accounts", err)
		return err
	}
	err = (&Accounts).Unmarshal(b)
	if err != nil {
		logger.GetLogger().Println("cannot unmarshal accounts")
		return err
	}
	// A pre-index snapshot carries the full per-account transaction history in
	// its lists; move it to the DB index so the next store is slim. No-op for
	// snapshots written after the index existed (their lists are empty).
	migrateTxHistoryLocked()
	return nil
}

// AccountsStoredAtHeight reports whether an accounts snapshot exists for height.
// Used by the rewind path to find a height it can actually restore state from,
// instead of aborting on the first missing snapshot.
func AccountsStoredAtHeight(height int64) bool {
	if height < 0 {
		return false
	}
	ib := common.GetByteInt64(height)
	prefix := append(common.AccountsDBPrefix[:], ib...)
	ok, err := database.MainDB.IsKey(prefix)
	return err == nil && ok
}

func LastHeightStoredInAccounts() (int64, error) {
	// Snapshots are stored once per sync batch, so heights have gaps and the
	// authoritative answer lives in the meta key. The contiguity-assuming
	// search below remains only as the fallback for databases from before the
	// meta key existed - those really are contiguous.
	if h, ok := lastStoredHeightMeta(common.AccountsDBPrefix); ok {
		return h, nil
	}
	// AC-M8: find the highest stored height in O(log n) instead of an O(n) linear
	// scan from 0.
	return database.LastContiguousHeight(database.MainDB, func(h int64) []byte {
		return append(common.AccountsDBPrefix[:], common.GetByteInt64(h)...)
	})
}

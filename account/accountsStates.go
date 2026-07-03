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

func AddTransactionsSender(address [common.AddressLength]byte, hashTxn common.Hash) {
	AccountsRWMutex.Lock()
	defer AccountsRWMutex.Unlock()
	acc, isOK := Accounts.AllAccounts[address]
	if !isOK {
		// Create new account
		acc = Account{
			Balance:               0,
			Address:               address,
			TransactionDelay:      0,
			MultiSignNumber:       0,
			TransactionsSender:    make([]common.Hash, 0),
			TransactionsRecipient: make([]common.Hash, 0),
		}
		logger.GetLogger().Println("AddTransactionsSender: created new account for", common.Bytes2Hex(address[:]))
	}
	acc.TransactionsSender = append(acc.TransactionsSender, hashTxn)
	Accounts.AllAccounts[address] = acc
}

func AddTransactionsRecipient(address [common.AddressLength]byte, hashTxn common.Hash) {
	AccountsRWMutex.Lock()
	defer AccountsRWMutex.Unlock()
	acc, isOK := Accounts.AllAccounts[address]
	if !isOK {
		// Create new account for recipient
		acc = Account{
			Balance:               0,
			Address:               address,
			TransactionDelay:      0,
			MultiSignNumber:       0,
			TransactionsSender:    make([]common.Hash, 0),
			TransactionsRecipient: make([]common.Hash, 0),
		}
		logger.GetLogger().Println("AddTransactionsRecipient: created new account for", common.Bytes2Hex(address[:]))
	}
	acc.TransactionsRecipient = append(acc.TransactionsRecipient, hashTxn)
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
	return nil
}

func LastHeightStoredInAccounts() (int64, error) {
	// AC-M8: find the highest stored height in O(log n) instead of an O(n) linear
	// scan from 0. Heights are stored contiguously from 0, so exponential search
	// brackets the boundary and binary search pinpoints it.
	exists := func(h int64) (bool, error) {
		ib := common.GetByteInt64(h)
		prefix := append(common.AccountsDBPrefix[:], ib...)
		return database.MainDB.IsKey(prefix)
	}
	if ok, err := exists(0); err != nil {
		return -1, err
	} else if !ok {
		return -1, nil
	}
	// Exponential search for a hi that does NOT exist (lo always exists).
	lo, hi := int64(0), int64(1)
	for {
		ok, err := exists(hi)
		if err != nil {
			return lo, err
		}
		if !ok {
			break
		}
		lo = hi
		hi *= 2
	}
	// Binary search the boundary in (lo, hi]: lo exists, hi does not.
	for hi-lo > 1 {
		mid := lo + (hi-lo)/2
		ok, err := exists(mid)
		if err != nil {
			return lo, err
		}
		if ok {
			lo = mid
		} else {
			hi = mid
		}
	}
	return lo, nil
}

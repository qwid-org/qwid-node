package account

import (
	"bytes"
	"fmt"
	"github.com/wonabru/qwid-node/common"
	"github.com/wonabru/qwid-node/database"
	"github.com/wonabru/qwid-node/logger"
	"sync"
)

type DexAccountsType struct {
	AllDexAccounts map[[20]byte]DexAccount `json:"all_dex_accounts"`
}

var DexAccounts DexAccountsType
var DexRWMutex sync.RWMutex

// Marshal converts DexAccountsType to a binary format.
func (da DexAccountsType) Marshal() []byte {
	var buffer bytes.Buffer

	// Number of accounts
	accountCount := len(da.AllDexAccounts)
	buffer.Write(common.GetByteInt64(int64(accountCount)))

	// Iterate over map and marshal each account
	for address, acc := range da.AllDexAccounts {
		buffer.Write(address[:]) // Write address
		accb := acc.Marshal()
		buffer.Write(common.BytesToLenAndBytes(accb)) // Marshal and write account
	}

	return buffer.Bytes()
}

// Unmarshal decodes DexAccountsType from a binary format.
func (da *DexAccountsType) Unmarshal(data []byte) error {
	buffer := bytes.NewBuffer(data)

	// Number of accounts
	accountCount := common.GetInt64FromByte(buffer.Next(8))

	da.AllDexAccounts = make(map[[common.AddressLength]byte]DexAccount, accountCount)

	// Read each account
	for i := int64(0); i < accountCount; i++ {
		var address [common.AddressLength]byte
		var acc DexAccount

		// Read address
		if n, err := buffer.Read(address[:]); err != nil || n != common.AddressLength {
			return fmt.Errorf("failed to read address: %w", err)
		}

		// The rest of the data; unmarshal it
		nb := common.GetInt32FromByte(buffer.Next(4))

		if err := acc.Unmarshal(buffer.Next(int(nb))); err != nil {
			return fmt.Errorf("failed to unmarshal account: %w", err)
		}

		da.AllDexAccounts[address] = acc
	}

	return nil
}

func StoreDexAccounts(height int64) error {
	DexRWMutex.Lock()
	defer DexRWMutex.Unlock()

	k := DexAccounts.Marshal()
	hb := common.GetByteInt64(height)
	prefix := append(common.DexAccountsDBPrefix[:], hb...)
	err := database.MainDB.Put(prefix, k[:])
	if err != nil {
		logger.GetLogger().Println("cannot store dex accounts", err)
	}

	return nil
}

func LoadDexAccounts(height int64) error {
	var err error
	DexRWMutex.Lock()
	defer DexRWMutex.Unlock()
	if height < 0 {
		height, err = LastHeightStoredInDexAccounts()
		if err != nil {
			logger.GetLogger().Println(err)
		}
	}

	hb := common.GetByteInt64(height)
	prefix := append(common.DexAccountsDBPrefix[:], hb...)
	b, err := database.MainDB.Get(prefix)
	if err != nil {
		logger.GetLogger().Println("cannot load accounts", err)
		return err
	}
	err = (&DexAccounts).Unmarshal(b)
	if err != nil {
		logger.GetLogger().Println("cannot unmarshal accounts", err)
		return err
	}

	return nil
}

func GetDexAccountByAddressBytes(address []byte) DexAccount {
	DexRWMutex.RLock()
	defer DexRWMutex.RUnlock()
	addrb := [common.AddressLength]byte{}
	copy(addrb[:], address[:common.AddressLength])
	return DexAccounts.AllDexAccounts[addrb]
}

func SetDexAccountByAddressBytes(address []byte, acc DexAccount) {
	DexRWMutex.Lock()
	defer DexRWMutex.Unlock()
	addrb := [common.AddressLength]byte{}
	copy(addrb[:], address[:common.AddressLength])
	DexAccounts.AllDexAccounts[addrb] = acc
}

func GetCoinLiquidityInDex() int64 {
	// AC-M1: guard the map iteration with the DEX lock, like other accessors.
	DexRWMutex.RLock()
	defer DexRWMutex.RUnlock()
	sum := int64(0)
	for _, acc := range DexAccounts.AllDexAccounts {
		sum += acc.CoinPool
	}
	return sum
}

func RemoveDexAccountsFromDB(height int64) error {
	hb := common.GetByteInt64(height)
	prefix := append(common.DexAccountsDBPrefix[:], hb...)
	err := database.MainDB.Delete(prefix)
	if err != nil {
		logger.GetLogger().Println("cannot remove account", err)
		return err
	}
	return nil
}

func LastHeightStoredInDexAccounts() (int64, error) {
	return database.LastContiguousHeight(database.MainDB, func(h int64) []byte {
		return append(common.DexAccountsDBPrefix[:], common.GetByteInt64(h)...)
	})
}

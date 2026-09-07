package account

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/database"
	"github.com/qwid-org/qwid-node/logger"
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

	// Number of accounts. Guard the 8-byte read (GetInt64FromByte panics on a
	// short slice), bound the count by the bytes present, and reject a negative
	// count before make (QWID-2026-14).
	if buffer.Len() < 8 {
		return fmt.Errorf("not enough data to unmarshal dex accounts: have %d", buffer.Len())
	}
	accountCount := common.GetInt64FromByte(buffer.Next(8))
	if accountCount < 0 || accountCount > int64(buffer.Len())/int64(common.AddressLength) {
		return fmt.Errorf("invalid dex account count %d for %d bytes", accountCount, buffer.Len())
	}

	da.AllDexAccounts = make(map[[common.AddressLength]byte]DexAccount, safeMapHint(accountCount))

	// Read each account
	for i := int64(0); i < accountCount; i++ {
		var address [common.AddressLength]byte
		var acc DexAccount

		// Read address
		if n, err := buffer.Read(address[:]); err != nil || n != common.AddressLength {
			return fmt.Errorf("failed to read address: %w", err)
		}

		// The rest of the data; unmarshal it. Guard the 4-byte length read and
		// reject an over-long length — an over-long length would read past the
		// snapshot (QWID-2026-14). The length is written big-endian by
		// BytesToLenAndBytes; the decoder previously read it little-endian, which
		// only round-tripped a SINGLE dex account by accident (the unchecked
		// Next(huge) grabbed all remaining bytes). Read it big-endian to match
		// the encoder, exactly as the staking decoder does.
		if buffer.Len() < 4 {
			return fmt.Errorf("not enough data for dex account length at index %d", i)
		}
		nb := int(binary.BigEndian.Uint32(buffer.Next(4)))
		if nb > buffer.Len() {
			return fmt.Errorf("invalid dex account length %d for remaining %d at index %d", nb, buffer.Len(), i)
		}

		if err := acc.Unmarshal(buffer.Next(nb)); err != nil {
			return fmt.Errorf("failed to unmarshal account: %w", err)
		}

		da.AllDexAccounts[address] = acc
	}

	return nil
}

func StoreDexAccounts(height int64) error {
	// Normalize like StoreAccounts (QWID-2026-12). The shutdown path passes -1,
	// and the previous code wrote the snapshot under the literal signed
	// encoding of -1 — a key no load path can ever select, so every restart
	// silently fell back to the genesis DEX state and validators diverged on
	// pool reserves from then on.
	if height < 0 {
		height = common.GetHeight()
	}
	DexRWMutex.Lock()
	defer DexRWMutex.Unlock()

	k := DexAccounts.Marshal()
	hb := common.GetByteInt64(height)
	prefix := append(common.DexAccountsDBPrefix[:], hb...)
	err := database.MainDB.Put(prefix, k[:])
	if err != nil {
		// Returned, not swallowed: the callers treat a failed accounts store as
		// fatal for the batch, and DEX state is exactly as consensus-relevant.
		logger.GetLogger().Println("cannot store dex accounts", err)
		return err
	}
	raiseLastStoredHeightMeta(common.DexAccountsDBPrefix, height)
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
		// Snapshots are written on the accounts cadence, so heights have gaps.
		// A rewind target between two snapshots falls back to the highest
		// stored height NOT ABOVE the request — never to a newer one, which
		// would resurrect post-rewind DEX state the chain no longer contains.
		// The meta key only records the newest snapshot overall, so this walks
		// downward; the walk is bounded the same way the rewind itself is
		// (MaxStartupRewind), which covers every height the rewind can target.
		found := int64(-1)
		floor := height - common.MaxStartupRewind
		if floor < 0 {
			floor = 0
		}
		for h := height - 1; h >= floor; h-- {
			key := append(common.DexAccountsDBPrefix[:], common.GetByteInt64(h)...)
			if ok, kerr := database.MainDB.IsKey(key); kerr == nil && ok {
				found = h
				break
			}
		}
		if found < 0 {
			logger.GetLogger().Println("cannot load dex accounts at", height, ":", err)
			return err
		}
		logger.GetLogger().Println("no dex snapshot at", height, "- loading the one at", found)
		hb = common.GetByteInt64(found)
		prefix = append(common.DexAccountsDBPrefix[:], hb...)
		if b, err = database.MainDB.Get(prefix); err != nil {
			logger.GetLogger().Println("cannot load dex accounts at fallback", found, ":", err)
			return err
		}
	}
	err = (&DexAccounts).Unmarshal(b)
	if err != nil {
		logger.GetLogger().Println("cannot unmarshal dex accounts", err)
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
	// Same rule as accounts: gaps between snapshots make the meta key the
	// authority; the contiguity-assuming search is only the legacy fallback.
	if h, ok := lastStoredHeightMeta(common.DexAccountsDBPrefix); ok {
		return h, nil
	}
	return database.LastContiguousHeight(database.MainDB, func(h int64) []byte {
		return append(common.DexAccountsDBPrefix[:], common.GetByteInt64(h)...)
	})
}

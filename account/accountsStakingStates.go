package account

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/wonabru/qwid-node/common"
	"github.com/wonabru/qwid-node/database"
	"github.com/wonabru/qwid-node/logger"
)

type StakingAccountsType struct {
	AllStakingAccounts map[[20]byte]StakingAccount `json:"all_staking_accounts"`
	// StakeChangedAt is the containing block timestamp of the change that most
	// recently established this delegated account's current total stake.
	StakeChangedAt int64 `json:"stake_changed_at,omitempty"`
}

var StakingAccounts [256]StakingAccountsType

// Marshal converts AccountsType to a binary format.
func (at StakingAccountsType) Marshal() []byte {
	var buffer bytes.Buffer

	// Number of accounts
	accountCount := len(at.AllStakingAccounts)
	buffer.Write(common.GetByteInt64(int64(accountCount)))

	// Iterate over map and marshal each account
	for address, acc := range at.AllStakingAccounts {
		buffer.Write(address[:]) // Write address
		accb := acc.Marshal()
		buffer.Write(common.BytesToLenAndBytes(accb)) // Marshal and write account
	}
	buffer.Write(common.GetByteInt64(at.StakeChangedAt))

	return buffer.Bytes()
}

// Unmarshal decodes AccountsType from a binary format.
func (at *StakingAccountsType) Unmarshal(data []byte) error {
	buffer := bytes.NewBuffer(data)

	// Number of accounts
	accountCount := common.GetInt64FromByte(buffer.Next(8))

	at.AllStakingAccounts = make(map[[common.AddressLength]byte]StakingAccount, accountCount)

	// Read each account
	for i := int64(0); i < accountCount; i++ {
		var address [common.AddressLength]byte
		var acc StakingAccount

		// Read address
		if n, err := buffer.Read(address[:]); err != nil || n != common.AddressLength {
			return fmt.Errorf("failed to read address: %w", err)
		}

		// The rest of the data is for the StakingAccount; unmarshal it
		nb := int(binary.BigEndian.Uint32(buffer.Next(4)))

		if err := acc.Unmarshal(buffer.Next(nb)); err != nil {
			return fmt.Errorf("failed to unmarshal account: %w", err)
		}

		at.AllStakingAccounts[address] = acc
	}
	if buffer.Len() >= 8 {
		at.StakeChangedAt = common.GetInt64FromByte(buffer.Next(8))
	}

	return nil
}

func StoreStakingAccounts(height int64) error {
	StakingRWMutex.Lock()
	defer StakingRWMutex.Unlock()
	for i := 0; i < 256; i++ {
		k := StakingAccounts[i].Marshal()
		hb := common.GetByteInt64(height)
		prefix := append(common.StakingAccountsDBPrefix[:], hb...)
		prefix = append(prefix, byte(i))
		err := database.MainDB.Put(prefix, k[:])
		if err != nil {
			logger.GetLogger().Println("cannot store accounts", err)
		}
	}
	raiseLastStoredHeightMeta(common.StakingAccountsDBPrefix, height)
	return nil
}

func LoadStakingAccounts(height int64) error {
	var err error
	StakingRWMutex.Lock()
	defer StakingRWMutex.Unlock()
	if height < 0 {
		height, err = LastHeightStoredInStakingAccounts()
		if err != nil {
			logger.GetLogger().Println(err)
		}
	}

	for i := 0; i < 256; i++ {
		hb := common.GetByteInt64(height)
		prefix := append(common.StakingAccountsDBPrefix[:], hb...)
		prefix = append(prefix, byte(i))
		b, err := database.MainDB.Get(prefix)
		if err != nil || b == nil {
			logger.GetLogger().Println("cannot load accounts", err)
			continue
		}
		err = (&StakingAccounts[i]).Unmarshal(b)
		if err != nil {
			logger.GetLogger().Println("cannot unmarshal accounts", err)
			return err
		}
	}
	return nil
}

func GetStakingAccountByAddressBytes(address []byte, delegatedAccount int) StakingAccount {
	StakingRWMutex.RLock()
	defer StakingRWMutex.RUnlock()
	// AC-M2: bounds-check the delegated account index (0..255) before indexing
	// the fixed-size array, so an invalid index returns empty instead of panicking.
	if delegatedAccount < 0 || delegatedAccount >= len(StakingAccounts) {
		return StakingAccount{}
	}
	addrb := [common.AddressLength]byte{}
	copy(addrb[:], address[:common.AddressLength])
	return StakingAccounts[delegatedAccount].AllStakingAccounts[addrb]
}

func RemoveStakingAccountsFromDB(height int64) error {
	hb := common.GetByteInt64(height)
	base := append(common.StakingAccountsDBPrefix[:], hb...)
	for i := 0; i < 256; i++ {
		// AC-M3: build a fresh prefix per iteration. The previous code appended
		// byte(i) to the same accumulating slice, producing prefixes like
		// base+{0}, base+{0,1}, base+{0,1,2}, ... instead of base+{i}.
		prefix := make([]byte, len(base), len(base)+1)
		copy(prefix, base)
		prefix = append(prefix, byte(i))
		err := database.MainDB.Delete(prefix)
		if err != nil {
			logger.GetLogger().Println("cannot remove account", err)
			return err
		}
	}
	return nil
}

// StakingAccountsStoredAtHeight reports whether a staking snapshot exists for
// height. Counterpart of AccountsStoredAtHeight for the rewind path.
func StakingAccountsStoredAtHeight(height int64) bool {
	if height < 0 {
		return false
	}
	ib := common.GetByteInt64(height)
	prefix := append(common.StakingAccountsDBPrefix[:], ib...)
	prefix = append(prefix, byte(1))
	ok, err := database.MainDB.IsKey(prefix)
	return err == nil && ok
}

func LastHeightStoredInStakingAccounts() (int64, error) {
	// Meta key first - snapshot heights have gaps since they are stored once
	// per sync batch. The contiguity search is the pre-meta-database fallback.
	if h, ok := lastStoredHeightMeta(common.StakingAccountsDBPrefix); ok {
		return h, nil
	}
	return database.LastContiguousHeight(database.MainDB, func(h int64) []byte {
		prefix := append(common.StakingAccountsDBPrefix[:], common.GetByteInt64(h)...)
		return append(prefix, byte(1))
	})
}

func GetStakedInAllDelegatedAccounts() int64 {
	StakingRWMutex.RLock()
	defer StakingRWMutex.RUnlock()

	totalStaked := int64(0)

	for _, delegatedAccount := range StakingAccounts {
		for _, sa := range delegatedAccount.AllStakingAccounts {
			totalStaked += sa.StakedBalance
		}
	}

	return totalStaked
}

const MaxActiveStakingNodes = 128

// IsTop128StakingNode reports whether operator controls an eligible delegated
// account in the current staking-state snapshot. Equal delegated totals are
// ordered by the block time at which the current total was
// established; equal seconds are finally ordered by delegated-account ID.
func IsTop128StakingNode(delegatedAccount int, operator common.Address) bool {
	StakingRWMutex.RLock()
	defer StakingRWMutex.RUnlock()

	if delegatedAccount <= 0 || delegatedAccount >= len(StakingAccounts) {
		return false
	}

	var totals [256]int64
	for id, delegated := range StakingAccounts {
		for _, staking := range delegated.AllStakingAccounts {
			totals[id] += staking.StakedBalance
		}
	}

	targetStake := totals[delegatedAccount]
	if targetStake < common.MinStakingForNode {
		return false
	}

	var selectedOperator [common.AddressLength]byte
	selectedStake := int64(-1)
	selectedSince := int64(0)
	for address, staking := range StakingAccounts[delegatedAccount].AllStakingAccounts {
		if !staking.OperationalAccount {
			continue
		}
		if staking.StakedBalance > selectedStake ||
			(staking.StakedBalance == selectedStake &&
				(staking.OperationalSince < selectedSince ||
					(staking.OperationalSince == selectedSince && bytes.Compare(address[:], selectedOperator[:]) < 0))) {
			selectedStake = staking.StakedBalance
			selectedSince = staking.OperationalSince
			selectedOperator = address
		}
	}
	if selectedStake < 0 || !bytes.Equal(selectedOperator[:], operator.GetBytes()) {
		return false
	}

	targetTime := StakingAccounts[delegatedAccount].StakeChangedAt
	rank := 1
	for id, stake := range totals {
		if id == delegatedAccount {
			continue
		}
		candidateTime := StakingAccounts[id].StakeChangedAt
		if stake > targetStake ||
			(stake == targetStake && (candidateTime < targetTime ||
				(candidateTime == targetTime && id < delegatedAccount))) {
			rank++
		}
	}
	return rank <= MaxActiveStakingNodes
}

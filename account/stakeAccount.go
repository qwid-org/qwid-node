package account

import (
	"bytes"
	"fmt"
	"time"

	"github.com/wonabru/qwid-node/common"
)

type StakingAccount struct {
	StakedBalance      int64                      `json:"staked_balance"`
	StakingRewards     int64                      `json:"staking_rewards"`
	LockedAmount       []int64                    `json:"locked_amount"`
	ReleasePerBlock    []int64                    `json:"release_per_block"`
	LockedInitBlock    []int64                    `json:"locked_init_block"`
	DelegatedAccount   [common.AddressLength]byte `json:"delegated_account"`
	Address            [common.AddressLength]byte `json:"address"`
	OperationalAccount bool                       `json:"operational_account"`
	// OperationalSince is the containing block's timestamp (Unix seconds) of
	// the first operator signal. It is consensus data used to resolve equal
	// operator stakes according to the whitepaper's "fastest signal" rule.
	OperationalSince int64                     `json:"operational_since,omitempty"`
	LastStakeHeight  int64                     `json:last_stake_height,omitempty`
	StakingDetails   map[int64][]StakingDetail `json:"staking_details,omitempty"` // block number as key of map
}

type StakingDetail struct {
	Amount      int64 `json:"amount"`
	Reward      int64 `json:"reward"`
	LastUpdated int64 `json:"last_updated"`
}

// pruneStakingDetails folds detail entries older than
// common.StakingDetailsRetentionBlocks below height into a single aggregate
// entry at key 0. Rewards append an entry EVERY block, so without this the
// map grows one entry per block forever and the staking snapshot marshals
// O(chain history). Details are informational (wallet display) - consensus
// reads only StakedBalance/StakingRewards/locks - so folding them changes no
// validation, and the totals a wallet shows stay exact because amounts and
// rewards are summed, never dropped. Callers hold StakingRWMutex.
func pruneStakingDetails(acc *StakingAccount, height int64) {
	cutoff := height - common.StakingDetailsRetentionBlocks
	if cutoff <= 0 || acc.StakingDetails == nil {
		return
	}
	agg := StakingDetail{}
	if existing, ok := acc.StakingDetails[0]; ok && len(existing) > 0 {
		// Previous aggregate (or genesis-height details) - keep folding into it.
		for _, d := range existing {
			agg.Amount += d.Amount
			agg.Reward += d.Reward
			if d.LastUpdated > agg.LastUpdated {
				agg.LastUpdated = d.LastUpdated
			}
		}
	}
	folded := false
	for h, details := range acc.StakingDetails {
		if h == 0 || h >= cutoff {
			continue
		}
		for _, d := range details {
			agg.Amount += d.Amount
			agg.Reward += d.Reward
			if d.LastUpdated > agg.LastUpdated {
				agg.LastUpdated = d.LastUpdated
			}
		}
		delete(acc.StakingDetails, h)
		folded = true
	}
	if folded {
		acc.StakingDetails[0] = []StakingDetail{agg}
	}
}

func GetLockedAmount(accb []byte, height int64, delegatedAccount int) (int64, error) {
	if len(accb) != common.AddressLength {
		return 0, fmt.Errorf("wrong address length, must be %v", common.AddressLength)
	}
	acc := GetStakingAccountByAddressBytes(accb, delegatedAccount)
	if !bytes.Equal(acc.Address[:], accb) {
		copy(acc.Address[:], accb)
	}
	locked := int64(0)
	numLocked := len(acc.LockedAmount)
	toRemoveLockedInd := []int{}
	for ind := 0; ind < numLocked; ind++ {
		lock := acc.LockedAmount[ind] - (height-acc.LockedInitBlock[ind])*acc.ReleasePerBlock[ind]
		if lock <= 0 {
			lock = 0
			toRemoveLockedInd = append(toRemoveLockedInd, ind)
		}
		locked += lock
	}
	return locked, nil
}

func lastStakeBlock(accb StakingAccount) (hmax int64) {
	return accb.LastStakeHeight
}

func Stake(accb []byte, amount int64, height int64, stakingTime int64, delegatedAccount int, operational bool, lockedAmount int64, releasePerBlock int64) error {
	if len(accb) != common.AddressLength {
		return fmt.Errorf("wrong address length, must be %v", common.AddressLength)
	}
	acc := GetStakingAccountByAddressBytes(accb, delegatedAccount)
	if !bytes.Equal(acc.Address[:], accb) {
		copy(acc.Address[:], accb)
	}
	StakingRWMutex.Lock()
	defer StakingRWMutex.Unlock()
	if amount < 0 {
		return fmt.Errorf("staked amount has to be larger or equal than 0")
	}
	if releasePerBlock < 0 {
		return fmt.Errorf("releasePerBlock has to be larger or equal than 0")
	}
	if releasePerBlock > lockedAmount {
		return fmt.Errorf("releasePerBlock cannot be larger than lockedAmount")
	}
	if lockedAmount < 0 {
		return fmt.Errorf("lockedAmount has to be larger or equal than 0")
	}
	if lockedAmount > amount {
		return fmt.Errorf("locked amount cannot be larger than amount")
	}
	hmax := lastStakeBlock(acc)
	if height < hmax+common.MinNumberOfBlocksInStake {
		return fmt.Errorf("staking must be delayed %v blocks", common.MinNumberOfBlocksInStake)
	}
	// in order for someone else not to spoil to be operator
	if lockedAmount == 0 && acc.OperationalAccount == false {
		acc.OperationalAccount = operational
		if operational {
			acc.OperationalSince = stakingTime
		}
	}
	acc.StakedBalance += amount
	acc.LastStakeHeight = height
	if lockedAmount > 0 {
		acc.LockedInitBlock = append(acc.LockedInitBlock, height)
		acc.LockedAmount = append(acc.LockedAmount, lockedAmount)
		acc.ReleasePerBlock = append(acc.ReleasePerBlock, releasePerBlock)
	}
	sd := StakingDetail{
		Amount:      amount,
		Reward:      0,
		LastUpdated: stakingTime,
	}
	// AC-C3: only lazily initialize the map when nil; never replace it, which
	// would erase the staking history recorded at all other heights.
	if acc.StakingDetails == nil {
		acc.StakingDetails = map[int64][]StakingDetail{}
	}
	if _, ok := acc.StakingDetails[height]; !ok {
		acc.StakingDetails[height] = []StakingDetail{}
	}
	acc.StakingDetails[height] = append(acc.StakingDetails[height], sd)
	pruneStakingDetails(&acc, height)
	da := common.GetDelegatedAccountAddress(int16(delegatedAccount))
	copy(acc.DelegatedAccount[:], da.GetBytes())
	copy(acc.Address[:], accb[:])
	StakingAccounts[delegatedAccount].AllStakingAccounts[acc.Address] = acc
	StakingAccounts[delegatedAccount].StakeChangedAt = stakingTime
	return nil
}

func Unstake(accb []byte, amount int64, height int64, stakingTime int64, delegatedAccount int) error {
	if len(accb) != common.AddressLength {
		return fmt.Errorf("wrong address length, must be %v", common.AddressLength)
	}
	acc := GetStakingAccountByAddressBytes(accb, delegatedAccount)
	if !bytes.Equal(acc.Address[:], accb) {
		return fmt.Errorf("no account present in unstaking account")
	}
	StakingRWMutex.Lock()
	defer StakingRWMutex.Unlock()
	if amount >= 0 {
		return fmt.Errorf("unstaked amount has to be larger than 0")
	}
	hmax := lastStakeBlock(acc)
	if height < hmax+common.MinNumberOfBlocksInStake {
		return fmt.Errorf("staking must be delayed %v blocks", common.MinNumberOfBlocksInStake)
	}
	if acc.StakedBalance+amount < 0 {
		return fmt.Errorf("insufficient staked balance")
	}
	locked := int64(0)
	numLocked := len(acc.LockedAmount)
	toRemoveLockedInd := []int{}
	for ind := 0; ind < numLocked; ind++ {
		lock := acc.LockedAmount[ind] - (height-acc.LockedInitBlock[ind])*acc.ReleasePerBlock[ind]
		if lock <= 0 {
			lock = 0
			toRemoveLockedInd = append(toRemoveLockedInd, ind)
		}
		locked += lock
	}
	if acc.StakedBalance-locked+amount < 0 {
		return fmt.Errorf("insufficient staked balance after locking")
	}
	// AC-H1: rebuild the three parallel slices excluding the marked indices.
	// The previous code removed by original index in a loop, but each removal
	// shifts later elements, so subsequent indices were wrong (dropping the
	// wrong entry or panicking).
	if len(toRemoveLockedInd) > 0 {
		remove := make(map[int]bool, len(toRemoveLockedInd))
		for _, ind := range toRemoveLockedInd {
			remove[ind] = true
		}
		newAmount := make([]int64, 0, numLocked)
		newRelease := make([]int64, 0, numLocked)
		newInit := make([]int64, 0, numLocked)
		for i := 0; i < numLocked; i++ {
			if remove[i] {
				continue
			}
			newAmount = append(newAmount, acc.LockedAmount[i])
			newRelease = append(newRelease, acc.ReleasePerBlock[i])
			newInit = append(newInit, acc.LockedInitBlock[i])
		}
		acc.LockedAmount = newAmount
		acc.ReleasePerBlock = newRelease
		acc.LockedInitBlock = newInit
	}
	acc.StakedBalance += amount
	acc.LastStakeHeight = height
	if acc.StakedBalance == 0 {
		acc.OperationalAccount = false
		acc.OperationalSince = 0
	}
	sd := StakingDetail{
		Amount:      amount,
		LastUpdated: stakingTime,
	}
	// AC-C3: only lazily initialize the map when nil; never replace it, which
	// would erase the staking history recorded at all other heights.
	if acc.StakingDetails == nil {
		acc.StakingDetails = map[int64][]StakingDetail{}
	}
	if _, ok := acc.StakingDetails[height]; !ok {
		acc.StakingDetails[height] = []StakingDetail{}
	}
	acc.StakingDetails[height] = append(acc.StakingDetails[height], sd)
	pruneStakingDetails(&acc, height)

	StakingAccounts[delegatedAccount].AllStakingAccounts[acc.Address] = acc
	StakingAccounts[delegatedAccount].StakeChangedAt = stakingTime
	return nil
}

func Reward(accb []byte, reward int64, height int64, delegatedAccount int) error {
	if len(accb) != common.AddressLength {
		return fmt.Errorf("wrong address length, must be %v", common.AddressLength)
	}
	acc := GetStakingAccountByAddressBytes(accb, delegatedAccount)
	if !bytes.Equal(acc.Address[:], accb) {
		return fmt.Errorf("no account present in rewarding account")
	}
	StakingRWMutex.Lock()
	defer StakingRWMutex.Unlock()
	if reward < 0 {
		return fmt.Errorf("reward has to be larger than 0")
	}

	acc.StakingRewards += reward
	sd := StakingDetail{
		Amount:      0,
		Reward:      reward,
		LastUpdated: time.Now().Unix(),
	}
	// AC-C3: only lazily initialize the map when nil; never replace it, which
	// would erase the staking history recorded at all other heights.
	if acc.StakingDetails == nil {
		acc.StakingDetails = map[int64][]StakingDetail{}
	}
	if _, ok := acc.StakingDetails[height]; !ok {
		acc.StakingDetails[height] = []StakingDetail{}
	}
	acc.StakingDetails[height] = append(acc.StakingDetails[height], sd)
	pruneStakingDetails(&acc, height)
	StakingAccounts[delegatedAccount].AllStakingAccounts[acc.Address] = acc
	return nil
}

func WithdrawReward(accb []byte, amount int64, height int64, delegatedAccount int) error {
	if len(accb) != common.AddressLength {
		return fmt.Errorf("wrong address length, must be %v", common.AddressLength)
	}
	acc := GetStakingAccountByAddressBytes(accb, delegatedAccount)
	if !bytes.Equal(acc.Address[:], accb) {
		return fmt.Errorf("no account present in withdraw rewarding")
	}
	StakingRWMutex.Lock()
	defer StakingRWMutex.Unlock()
	if amount >= 0 {
		return fmt.Errorf("withdraw amount has to be larger than 0")
	}

	if acc.StakingRewards+amount < 0 {
		return fmt.Errorf("insufficient rewards balance to withdraw")
	}
	acc.StakingRewards += amount
	sd := StakingDetail{
		Amount:      0,
		Reward:      amount,
		LastUpdated: time.Now().Unix(),
	}
	// AC-C3: only lazily initialize the map when nil; never replace it, which
	// would erase the staking history recorded at all other heights.
	if acc.StakingDetails == nil {
		acc.StakingDetails = map[int64][]StakingDetail{}
	}
	if _, ok := acc.StakingDetails[height]; !ok {
		acc.StakingDetails[height] = []StakingDetail{}
	}
	acc.StakingDetails[height] = append(acc.StakingDetails[height], sd)
	pruneStakingDetails(&acc, height)

	StakingAccounts[delegatedAccount].AllStakingAccounts[acc.Address] = acc
	return nil
}

// Marshal converts StakingAccount to a binary format.
func (sa StakingAccount) Marshal() []byte {

	var buffer bytes.Buffer

	// StakedBalance, StakingRewards
	buffer.Write(common.GetByteInt64(sa.StakedBalance))
	buffer.Write(common.GetByteInt64(sa.StakingRewards))
	numLocked := len(sa.LockedAmount)
	buffer.Write(common.GetByteInt64(int64(numLocked)))
	for ind := 0; ind < numLocked; ind++ {
		buffer.Write(common.GetByteInt64(sa.LockedAmount[ind]))
		buffer.Write(common.GetByteInt64(sa.ReleasePerBlock[ind]))
		buffer.Write(common.GetByteInt64(sa.LockedInitBlock[ind]))
	}
	// Address length and Address
	buffer.Write(sa.DelegatedAccount[:])
	// Address length and Address
	buffer.Write(sa.Address[:])
	buffer.Write([]byte{common.BoolToByte(sa.OperationalAccount)})
	// StakingDetails count
	buffer.Write(common.GetByteInt64(int64(len(sa.StakingDetails))))

	// StakingDetails
	for key, details := range sa.StakingDetails {
		buffer.Write(common.GetByteInt64(key))
		buffer.Write(common.GetByteInt64(int64(len(details))))

		for _, detail := range details {
			buffer.Write(common.GetByteInt64(detail.Amount))
			buffer.Write(common.GetByteInt64(detail.Reward))
			buffer.Write(common.GetByteInt64(detail.LastUpdated))
		}
	}
	// Appended for backward-compatible decoding of existing snapshots.
	buffer.Write(common.GetByteInt64(sa.OperationalSince))

	return buffer.Bytes()
}

// Unmarshal decodes StakingAccount from a binary format.
func (sa *StakingAccount) Unmarshal(data []byte) error {

	buffer := bytes.NewBuffer(data)
	// Ensure there's enough data for StakedBalance and StakingRewards
	if buffer.Len() < 16+8+2*common.AddressLength {
		return fmt.Errorf("insufficient data for StakedBalance and StakingRewards")
	}
	// StakedBalance, StakingRewards
	sa.StakedBalance = common.GetInt64FromByte(buffer.Next(8))
	sa.StakingRewards = common.GetInt64FromByte(buffer.Next(8))
	numLocked := common.GetInt64FromByte(buffer.Next(8))

	sa.LockedAmount = []int64{}
	sa.ReleasePerBlock = []int64{}
	sa.LockedInitBlock = []int64{}
	for ind := int64(0); ind < numLocked; ind++ {
		sa.LockedAmount = append(sa.LockedAmount, common.GetInt64FromByte(buffer.Next(8)))
		sa.ReleasePerBlock = append(sa.ReleasePerBlock, common.GetInt64FromByte(buffer.Next(8)))
		sa.LockedInitBlock = append(sa.LockedInitBlock, common.GetInt64FromByte(buffer.Next(8)))
	}
	// Address
	copy(sa.DelegatedAccount[:], buffer.Next(common.AddressLength))
	copy(sa.Address[:], buffer.Next(common.AddressLength))
	sa.OperationalAccount = false
	if buffer.Next(1)[0] > 0 {
		sa.OperationalAccount = true
	}
	// StakingDetails
	detailsCount := common.GetInt64FromByte(buffer.Next(8))
	sa.StakingDetails = make(map[int64][]StakingDetail, detailsCount)

	for i := int64(0); i < detailsCount; i++ {
		// Ensure there's enough data for the key and the detail count
		if buffer.Len() < 16 {
			return fmt.Errorf("insufficient data for key and detail count at detail %d", i)
		}
		key := common.GetInt64FromByte(buffer.Next(8))
		detailCount := common.GetInt64FromByte(buffer.Next(8))

		details := make([]StakingDetail, detailCount)
		for j := int64(0); j < detailCount; j++ {
			// Ensure there's enough data for each StakingDetail
			if buffer.Len() < 24 {
				return fmt.Errorf("insufficient data for StakingDetail at detail %d, entry %d", i, j)
			}
			amount := common.GetInt64FromByte(buffer.Next(8))
			reward := common.GetInt64FromByte(buffer.Next(8))
			lastUpdated := common.GetInt64FromByte(buffer.Next(8))

			details[j] = StakingDetail{
				Amount:      amount,
				Reward:      reward,
				LastUpdated: lastUpdated,
			}
		}

		sa.StakingDetails[key] = details
	}
	if buffer.Len() >= 8 {
		sa.OperationalSince = common.GetInt64FromByte(buffer.Next(8))
	}
	return nil
}

// GetStakedInDelegatedAccount returns the staking accounts, the total staked
// balance (exact int64, previously float64 which lost precision above 2^53 in
// reward math — AC-H5/AC-M9), and the operational account.
func GetStakedInDelegatedAccount(n int) ([]Account, int64, Account) {
	StakingRWMutex.RLock()
	defer StakingRWMutex.RUnlock()
	sum := int64(0)
	intAcc := Account{
		Balance:               0,
		Address:               [20]byte{},
		TransactionDelay:      0,
		MultiSignNumber:       0,
		MultiSignAddresses:    make([][20]byte, 0),
		TransactionsSender:    make([]common.Hash, 0),
		TransactionsRecipient: make([]common.Hash, 0),
	}
	accs := []Account{}
	operatorSince := int64(0)
	for _, sa := range StakingAccounts[n].AllStakingAccounts {
		acc := Account{
			Balance:               sa.StakedBalance,
			Address:               [20]byte{},
			TransactionDelay:      0,
			MultiSignNumber:       0,
			MultiSignAddresses:    make([][20]byte, 0),
			TransactionsSender:    make([]common.Hash, 0),
			TransactionsRecipient: make([]common.Hash, 0),
		}
		copy(acc.Address[:], sa.Address[:])
		if sa.OperationalAccount && (intAcc.Balance < sa.StakedBalance ||
			(intAcc.Balance == sa.StakedBalance &&
				(sa.OperationalSince < operatorSince ||
					(sa.OperationalSince == operatorSince && bytes.Compare(sa.Address[:], intAcc.Address[:]) < 0)))) {
			intAcc.Balance = sa.StakedBalance
			operatorSince = sa.OperationalSince
			copy(intAcc.Address[:], sa.Address[:])
		}
		sum += sa.StakedBalance
		accs = append(accs, acc)
	}
	return accs, sum, intAcc
}

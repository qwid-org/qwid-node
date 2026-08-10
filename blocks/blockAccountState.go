package blocks

import (
	"fmt"
	"github.com/wonabru/qwid-node/account"
	"github.com/wonabru/qwid-node/common"
)

func AddBalance(address [common.AddressLength]byte, addedAmount int64) error {
	// AC-C1: hold the write lock across the entire read-check-write so two
	// concurrent AddBalance calls cannot both pass the funds check against the
	// same starting balance and overspend. The final write is done inline rather
	// than via SetBalance (which re-acquires the same non-reentrant lock).
	account.AccountsRWMutex.Lock()
	defer account.AccountsRWMutex.Unlock()

	acc, ok := account.Accounts.AllAccounts[address]
	if !ok {
		acc = account.Account{
			Balance:               0,
			Address:               address,
			TransactionDelay:      0,
			MultiSignNumber:       0,
			MultiSignAddresses:    make([][20]byte, 0),
			TransactionsSender:    make([]common.Hash, 0),
			TransactionsRecipient: make([]common.Hash, 0),
		}
		account.Accounts.AllAccounts[address] = acc
	}
	if acc.Balance+addedAmount < 0 {
		return fmt.Errorf("Not enough funds on account")
	}
	acc.Balance += addedAmount
	account.Accounts.AllAccounts[address] = acc
	return nil
}

func GetSupplyInAccounts() int64 {
	sum := int64(0)
	account.AccountsRWMutex.RLock()
	defer account.AccountsRWMutex.RUnlock()
	for _, acc := range account.Accounts.AllAccounts {
		sum += acc.Balance
	}
	return sum
}

func GetSupplyInStakedAccounts() (int64, int64) {
	sumStaked := int64(0)
	sumRewards := int64(0)
	account.StakingRWMutex.RLock()
	defer account.StakingRWMutex.RUnlock()

	for _, delAcc := range account.StakingAccounts {
		for _, acc := range delAcc.AllStakingAccounts {
			sumStaked += acc.StakedBalance
			sumRewards += acc.StakingRewards
		}
	}
	return sumStaked, sumRewards
}

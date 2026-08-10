package blocks

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
	"github.com/stretchr/testify/assert"
)

func initTestAccounts() {
	account.AccountsRWMutex.Lock()
	account.Accounts.AllAccounts = make(map[[common.AddressLength]byte]account.Account)
	account.AccountsRWMutex.Unlock()
}

func initTestStaking() {
	for i := 0; i < 256; i++ {
		account.StakingAccounts[i] = account.StakingAccountsType{
			AllStakingAccounts: make(map[[20]byte]account.StakingAccount),
		}
	}
}

func TestAddBalance(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	t.Run("add balance to new account", func(t *testing.T) {
		initTestAccounts()
		addr := [common.AddressLength]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
		err := AddBalance(addr, 1000000)
		assert.NoError(t, err)
		assert.Equal(t, int64(1000000), account.GetBalance(addr))
	})

	t.Run("add balance to existing account", func(t *testing.T) {
		initTestAccounts()
		addr := [common.AddressLength]byte{2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21}
		account.AccountsRWMutex.Lock()
		account.Accounts.AllAccounts[addr] = account.Account{Address: addr, Balance: 500000}
		account.AccountsRWMutex.Unlock()

		err := AddBalance(addr, 300000)
		assert.NoError(t, err)
		assert.Equal(t, int64(800000), account.GetBalance(addr))
	})

	t.Run("add negative amount (deduct)", func(t *testing.T) {
		initTestAccounts()
		addr := [common.AddressLength]byte{3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22}
		account.AccountsRWMutex.Lock()
		account.Accounts.AllAccounts[addr] = account.Account{Address: addr, Balance: 1000000}
		account.AccountsRWMutex.Unlock()

		err := AddBalance(addr, -400000)
		assert.NoError(t, err)
		assert.Equal(t, int64(600000), account.GetBalance(addr))
	})

	t.Run("insufficient funds returns error", func(t *testing.T) {
		initTestAccounts()
		addr := [common.AddressLength]byte{4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23}
		account.AccountsRWMutex.Lock()
		account.Accounts.AllAccounts[addr] = account.Account{Address: addr, Balance: 100}
		account.AccountsRWMutex.Unlock()

		err := AddBalance(addr, -500)
		assert.Error(t, err)
		// Balance should remain unchanged
		assert.Equal(t, int64(100), account.GetBalance(addr))
	})

	t.Run("exact deduction to zero succeeds", func(t *testing.T) {
		initTestAccounts()
		addr := [common.AddressLength]byte{5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24}
		account.AccountsRWMutex.Lock()
		account.Accounts.AllAccounts[addr] = account.Account{Address: addr, Balance: 1000}
		account.AccountsRWMutex.Unlock()

		err := AddBalance(addr, -1000)
		assert.NoError(t, err)
		assert.Equal(t, int64(0), account.GetBalance(addr))
	})

	t.Run("add zero amount is no-op", func(t *testing.T) {
		initTestAccounts()
		addr := [common.AddressLength]byte{6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25}
		account.AccountsRWMutex.Lock()
		account.Accounts.AllAccounts[addr] = account.Account{Address: addr, Balance: 777}
		account.AccountsRWMutex.Unlock()

		err := AddBalance(addr, 0)
		assert.NoError(t, err)
		assert.Equal(t, int64(777), account.GetBalance(addr))
	})
}

// TestAddBalanceConcurrentNoOverspend verifies AC-C1: many concurrent
// deductions against one account never drive the balance negative and never let
// more than the available balance be withdrawn.
func TestAddBalanceConcurrentNoOverspend(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	initTestAccounts()
	addr := [common.AddressLength]byte{9, 9, 9}
	const start = 100
	account.AccountsRWMutex.Lock()
	account.Accounts.AllAccounts[addr] = account.Account{Address: addr, Balance: start}
	account.AccountsRWMutex.Unlock()

	// 1000 goroutines each try to withdraw 1 unit; only `start` can succeed.
	const workers = 1000
	var wg sync.WaitGroup
	var success int64
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := AddBalance(addr, -1); err == nil {
				atomic.AddInt64(&success, 1)
			}
		}()
	}
	wg.Wait()

	assert.Equal(t, int64(start), atomic.LoadInt64(&success), "exactly start withdrawals should succeed")
	assert.GreaterOrEqual(t, account.GetBalance(addr), int64(0), "balance must never go negative")
	assert.Equal(t, int64(0), account.GetBalance(addr))
}

func TestGetSupplyInAccounts(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	t.Run("empty accounts returns zero", func(t *testing.T) {
		initTestAccounts()
		sum := GetSupplyInAccounts()
		assert.Equal(t, int64(0), sum)
	})

	t.Run("sum of all balances", func(t *testing.T) {
		initTestAccounts()
		addr1 := [common.AddressLength]byte{10, 0}
		addr2 := [common.AddressLength]byte{11, 0}
		addr3 := [common.AddressLength]byte{12, 0}
		account.AccountsRWMutex.Lock()
		account.Accounts.AllAccounts[addr1] = account.Account{Address: addr1, Balance: 1000}
		account.Accounts.AllAccounts[addr2] = account.Account{Address: addr2, Balance: 2000}
		account.Accounts.AllAccounts[addr3] = account.Account{Address: addr3, Balance: 3000}
		account.AccountsRWMutex.Unlock()

		sum := GetSupplyInAccounts()
		assert.Equal(t, int64(6000), sum)
	})

	t.Run("single account", func(t *testing.T) {
		initTestAccounts()
		addr := [common.AddressLength]byte{20, 0}
		account.AccountsRWMutex.Lock()
		account.Accounts.AllAccounts[addr] = account.Account{Address: addr, Balance: 9999999}
		account.AccountsRWMutex.Unlock()

		sum := GetSupplyInAccounts()
		assert.Equal(t, int64(9999999), sum)
	})
}

func TestGetSupplyInStakedAccounts(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	t.Run("empty staking returns zeros", func(t *testing.T) {
		initTestStaking()
		staked, rewards := GetSupplyInStakedAccounts()
		assert.Equal(t, int64(0), staked)
		assert.Equal(t, int64(0), rewards)
	})

	t.Run("sum of staked and rewards", func(t *testing.T) {
		initTestStaking()
		addr1 := [20]byte{1, 0}
		addr2 := [20]byte{2, 0}

		account.StakingRWMutex.Lock()
		account.StakingAccounts[1].AllStakingAccounts[addr1] = account.StakingAccount{
			StakedBalance:  1000000,
			StakingRewards: 50000,
		}
		account.StakingAccounts[2].AllStakingAccounts[addr2] = account.StakingAccount{
			StakedBalance:  2000000,
			StakingRewards: 100000,
		}
		account.StakingRWMutex.Unlock()

		staked, rewards := GetSupplyInStakedAccounts()
		assert.Equal(t, int64(3000000), staked)
		assert.Equal(t, int64(150000), rewards)
	})
}

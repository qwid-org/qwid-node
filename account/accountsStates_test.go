package account

import (
	"testing"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
	"github.com/stretchr/testify/assert"
)

func TestAccountsTypeMarshalUnmarshal(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	t.Run("marshal and unmarshal empty accounts", func(t *testing.T) {
		original := AccountsType{
			AllAccounts: make(map[[common.AddressLength]byte]Account),
			Height:      100,
		}

		data := original.Marshal()
		assert.NotEmpty(t, data)

		var restored AccountsType
		err := restored.Unmarshal(data)
		assert.NoError(t, err)
		assert.Equal(t, original.Height, restored.Height)
		assert.Equal(t, 0, len(restored.AllAccounts))
	})

	t.Run("marshal and unmarshal with accounts", func(t *testing.T) {
		addr1 := [common.AddressLength]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
		addr2 := [common.AddressLength]byte{2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21}

		original := AccountsType{
			AllAccounts: map[[common.AddressLength]byte]Account{
				addr1: {
					Balance: 1000000,
					Address: addr1,
				},
				addr2: {
					Balance: 2000000,
					Address: addr2,
				},
			},
			Height: 200,
		}

		data := original.Marshal()
		var restored AccountsType
		err := restored.Unmarshal(data)
		assert.NoError(t, err)
		assert.Equal(t, original.Height, restored.Height)
		assert.Equal(t, 2, len(restored.AllAccounts))
	})

	t.Run("unmarshal with insufficient data", func(t *testing.T) {
		var at AccountsType
		err := at.Unmarshal([]byte{1, 2, 3})
		// Should handle gracefully (might panic or error depending on implementation)
		// Just check it doesn't crash for very short data
		assert.True(t, err != nil || len(at.AllAccounts) == 0)
	})
}

func TestSetBalance(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	// Initialize
	AccountsRWMutex.Lock()
	Accounts.AllAccounts = make(map[[common.AddressLength]byte]Account)
	AccountsRWMutex.Unlock()

	t.Run("set balance for new account", func(t *testing.T) {
		addr := [common.AddressLength]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}

		// Create account first
		AccountsRWMutex.Lock()
		Accounts.AllAccounts[addr] = Account{Address: addr}
		AccountsRWMutex.Unlock()

		SetBalance(addr, 5000000)
		balance := GetBalance(addr)
		assert.Equal(t, int64(5000000), balance)
	})

	t.Run("update existing balance", func(t *testing.T) {
		addr := [common.AddressLength]byte{2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21}

		AccountsRWMutex.Lock()
		Accounts.AllAccounts[addr] = Account{Address: addr, Balance: 1000}
		AccountsRWMutex.Unlock()

		SetBalance(addr, 10000000)
		balance := GetBalance(addr)
		assert.Equal(t, int64(10000000), balance)
	})
}

func TestSetBalanceSetsAddressForNewAccount(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	// Reset the map
	AccountsRWMutex.Lock()
	Accounts.AllAccounts = make(map[[common.AddressLength]byte]Account)
	AccountsRWMutex.Unlock()

	var a [common.AddressLength]byte
	a[0] = 0x77

	SetBalance(a, 123)

	assert.Equal(t, int64(123), GetBalance(a))

	AccountsRWMutex.RLock()
	storedAddr := Accounts.AllAccounts[a].Address
	AccountsRWMutex.RUnlock()

	assert.Equal(t, a, storedAddr)
}

func TestGetBalance(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	// Initialize
	AccountsRWMutex.Lock()
	Accounts.AllAccounts = make(map[[common.AddressLength]byte]Account)
	AccountsRWMutex.Unlock()

	t.Run("get balance for existing account", func(t *testing.T) {
		addr := [common.AddressLength]byte{3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22}

		AccountsRWMutex.Lock()
		Accounts.AllAccounts[addr] = Account{Address: addr, Balance: 7500000}
		AccountsRWMutex.Unlock()

		balance := GetBalance(addr)
		assert.Equal(t, int64(7500000), balance)
	})

	t.Run("get balance for non-existing account returns zero", func(t *testing.T) {
		addr := [common.AddressLength]byte{4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23}
		balance := GetBalance(addr)
		assert.Equal(t, int64(0), balance)
	})
}

func TestAddTransactionsSender(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	withHistoryTempDB(t)

	// Initialize
	AccountsRWMutex.Lock()
	Accounts.AllAccounts = make(map[[common.AddressLength]byte]Account)
	AccountsRWMutex.Unlock()

	t.Run("add transaction to existing account", func(t *testing.T) {
		addr := [common.AddressLength]byte{5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24}
		hash := common.EmptyHash()

		AccountsRWMutex.Lock()
		Accounts.AllAccounts[addr] = Account{
			Address: addr,
		}
		AccountsRWMutex.Unlock()

		AddTransactionsSender(addr, hash)

		AccountsRWMutex.RLock()
		acc := Accounts.AllAccounts[addr]
		AccountsRWMutex.RUnlock()

		// The state carries only the counter; the hash lives in the DB index.
		assert.Equal(t, int64(1), acc.SentCount)
		assert.Equal(t, 0, len(acc.TransactionsSender))
		assert.Equal(t, []common.Hash{hash}, GetTxHistorySent(addr, 0))
	})

	t.Run("add multiple transactions", func(t *testing.T) {
		addr := [common.AddressLength]byte{6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25}

		AccountsRWMutex.Lock()
		Accounts.AllAccounts[addr] = Account{
			Address: addr,
		}
		AccountsRWMutex.Unlock()

		for i := 0; i < 5; i++ {
			AddTransactionsSender(addr, common.EmptyHash())
		}

		AccountsRWMutex.RLock()
		acc := Accounts.AllAccounts[addr]
		AccountsRWMutex.RUnlock()

		assert.Equal(t, int64(5), acc.SentCount)
		assert.Equal(t, 5, len(GetTxHistorySent(addr, 0)))
		assert.Equal(t, 2, len(GetTxHistorySent(addr, 2)), "tail query returns the requested count")
	})
}

func TestAddTransactionsRecipient(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	withHistoryTempDB(t)

	// Initialize
	AccountsRWMutex.Lock()
	Accounts.AllAccounts = make(map[[common.AddressLength]byte]Account)
	AccountsRWMutex.Unlock()

	t.Run("add recipient transaction", func(t *testing.T) {
		addr := [common.AddressLength]byte{7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26}
		hash := common.EmptyHash()

		AccountsRWMutex.Lock()
		Accounts.AllAccounts[addr] = Account{
			Address: addr,
		}
		AccountsRWMutex.Unlock()

		AddTransactionsRecipient(addr, hash)

		AccountsRWMutex.RLock()
		acc := Accounts.AllAccounts[addr]
		AccountsRWMutex.RUnlock()

		assert.Equal(t, int64(1), acc.ReceivedCount)
		assert.Equal(t, 0, len(acc.TransactionsRecipient))
		assert.Equal(t, []common.Hash{hash}, GetTxHistoryReceived(addr, 0))
	})
}

func TestAccountsRWMutexConcurrency(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	// Initialize
	AccountsRWMutex.Lock()
	Accounts.AllAccounts = make(map[[common.AddressLength]byte]Account)
	AccountsRWMutex.Unlock()

	t.Run("concurrent read/write access", func(t *testing.T) {
		done := make(chan bool, 100)

		// Multiple writers
		for i := 0; i < 50; i++ {
			go func(n int) {
				addr := [common.AddressLength]byte{byte(n)}
				AccountsRWMutex.Lock()
				Accounts.AllAccounts[addr] = Account{Balance: int64(n)}
				AccountsRWMutex.Unlock()
				done <- true
			}(i)
		}

		// Multiple readers
		for i := 0; i < 50; i++ {
			go func() {
				AccountsRWMutex.RLock()
				_ = len(Accounts.AllAccounts)
				AccountsRWMutex.RUnlock()
				done <- true
			}()
		}

		// Wait for all
		for i := 0; i < 100; i++ {
			<-done
		}

		assert.True(t, true)
	})
}

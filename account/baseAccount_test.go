package account

import (
	"testing"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
	"github.com/stretchr/testify/assert"
)

func TestAccountMarshalUnmarshal(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	t.Run("marshal and unmarshal basic account", func(t *testing.T) {
		addr := [common.AddressLength]byte{}
		copy(addr[:], []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20})

		original := Account{
			Balance:               1000000,
			Address:               addr,
			TransactionDelay:      0,
			MultiSignNumber:       0,
			MultiSignAddresses:    nil,
			TransactionsSender:    []common.Hash{},
			TransactionsRecipient: []common.Hash{},
		}

		data := original.Marshal()
		assert.NotEmpty(t, data)

		var restored Account
		err := restored.Unmarshal(data)
		assert.NoError(t, err)
		assert.Equal(t, original.Balance, restored.Balance)
		assert.Equal(t, original.Address, restored.Address)
		assert.Equal(t, original.TransactionDelay, restored.TransactionDelay)
	})

	t.Run("marshal and unmarshal escrow account", func(t *testing.T) {
		addr := [common.AddressLength]byte{}
		copy(addr[:], []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20})

		original := Account{
			Balance:               5000000,
			Address:               addr,
			TransactionDelay:      100,
			MultiSignNumber:       0,
			MultiSignAddresses:    nil,
			TransactionsSender:    []common.Hash{},
			TransactionsRecipient: []common.Hash{},
		}

		data := original.Marshal()
		var restored Account
		err := restored.Unmarshal(data)
		assert.NoError(t, err)
		assert.Equal(t, original.TransactionDelay, restored.TransactionDelay)
	})

	t.Run("marshal and unmarshal multisig account", func(t *testing.T) {
		addr := [common.AddressLength]byte{}
		copy(addr[:], []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20})

		msAddrs := make([][common.AddressLength]byte, 2)
		copy(msAddrs[0][:], []byte{20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1})
		copy(msAddrs[1][:], []byte{10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29})

		original := Account{
			Balance:               2000000,
			Address:               addr,
			TransactionDelay:      0,
			MultiSignNumber:       2,
			MultiSignAddresses:    msAddrs,
			TransactionsSender:    []common.Hash{},
			TransactionsRecipient: []common.Hash{},
		}

		data := original.Marshal()
		var restored Account
		err := restored.Unmarshal(data)
		assert.NoError(t, err)
		assert.Equal(t, original.MultiSignNumber, restored.MultiSignNumber)
		assert.Equal(t, len(original.MultiSignAddresses), len(restored.MultiSignAddresses))
	})

	t.Run("unmarshal with insufficient data", func(t *testing.T) {
		var acc Account
		err := acc.Unmarshal([]byte{1, 2, 3})
		assert.Error(t, err)
	})
}

func TestGetBalanceConfirmedFloat(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	t.Run("convert balance to float", func(t *testing.T) {
		acc := Account{
			Balance: 100000000, // 1.0 with 8 decimals
		}
		floatBal := acc.GetBalanceConfirmedFloat()
		assert.InDelta(t, 1.0, floatBal, 0.0001)
	})

	t.Run("convert zero balance", func(t *testing.T) {
		acc := Account{
			Balance: 0,
		}
		floatBal := acc.GetBalanceConfirmedFloat()
		assert.Equal(t, 0.0, floatBal)
	})

	t.Run("convert large balance", func(t *testing.T) {
		acc := Account{
			Balance: 1000000000000, // 10000.0 with 8 decimals
		}
		floatBal := acc.GetBalanceConfirmedFloat()
		assert.InDelta(t, 10000.0, floatBal, 0.0001)
	})
}

func TestAccountGetString(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	t.Run("basic account string representation", func(t *testing.T) {
		addr := [common.AddressLength]byte{}
		copy(addr[:], []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20})

		acc := Account{
			Balance:            1000000,
			Address:            addr,
			TransactionDelay:   0,
			MultiSignNumber:    0,
			MultiSignAddresses: nil,
		}

		str := acc.GetString()
		assert.Contains(t, str, "Address:")
		assert.Contains(t, str, "Balance:")
	})

	t.Run("escrow account string representation", func(t *testing.T) {
		addr := [common.AddressLength]byte{}
		acc := Account{
			Balance:          1000000,
			Address:          addr,
			TransactionDelay: 100,
		}

		str := acc.GetString()
		assert.Contains(t, str, "Escrow account")
		assert.Contains(t, str, "Transactions Delayed")
	})

	t.Run("multisig account string representation", func(t *testing.T) {
		addr := [common.AddressLength]byte{}
		msAddrs := make([][common.AddressLength]byte, 2)

		acc := Account{
			Balance:            1000000,
			Address:            addr,
			MultiSignNumber:    2,
			MultiSignAddresses: msAddrs,
		}

		str := acc.GetString()
		assert.Contains(t, str, "Multi Signature account")
	})
}

func TestModifyAccountToEscrow(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	// Initialize accounts map
	AccountsRWMutex.Lock()
	if Accounts.AllAccounts == nil {
		Accounts.AllAccounts = make(map[[common.AddressLength]byte]Account)
	}
	AccountsRWMutex.Unlock()

	t.Run("modify to escrow with valid delay", func(t *testing.T) {
		addr := [common.AddressLength]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
		acc := Account{
			Balance:          1000000,
			Address:          addr,
			TransactionDelay: 0,
		}

		err := acc.ModifyAccountToEscrow(100)
		assert.NoError(t, err)
		assert.Equal(t, int64(100), acc.TransactionDelay)
	})

	t.Run("modify already escrow account fails", func(t *testing.T) {
		addr := [common.AddressLength]byte{2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21}
		acc := Account{
			Balance:          1000000,
			Address:          addr,
			TransactionDelay: 50,
		}

		err := acc.ModifyAccountToEscrow(100)
		assert.Error(t, err)
	})

	t.Run("modify with zero delay fails", func(t *testing.T) {
		addr := [common.AddressLength]byte{3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22}
		acc := Account{
			Balance:          1000000,
			Address:          addr,
			TransactionDelay: 0,
		}

		err := acc.ModifyAccountToEscrow(0)
		assert.Error(t, err)
	})

	t.Run("modify with delay exceeding max fails", func(t *testing.T) {
		addr := [common.AddressLength]byte{4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23}
		acc := Account{
			Balance:          1000000,
			Address:          addr,
			TransactionDelay: 0,
		}

		err := acc.ModifyAccountToEscrow(common.MaxTransactionDelay + 1)
		assert.Error(t, err)
	})
}

func TestModifyAccountToMultiSign(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	// Initialize accounts map
	AccountsRWMutex.Lock()
	if Accounts.AllAccounts == nil {
		Accounts.AllAccounts = make(map[[common.AddressLength]byte]Account)
	}
	AccountsRWMutex.Unlock()

	t.Run("modify to multisig with valid params", func(t *testing.T) {
		addr := [common.AddressLength]byte{5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24}
		acc := Account{
			Balance:         1000000,
			Address:         addr,
			MultiSignNumber: 0,
		}

		addresses := []common.Address{
			common.EmptyAddress(),
			common.EmptyAddress(),
		}

		err := acc.ModifyAccountToMultiSign(2, addresses)
		assert.NoError(t, err)
		assert.Equal(t, uint8(2), acc.MultiSignNumber)
	})

	t.Run("modify already multisig account fails", func(t *testing.T) {
		addr := [common.AddressLength]byte{6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25}
		acc := Account{
			Balance:         1000000,
			Address:         addr,
			MultiSignNumber: 2,
		}

		addresses := []common.Address{common.EmptyAddress()}
		err := acc.ModifyAccountToMultiSign(1, addresses)
		assert.Error(t, err)
	})

	t.Run("modify with zero approvals fails", func(t *testing.T) {
		addr := [common.AddressLength]byte{7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26}
		acc := Account{
			Balance:         1000000,
			Address:         addr,
			MultiSignNumber: 0,
		}

		addresses := []common.Address{common.EmptyAddress()}
		err := acc.ModifyAccountToMultiSign(0, addresses)
		assert.Error(t, err)
	})

	t.Run("modify with more approvals than addresses fails", func(t *testing.T) {
		addr := [common.AddressLength]byte{8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27}
		acc := Account{
			Balance:         1000000,
			Address:         addr,
			MultiSignNumber: 0,
		}

		addresses := []common.Address{common.EmptyAddress()}
		err := acc.ModifyAccountToMultiSign(3, addresses)
		assert.Error(t, err)
	})
}

func TestSetAccountByAddressBytes(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	// Initialize accounts map
	AccountsRWMutex.Lock()
	Accounts.AllAccounts = make(map[[common.AddressLength]byte]Account)
	AccountsRWMutex.Unlock()

	t.Run("create new account", func(t *testing.T) {
		addr := []byte{10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29}
		acc := SetAccountByAddressBytes(addr)

		assert.Equal(t, int64(0), acc.Balance)
		assert.NotNil(t, acc.TransactionsSender)
		assert.NotNil(t, acc.TransactionsRecipient)
	})

	t.Run("get existing account", func(t *testing.T) {
		addr := [common.AddressLength]byte{11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30}

		// Create account first
		AccountsRWMutex.Lock()
		Accounts.AllAccounts[addr] = Account{
			Balance: 5000,
			Address: addr,
		}
		AccountsRWMutex.Unlock()

		acc := SetAccountByAddressBytes(addr[:])
		assert.Equal(t, int64(5000), acc.Balance)
	})
}

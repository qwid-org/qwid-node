package account

import (
	"testing"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
	"github.com/stretchr/testify/assert"
)

func TestCoinTokenDetailsMarshalUnmarshal(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	t.Run("marshal and unmarshal", func(t *testing.T) {
		original := CoinTokenDetails{
			CoinBalance:  1000000,
			TokenBalance: 2000000,
		}

		data := original.Marshal()
		assert.Equal(t, 16, len(data))

		restored := CoinTokenDetails{}.Unmarshal(data)
		assert.Equal(t, original.CoinBalance, restored.CoinBalance)
		assert.Equal(t, original.TokenBalance, restored.TokenBalance)
	})

	t.Run("marshal zero values", func(t *testing.T) {
		original := CoinTokenDetails{
			CoinBalance:  0,
			TokenBalance: 0,
		}

		data := original.Marshal()
		restored := CoinTokenDetails{}.Unmarshal(data)
		assert.Equal(t, int64(0), restored.CoinBalance)
		assert.Equal(t, int64(0), restored.TokenBalance)
	})

	t.Run("marshal negative values", func(t *testing.T) {
		original := CoinTokenDetails{
			CoinBalance:  -1000,
			TokenBalance: -2000,
		}

		data := original.Marshal()
		restored := CoinTokenDetails{}.Unmarshal(data)
		assert.Equal(t, original.CoinBalance, restored.CoinBalance)
		assert.Equal(t, original.TokenBalance, restored.TokenBalance)
	})
}

func TestDexAccountMarshalUnmarshal(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	t.Run("marshal and unmarshal empty dex account", func(t *testing.T) {
		original := DexAccount{
			Balances:     make(map[[common.AddressLength]byte]CoinTokenDetails),
			CoinPool:     1000000,
			TokenPool:    2000000,
			TokenPrice:   100,
			TokenAddress: common.EmptyAddress(),
		}

		data := original.Marshal()
		assert.NotEmpty(t, data)

		var restored DexAccount
		err := restored.Unmarshal(data)
		assert.NoError(t, err)
		assert.Equal(t, original.CoinPool, restored.CoinPool)
		assert.Equal(t, original.TokenPool, restored.TokenPool)
		assert.Equal(t, original.TokenPrice, restored.TokenPrice)
	})

	t.Run("marshal and unmarshal with balances", func(t *testing.T) {
		addr1 := [common.AddressLength]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
		addr2 := [common.AddressLength]byte{2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21}

		original := DexAccount{
			Balances: map[[common.AddressLength]byte]CoinTokenDetails{
				addr1: {CoinBalance: 500000, TokenBalance: 600000},
				addr2: {CoinBalance: 700000, TokenBalance: 800000},
			},
			CoinPool:     5000000,
			TokenPool:    10000000,
			TokenPrice:   200,
			TokenAddress: common.EmptyAddress(),
		}

		data := original.Marshal()
		var restored DexAccount
		err := restored.Unmarshal(data)
		assert.NoError(t, err)
		assert.Equal(t, 2, len(restored.Balances))
		assert.Equal(t, original.CoinPool, restored.CoinPool)
		assert.Equal(t, original.TokenPool, restored.TokenPool)
	})

	t.Run("unmarshal with insufficient data", func(t *testing.T) {
		var da DexAccount
		err := da.Unmarshal([]byte{1, 2, 3})
		assert.Error(t, err)
	})

	t.Run("marshal and unmarshal preserves token address", func(t *testing.T) {
		tokenAddr := common.EmptyAddress()
		tokenAddr.ByteValue[0] = 0xAB
		tokenAddr.ByteValue[1] = 0xCD

		original := DexAccount{
			Balances:     make(map[[common.AddressLength]byte]CoinTokenDetails),
			CoinPool:     1000000,
			TokenPool:    2000000,
			TokenPrice:   100,
			TokenAddress: tokenAddr,
		}

		data := original.Marshal()
		var restored DexAccount
		err := restored.Unmarshal(data)
		assert.NoError(t, err)
		assert.Equal(t, tokenAddr.ByteValue, restored.TokenAddress.ByteValue)
	})
}

func TestDexAccountPools(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	t.Run("coin and token pools are independent", func(t *testing.T) {
		da := DexAccount{
			Balances:   make(map[[common.AddressLength]byte]CoinTokenDetails),
			CoinPool:   1000000,
			TokenPool:  5000000,
			TokenPrice: 500,
		}

		assert.NotEqual(t, da.CoinPool, da.TokenPool)
		assert.Equal(t, int64(1000000), da.CoinPool)
		assert.Equal(t, int64(5000000), da.TokenPool)
	})

	t.Run("pool values can be zero", func(t *testing.T) {
		da := DexAccount{
			Balances:   make(map[[common.AddressLength]byte]CoinTokenDetails),
			CoinPool:   0,
			TokenPool:  0,
			TokenPrice: 0,
		}

		data := da.Marshal()
		var restored DexAccount
		err := restored.Unmarshal(data)
		assert.NoError(t, err)
		assert.Equal(t, int64(0), restored.CoinPool)
		assert.Equal(t, int64(0), restored.TokenPool)
	})
}

func TestDexAccountBalances(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	t.Run("add balance for address", func(t *testing.T) {
		da := DexAccount{
			Balances: make(map[[common.AddressLength]byte]CoinTokenDetails),
		}

		addr := [common.AddressLength]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
		da.Balances[addr] = CoinTokenDetails{
			CoinBalance:  100000,
			TokenBalance: 200000,
		}

		assert.Equal(t, 1, len(da.Balances))
		assert.Equal(t, int64(100000), da.Balances[addr].CoinBalance)
		assert.Equal(t, int64(200000), da.Balances[addr].TokenBalance)
	})

	t.Run("multiple addresses", func(t *testing.T) {
		da := DexAccount{
			Balances: make(map[[common.AddressLength]byte]CoinTokenDetails),
		}

		for i := 0; i < 10; i++ {
			addr := [common.AddressLength]byte{byte(i)}
			da.Balances[addr] = CoinTokenDetails{
				CoinBalance:  int64(i * 1000),
				TokenBalance: int64(i * 2000),
			}
		}

		assert.Equal(t, 10, len(da.Balances))
	})

	t.Run("update existing balance", func(t *testing.T) {
		da := DexAccount{
			Balances: make(map[[common.AddressLength]byte]CoinTokenDetails),
		}

		addr := [common.AddressLength]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
		da.Balances[addr] = CoinTokenDetails{CoinBalance: 100, TokenBalance: 200}
		da.Balances[addr] = CoinTokenDetails{CoinBalance: 300, TokenBalance: 400}

		assert.Equal(t, int64(300), da.Balances[addr].CoinBalance)
		assert.Equal(t, int64(400), da.Balances[addr].TokenBalance)
	})
}

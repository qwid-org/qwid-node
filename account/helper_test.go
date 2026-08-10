package account

import (
	"testing"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
	"github.com/stretchr/testify/assert"
)

func TestInt64toFloat64(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	t.Run("convert zero", func(t *testing.T) {
		result := Int64toFloat64(0)
		assert.Equal(t, 0.0, result)
	})

	t.Run("convert one unit", func(t *testing.T) {
		// 1 with 8 decimals = 100000000
		result := Int64toFloat64(100000000)
		assert.InDelta(t, 1.0, result, 0.0001)
	})

	t.Run("convert fractional", func(t *testing.T) {
		// 0.5 with 8 decimals = 50000000
		result := Int64toFloat64(50000000)
		assert.InDelta(t, 0.5, result, 0.0001)
	})

	t.Run("convert large value", func(t *testing.T) {
		// 1000000 with 8 decimals
		result := Int64toFloat64(100000000000000)
		assert.InDelta(t, 1000000.0, result, 0.0001)
	})

	t.Run("convert negative value", func(t *testing.T) {
		result := Int64toFloat64(-100000000)
		assert.InDelta(t, -1.0, result, 0.0001)
	})
}

func TestInt64toFloat64ByDecimals(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	t.Run("convert with 8 decimals", func(t *testing.T) {
		result := Int64toFloat64ByDecimals(100000000, 8)
		assert.InDelta(t, 1.0, result, 0.0001)
	})

	t.Run("convert with 6 decimals", func(t *testing.T) {
		result := Int64toFloat64ByDecimals(1000000, 6)
		assert.InDelta(t, 1.0, result, 0.0001)
	})

	t.Run("convert with 18 decimals", func(t *testing.T) {
		result := Int64toFloat64ByDecimals(1000000000000000000, 18)
		assert.InDelta(t, 1.0, result, 0.0001)
	})

	t.Run("convert with zero decimals", func(t *testing.T) {
		result := Int64toFloat64ByDecimals(100, 0)
		assert.Equal(t, 100.0, result)
	})
}

func TestIntDelegatedAccountFromAddress(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	t.Run("valid delegated account 1", func(t *testing.T) {
		da := common.GetDelegatedAccountAddress(1)
		n, err := IntDelegatedAccountFromAddress(da)
		assert.NoError(t, err)
		assert.Equal(t, 1, n)
	})

	t.Run("valid delegated account 100", func(t *testing.T) {
		da := common.GetDelegatedAccountAddress(100)
		n, err := IntDelegatedAccountFromAddress(da)
		assert.NoError(t, err)
		assert.Equal(t, 100, n)
	})

	t.Run("valid delegated account 255", func(t *testing.T) {
		da := common.GetDelegatedAccountAddress(255)
		n, err := IntDelegatedAccountFromAddress(da)
		assert.NoError(t, err)
		assert.Equal(t, 255, n)
	})

	t.Run("invalid delegated account - non-zero bytes", func(t *testing.T) {
		addr := common.EmptyAddress()
		// Set first two bytes to valid delegated account
		addr.ByteValue[0] = 0
		addr.ByteValue[1] = 1
		// But also set other bytes (invalid)
		addr.ByteValue[5] = 1

		_, err := IntDelegatedAccountFromAddress(addr)
		assert.Error(t, err)
	})

	t.Run("invalid delegated account - zero value", func(t *testing.T) {
		addr := common.EmptyAddress()
		_, err := IntDelegatedAccountFromAddress(addr)
		assert.Error(t, err)
	})

	t.Run("regular address is not delegated account", func(t *testing.T) {
		addr := common.EmptyAddress()
		addr.ByteValue[0] = 0xAB
		addr.ByteValue[1] = 0xCD
		addr.ByteValue[2] = 0xEF

		_, err := IntDelegatedAccountFromAddress(addr)
		assert.Error(t, err)
	})
}

func TestStakingRWMutex(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	t.Run("concurrent access to staking mutex", func(t *testing.T) {
		done := make(chan bool, 20)

		// Multiple readers
		for i := 0; i < 10; i++ {
			go func() {
				StakingRWMutex.RLock()
				StakingRWMutex.RUnlock()
				done <- true
			}()
		}

		// Multiple writers
		for i := 0; i < 10; i++ {
			go func() {
				StakingRWMutex.Lock()
				StakingRWMutex.Unlock()
				done <- true
			}()
		}

		// Wait for all
		for i := 0; i < 20; i++ {
			<-done
		}

		assert.True(t, true)
	})
}

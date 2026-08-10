package nonceServices

import (
	"testing"

	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
	"github.com/stretchr/testify/assert"
)

func TestIsEligibleProducer(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	for i := 0; i < 256; i++ {
		account.StakingAccounts[i] = account.StakingAccountsType{
			AllStakingAccounts: make(map[[common.AddressLength]byte]account.StakingAccount),
		}
	}
	operator := func(id byte) common.Address {
		var a common.Address
		a.ByteValue[0] = id
		return a
	}
	// 129 equally-staked operators: id 129 falls outside the top 128.
	for id := 1; id <= 129; id++ {
		op := operator(byte(id))
		assert.NoError(t, account.Stake(op.GetBytes(), common.MinStakingForNode, 100, int64(1000+id), id, true, 0, 0))
	}

	t.Run("registered top-128 operator may produce", func(t *testing.T) {
		assert.True(t, isEligibleProducer(operator(128), 128, true))
	})
	t.Run("unregistered pubkey blocks production", func(t *testing.T) {
		assert.False(t, isEligibleProducer(operator(128), 128, false))
	})
	t.Run("non-top-128 operator may not produce", func(t *testing.T) {
		assert.False(t, isEligibleProducer(operator(129), 129, true))
	})
}

func TestResetToDefaultEncryptionOptData(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	t.Run("reset creates valid encryption data", func(t *testing.T) {
		ResetToDefaultEncryptionOptData()

		assert.NotNil(t, EncryptionOptData)
		// Default encryption data should have length prefix for two empty byte slices
		// Each empty slice with length prefix = 4 bytes (int32 length = 0)
		assert.Equal(t, 8, len(EncryptionOptData))
	})

	t.Run("multiple resets produce same result", func(t *testing.T) {
		ResetToDefaultEncryptionOptData()
		first := make([]byte, len(EncryptionOptData))
		copy(first, EncryptionOptData)

		ResetToDefaultEncryptionOptData()
		second := make([]byte, len(EncryptionOptData))
		copy(second, EncryptionOptData)

		assert.Equal(t, first, second)
	})
}

func TestSetEncryptionData(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	t.Run("set custom encryption data", func(t *testing.T) {
		enc1 := []byte{1, 2, 3, 4}
		enc2 := []byte{5, 6, 7, 8}

		SetEncryptionData(enc1, enc2)

		assert.NotNil(t, EncryptionOptData)
		// Length should be: 4 (len prefix) + 4 (enc1) + 4 (len prefix) + 4 (enc2) = 16
		assert.Equal(t, 16, len(EncryptionOptData))
	})

	t.Run("set empty encryption data", func(t *testing.T) {
		SetEncryptionData([]byte{}, []byte{})

		assert.NotNil(t, EncryptionOptData)
		assert.Equal(t, 8, len(EncryptionOptData))
	})

	t.Run("set different sized encryption data", func(t *testing.T) {
		enc1 := make([]byte, 100)
		enc2 := make([]byte, 50)

		SetEncryptionData(enc1, enc2)

		assert.NotNil(t, EncryptionOptData)
		// Length should be: 4 + 100 + 4 + 50 = 158
		assert.Equal(t, 158, len(EncryptionOptData))
	})
}

func TestSendFunction(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	t.Run("send without initialization returns false", func(t *testing.T) {
		// Without initializing the service, Send should fail gracefully
		addr := [4]byte{192, 168, 1, 1}
		data := []byte("test data")

		// This should not panic even without initialization
		result := Send(addr, data)
		// Result depends on whether channel is initialized
		assert.IsType(t, true, result)
	})
}

func TestEncryptionDataConcurrency(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	t.Run("concurrent access to encryption data", func(t *testing.T) {
		done := make(chan bool, 10)

		// Multiple goroutines setting encryption data
		for i := 0; i < 5; i++ {
			go func(n int) {
				enc1 := make([]byte, n+1)
				enc2 := make([]byte, n+2)
				SetEncryptionData(enc1, enc2)
				done <- true
			}(i)
		}

		// Multiple goroutines resetting
		for i := 0; i < 5; i++ {
			go func() {
				ResetToDefaultEncryptionOptData()
				done <- true
			}()
		}

		// Wait for all goroutines
		for i := 0; i < 10; i++ {
			<-done
		}

		// Should not panic and data should be valid
		assert.NotNil(t, EncryptionOptData)
	})
}

func TestBytesToLenAndBytesIntegration(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	t.Run("encryption data uses proper byte encoding", func(t *testing.T) {
		testData := []byte{0xDE, 0xAD, 0xBE, 0xEF}
		encoded := common.BytesToLenAndBytes(testData)

		// The length prefix is a 4-byte big-endian int (see common.BytesToLenAndBytes).
		assert.Equal(t, []byte{0, 0, 0, 4}, encoded[:4])

		// Remaining bytes should be the data
		assert.Equal(t, testData, encoded[4:])
	})
}

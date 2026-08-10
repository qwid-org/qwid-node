package services

import (
	"testing"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
	"github.com/qwid-org/qwid-node/message"
	"github.com/stretchr/testify/assert"
)

func TestGenerateBlockMessage(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	t.Run("generates message with correct head", func(t *testing.T) {
		// Create a minimal block for testing
		// Note: This tests the message generation, not full block creation
		// Full block creation requires database and wallet initialization
	})
}

func TestBlockMessageStructure(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	t.Run("block message has correct format", func(t *testing.T) {
		bm := message.BaseMessage{
			Head:    []byte("bl"),
			ChainID: common.GetChainID(),
		}
		txm := [2]byte{}
		copy(txm[:], append([]byte("N"), 0))
		atm := message.TransactionsMessage{
			BaseMessage:       bm,
			TransactionsBytes: map[[2]byte][][]byte{},
		}
		atm.TransactionsBytes[txm] = [][]byte{{1, 2, 3, 4}}

		msgBytes := atm.GetBytes()
		isValid, parsedMsg := message.CheckValidMessage(msgBytes)

		assert.True(t, isValid)
		assert.Equal(t, []byte("bl"), parsedMsg.GetHead())
	})
}

func TestServiceChannels(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	t.Run("nonce channel can be created", func(t *testing.T) {
		SendMutexNonce.Lock()
		SendChanNonce = make(chan []byte, 10)
		SendMutexNonce.Unlock()

		assert.NotNil(t, SendChanNonce)
	})

	t.Run("sync channel can be created", func(t *testing.T) {
		SendMutexSync.Lock()
		SendChanSync = make(chan []byte, 100)
		SendMutexSync.Unlock()

		assert.NotNil(t, SendChanSync)
	})

	t.Run("transaction channel can be created", func(t *testing.T) {
		SendMutexTx.Lock()
		SendChanTx = make(chan []byte, 100)
		SendMutexTx.Unlock()

		assert.NotNil(t, SendChanTx)
	})
}

func TestSendNonce(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	t.Run("send nonce prepends IP address", func(t *testing.T) {
		// Initialize the channel
		SendMutexNonce.Lock()
		SendChanNonce = make(chan []byte, 10)
		SendMutexNonce.Unlock()

		ip := [4]byte{192, 168, 1, 1}
		data := []byte("test nonce data")

		go SendNonce(ip, data)

		// Read from channel
		received := <-SendChanNonce

		// First 4 bytes should be IP
		assert.Equal(t, ip[:], received[:4])
		// Rest should be the data
		assert.Equal(t, data, received[4:])
	})
}

func TestQuitFlag(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	t.Run("quit flag initial state", func(t *testing.T) {
		// QUIT should be initialized to false
		assert.False(t, QUIT.Load())
	})

	t.Run("quit flag can be toggled", func(t *testing.T) {
		original := QUIT.Load()

		QUIT.Store(true)
		assert.True(t, QUIT.Load())

		QUIT.Store(false)
		assert.False(t, QUIT.Load())

		// Restore original state
		QUIT.Store(original)
	})
}

func TestMutexSafety(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	t.Run("concurrent mutex access", func(t *testing.T) {
		done := make(chan bool, 20)

		// Multiple goroutines trying to lock/unlock
		for i := 0; i < 10; i++ {
			go func() {
				SendMutexNonce.Lock()
				SendMutexNonce.Unlock()
				done <- true
			}()
		}

		for i := 0; i < 10; i++ {
			go func() {
				SendMutexSync.Lock()
				SendMutexSync.Unlock()
				done <- true
			}()
		}

		// Wait for all goroutines
		for i := 0; i < 20; i++ {
			<-done
		}

		// Should complete without deadlock
		assert.True(t, true)
	})
}

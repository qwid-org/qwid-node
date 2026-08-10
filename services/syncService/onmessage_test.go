package syncServices

import (
	"testing"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
	"github.com/qwid-org/qwid-node/message"
	"github.com/stretchr/testify/assert"
)

func TestOnMessageInvalidInput(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	addr := [4]byte{192, 168, 1, 1}

	t.Run("empty message", func(t *testing.T) {
		assert.NotPanics(t, func() {
			OnMessage(addr, []byte{})
		})
	})

	t.Run("too short message", func(t *testing.T) {
		assert.NotPanics(t, func() {
			OnMessage(addr, []byte{1, 2, 3})
		})
	})

	t.Run("invalid message format", func(t *testing.T) {
		invalidMsg := make([]byte, 100)
		for i := range invalidMsg {
			invalidMsg[i] = byte(i)
		}
		assert.NotPanics(t, func() {
			OnMessage(addr, invalidMsg)
		})
	})
}

func TestOnMessageRecovery(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	addr := [4]byte{10, 0, 0, 1}

	t.Run("recovers from malformed data", func(t *testing.T) {
		malformedMsg := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
		assert.NotPanics(t, func() {
			OnMessage(addr, malformedMsg)
		})
	})
}

func TestSyncMessageValidation(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	t.Run("valid hi message structure", func(t *testing.T) {
		bm := message.BaseMessage{
			Head:    []byte("hi"),
			ChainID: common.GetChainID(),
		}
		tm := message.TransactionsMessage{
			BaseMessage:       bm,
			TransactionsBytes: map[[2]byte][][]byte{},
		}
		tm.TransactionsBytes[[2]byte{'L', 'H'}] = [][]byte{common.GetByteInt64(100)}
		tm.TransactionsBytes[[2]byte{'L', 'B'}] = [][]byte{make([]byte, 32)}
		tm.TransactionsBytes[[2]byte{'P', 'P'}] = [][]byte{}

		msgBytes := tm.GetBytes()

		isValid, parsedMsg := message.CheckValidMessage(msgBytes)
		assert.True(t, isValid)
		assert.Equal(t, []byte("hi"), parsedMsg.GetHead())
	})

	t.Run("valid gh message structure", func(t *testing.T) {
		bm := message.BaseMessage{
			Head:    []byte("gh"),
			ChainID: common.GetChainID(),
		}
		tm := message.TransactionsMessage{
			BaseMessage:       bm,
			TransactionsBytes: map[[2]byte][][]byte{},
		}
		tm.TransactionsBytes[[2]byte{'B', 'H'}] = [][]byte{common.GetByteInt64(0)}
		tm.TransactionsBytes[[2]byte{'E', 'H'}] = [][]byte{common.GetByteInt64(10)}

		msgBytes := tm.GetBytes()

		isValid, parsedMsg := message.CheckValidMessage(msgBytes)
		assert.True(t, isValid)
		assert.Equal(t, []byte("gh"), parsedMsg.GetHead())
	})

	t.Run("valid sh message structure", func(t *testing.T) {
		bm := message.BaseMessage{
			Head:    []byte("sh"),
			ChainID: common.GetChainID(),
		}
		tm := message.TransactionsMessage{
			BaseMessage:       bm,
			TransactionsBytes: map[[2]byte][][]byte{},
		}
		tm.TransactionsBytes[[2]byte{'I', 'H'}] = [][]byte{}
		tm.TransactionsBytes[[2]byte{'H', 'V'}] = [][]byte{}

		msgBytes := tm.GetBytes()

		isValid, parsedMsg := message.CheckValidMessage(msgBytes)
		assert.True(t, isValid)
		assert.Equal(t, []byte("sh"), parsedMsg.GetHead())
	})

	t.Run("invalid chain ID rejected", func(t *testing.T) {
		bm := message.BaseMessage{
			Head:    []byte("hi"),
			ChainID: -999,
		}
		tm := message.TransactionsMessage{
			BaseMessage:       bm,
			TransactionsBytes: map[[2]byte][][]byte{},
		}
		msgBytes := tm.GetBytes()

		isValid, _ := message.CheckValidMessage(msgBytes)
		assert.False(t, isValid)
	})
}

func TestAddressHandlingSync(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	addresses := [][4]byte{
		{0, 0, 0, 0},
		{127, 0, 0, 1},
		{192, 168, 1, 1},
		{255, 255, 255, 255},
	}

	for _, addr := range addresses {
		t.Run("address_handling", func(t *testing.T) {
			assert.NotPanics(t, func() {
				OnMessage(addr, []byte{})
			})
		})
	}
}

func TestHeightMessageParsing(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	t.Run("parse height from message", func(t *testing.T) {
		height := int64(12345)
		heightBytes := common.GetByteInt64(height)

		parsedHeight := common.GetInt64FromByte(heightBytes)
		assert.Equal(t, height, parsedHeight)
	})

	t.Run("parse zero height", func(t *testing.T) {
		height := int64(0)
		heightBytes := common.GetByteInt64(height)

		parsedHeight := common.GetInt64FromByte(heightBytes)
		assert.Equal(t, height, parsedHeight)
	})

	t.Run("parse large height", func(t *testing.T) {
		height := int64(9999999999)
		heightBytes := common.GetByteInt64(height)

		parsedHeight := common.GetInt64FromByte(heightBytes)
		assert.Equal(t, height, parsedHeight)
	})
}

func TestSyncStateManagement(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	t.Run("syncing state can be toggled", func(t *testing.T) {
		// Store original state
		original := common.IsSyncing.Load()

		common.IsSyncing.Store(true)
		assert.True(t, common.IsSyncing.Load())

		common.IsSyncing.Store(false)
		assert.False(t, common.IsSyncing.Load())

		// Restore original state
		common.IsSyncing.Store(original)
	})
}

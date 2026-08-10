package transactionServices

import (
	"testing"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
	"github.com/qwid-org/qwid-node/message"
	"github.com/stretchr/testify/assert"
)

func TestOnMessageInvalidMessage(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	addr := [4]byte{192, 168, 1, 1}

	t.Run("empty message", func(t *testing.T) {
		// Should not panic with empty message
		assert.NotPanics(t, func() {
			OnMessage(addr, []byte{})
		})
	})

	t.Run("too short message", func(t *testing.T) {
		// Should not panic with very short message
		assert.NotPanics(t, func() {
			OnMessage(addr, []byte{1, 2, 3})
		})
	})

	t.Run("invalid message format", func(t *testing.T) {
		// Random bytes that don't form a valid message
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
		// Malformed message should trigger recovery
		malformedMsg := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
		assert.NotPanics(t, func() {
			OnMessage(addr, malformedMsg)
		})
	})
}

func TestMessageValidation(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	t.Run("check valid message structure", func(t *testing.T) {
		// Create a properly structured message
		bm := message.BaseMessage{
			Head:    []byte("tx"),
			ChainID: common.GetChainID(),
		}
		tm := message.TransactionsMessage{
			BaseMessage:       bm,
			TransactionsBytes: map[[2]byte][][]byte{},
		}
		msgBytes := tm.GetBytes()

		// Verify message can be validated
		isValid, _ := message.CheckValidMessage(msgBytes)
		assert.True(t, isValid)
	})

	t.Run("check invalid chain ID", func(t *testing.T) {
		bm := message.BaseMessage{
			Head:    []byte("tx"),
			ChainID: -1, // Invalid chain ID
		}
		tm := message.TransactionsMessage{
			BaseMessage:       bm,
			TransactionsBytes: map[[2]byte][][]byte{},
		}
		msgBytes := tm.GetBytes()

		isValid, _ := message.CheckValidMessage(msgBytes)
		// Should be invalid due to wrong chain ID
		assert.False(t, isValid)
	})
}

func TestMessageHeadTypes(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	headTypes := []struct {
		head        string
		description string
	}{
		{"tx", "regular transaction"},
		{"bx", "sync transaction"},
		{"st", "sync transaction request"},
		{"bt", "block transaction request"},
	}

	for _, ht := range headTypes {
		t.Run("head_type_"+ht.head, func(t *testing.T) {
			bm := message.BaseMessage{
				Head:    []byte(ht.head),
				ChainID: common.GetChainID(),
			}
			tm := message.TransactionsMessage{
				BaseMessage:       bm,
				TransactionsBytes: map[[2]byte][][]byte{},
			}
			msgBytes := tm.GetBytes()

			isValid, parsedMsg := message.CheckValidMessage(msgBytes)
			assert.True(t, isValid)
			assert.Equal(t, []byte(ht.head), parsedMsg.GetHead())
		})
	}
}

func TestAddressHandling(t *testing.T) {
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
			// OnMessage should handle various IP addresses without panic
			assert.NotPanics(t, func() {
				OnMessage(addr, []byte{})
			})
		})
	}
}

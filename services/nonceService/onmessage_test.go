package nonceServices

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

func TestOnMessageWhenSyncing(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	t.Run("returns early when syncing", func(t *testing.T) {
		// Set syncing state
		common.IsSyncing.Store(true)
		defer common.IsSyncing.Store(false)

		addr := [4]byte{10, 0, 0, 1}

		// Should return early without processing
		assert.NotPanics(t, func() {
			OnMessage(addr, []byte{1, 2, 3, 4, 5})
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

func TestMessageValidationNonce(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	t.Run("valid nonce message structure", func(t *testing.T) {
		bm := message.BaseMessage{
			Head:    []byte("nn"),
			ChainID: common.GetChainID(),
		}
		tm := message.TransactionsMessage{
			BaseMessage:       bm,
			TransactionsBytes: map[[2]byte][][]byte{},
		}
		msgBytes := tm.GetBytes()

		isValid, parsedMsg := message.CheckValidMessage(msgBytes)
		assert.True(t, isValid)
		assert.Equal(t, []byte("nn"), parsedMsg.GetHead())
	})

	t.Run("valid block message structure", func(t *testing.T) {
		bm := message.BaseMessage{
			Head:    []byte("bl"),
			ChainID: common.GetChainID(),
		}
		tm := message.TransactionsMessage{
			BaseMessage:       bm,
			TransactionsBytes: map[[2]byte][][]byte{},
		}
		msgBytes := tm.GetBytes()

		isValid, parsedMsg := message.CheckValidMessage(msgBytes)
		assert.True(t, isValid)
		assert.Equal(t, []byte("bl"), parsedMsg.GetHead())
	})

	t.Run("invalid chain ID rejected", func(t *testing.T) {
		bm := message.BaseMessage{
			Head:    []byte("nn"),
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

func TestNonceMessageHeadTypes(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	headTypes := []struct {
		head        string
		description string
	}{
		{"nn", "nonce message"},
		{"rb", "reject block"},
		{"bl", "block message"},
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

func TestAddressHandlingNonce(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	// Ensure not syncing for these tests
	common.IsSyncing.Store(false)

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

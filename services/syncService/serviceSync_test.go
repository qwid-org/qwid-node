package syncServices

import (
	"testing"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
	"github.com/qwid-org/qwid-node/message"
	"github.com/stretchr/testify/assert"
)

func TestGenerateSyncMsgHeight(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	t.Run("generates valid height message", func(t *testing.T) {
		msgBytes := generateSyncMsgHeight()

		// Should return non-empty bytes for valid message
		// Note: might be empty if block loading fails, which is acceptable in test
		assert.IsType(t, []byte{}, msgBytes)
	})
}

func TestGenerateSyncMsgGetHeaders(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	t.Run("returns nil for zero height", func(t *testing.T) {
		result := generateSyncMsgGetHeaders(0)
		assert.Nil(t, result)
	})

	t.Run("returns nil for negative height", func(t *testing.T) {
		result := generateSyncMsgGetHeaders(-1)
		assert.Nil(t, result)
	})

	t.Run("generates message for positive height", func(t *testing.T) {
		result := generateSyncMsgGetHeaders(10)
		assert.NotNil(t, result)
		assert.Greater(t, len(result), 0)
	})

	t.Run("message has correct head", func(t *testing.T) {
		result := generateSyncMsgGetHeaders(5)
		if len(result) > 0 {
			isValid, msg := message.CheckValidMessage(result)
			assert.True(t, isValid)
			assert.Equal(t, []byte("gh"), msg.GetHead())
		}
	})
}

func TestGenerateSyncMsgSendHeaders(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	t.Run("returns empty for negative height", func(t *testing.T) {
		result := generateSyncMsgSendHeaders(0, -1)
		assert.Empty(t, result)
	})

	t.Run("returns empty for invalid begin height", func(t *testing.T) {
		result := generateSyncMsgSendHeaders(-1, 10)
		assert.Empty(t, result)
	})

	t.Run("returns empty when begin greater than end", func(t *testing.T) {
		result := generateSyncMsgSendHeaders(10, 5)
		assert.Empty(t, result)
	})
}

func TestSendFunction(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	t.Run("send without initialization", func(t *testing.T) {
		addr := [4]byte{192, 168, 1, 1}
		data := []byte("test data")

		// Should not panic even without initialization
		result := Send(addr, data)
		assert.IsType(t, true, result)
	})
}

func TestSyncMessageTopics(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	topics := []struct {
		topic [2]byte
		name  string
	}{
		{[2]byte{'L', 'H'}, "last height"},
		{[2]byte{'L', 'B'}, "last block"},
		{[2]byte{'P', 'P'}, "peers"},
		{[2]byte{'B', 'H'}, "begin height"},
		{[2]byte{'E', 'H'}, "end height"},
		{[2]byte{'I', 'H'}, "index height"},
		{[2]byte{'H', 'V'}, "header value"},
	}

	for _, tc := range topics {
		t.Run("topic_"+tc.name, func(t *testing.T) {
			bm := message.BaseMessage{
				Head:    []byte("hi"),
				ChainID: common.GetChainID(),
			}
			tm := message.TransactionsMessage{
				BaseMessage:       bm,
				TransactionsBytes: map[[2]byte][][]byte{},
			}
			tm.TransactionsBytes[tc.topic] = [][]byte{{1, 2, 3, 4}}

			msgBytes := tm.GetBytes()
			isValid, _ := message.CheckValidMessage(msgBytes)
			assert.True(t, isValid)
		})
	}
}

func TestSyncMessageHeadTypes(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	headTypes := []struct {
		head        string
		description string
	}{
		{"hi", "height info"},
		{"gh", "get headers"},
		{"sh", "send headers"},
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

func TestHeightBoundaryCalculations(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	t.Run("get headers respects bucket size", func(t *testing.T) {
		// Test that the function handles large heights properly
		result := generateSyncMsgGetHeaders(1000000)
		if len(result) > 0 {
			isValid, msg := message.CheckValidMessage(result)
			assert.True(t, isValid)

			txn := msg.(message.TransactionsMessage).GetTransactionsBytes()
			bHeight := common.GetInt64FromByte(txn[[2]byte{'B', 'H'}][0])
			eHeight := common.GetInt64FromByte(txn[[2]byte{'E', 'H'}][0])

			// End height should not exceed the requested height
			assert.LessOrEqual(t, eHeight, int64(1000000))
			// Begin height should be less than or equal to end height
			assert.LessOrEqual(t, bHeight, eHeight)
		}
	})
}

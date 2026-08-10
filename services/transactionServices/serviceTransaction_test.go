package transactionServices

import (
	"testing"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
	"github.com/qwid-org/qwid-node/message"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
	"github.com/stretchr/testify/assert"
)

func TestGenerateTransactionMsg(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	topic := [2]byte{'T', 'T'}

	t.Run("empty transaction list", func(t *testing.T) {
		txs := []transactionsDefinition.Transaction{}
		msg, err := GenerateTransactionMsg(txs, []byte("tx"), topic)

		assert.NoError(t, err)
		assert.Equal(t, []byte("tx"), msg.GetHead())
		assert.Equal(t, common.GetChainID(), msg.GetChainID())
		assert.Empty(t, msg.TransactionsBytes[topic])
	})

	t.Run("single empty transaction", func(t *testing.T) {
		tx := transactionsDefinition.EmptyTransaction()
		txs := []transactionsDefinition.Transaction{tx}
		msg, err := GenerateTransactionMsg(txs, []byte("tx"), topic)

		assert.NoError(t, err)
		assert.Equal(t, []byte("tx"), msg.GetHead())
		assert.Len(t, msg.TransactionsBytes[topic], 1)
		assert.NotEmpty(t, msg.TransactionsBytes[topic][0])
	})

	t.Run("multiple transactions", func(t *testing.T) {
		tx1 := transactionsDefinition.EmptyTransaction()
		tx2 := transactionsDefinition.EmptyTransaction()
		tx2.GasPrice = 100
		txs := []transactionsDefinition.Transaction{tx1, tx2}
		msg, err := GenerateTransactionMsg(txs, []byte("tx"), topic)

		assert.NoError(t, err)
		assert.Len(t, msg.TransactionsBytes[topic], 2)
	})

	t.Run("different head values", func(t *testing.T) {
		tx := transactionsDefinition.EmptyTransaction()
		txs := []transactionsDefinition.Transaction{tx}

		heads := [][]byte{[]byte("tx"), []byte("bx"), []byte("st")}
		for _, head := range heads {
			msg, err := GenerateTransactionMsg(txs, head, topic)
			assert.NoError(t, err)
			assert.Equal(t, head, msg.GetHead())
		}
	})
}

func TestGenerateTransactionMsgGT(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	topic := [2]byte{'T', 'T'}

	t.Run("empty hash list", func(t *testing.T) {
		txsHashes := [][]byte{}
		msg, err := GenerateTransactionMsgGT(txsHashes, []byte("st"), topic)

		assert.NoError(t, err)
		assert.Equal(t, []byte("st"), msg.GetHead())
		assert.Equal(t, common.GetChainID(), msg.GetChainID())
		assert.Empty(t, msg.TransactionsBytes[topic])
	})

	t.Run("single hash", func(t *testing.T) {
		hash := common.EmptyHash()
		txsHashes := [][]byte{hash.GetBytes()}
		msg, err := GenerateTransactionMsgGT(txsHashes, []byte("st"), topic)

		assert.NoError(t, err)
		assert.Len(t, msg.TransactionsBytes[topic], 1)
		assert.Equal(t, hash.GetBytes(), msg.TransactionsBytes[topic][0])
	})

	t.Run("multiple hashes", func(t *testing.T) {
		hash1 := make([]byte, 32)
		hash2 := make([]byte, 32)
		hash1[0] = 1
		hash2[0] = 2
		txsHashes := [][]byte{hash1, hash2}
		msg, err := GenerateTransactionMsgGT(txsHashes, []byte("bt"), topic)

		assert.NoError(t, err)
		assert.Equal(t, []byte("bt"), msg.GetHead())
		assert.Len(t, msg.TransactionsBytes[topic], 2)
	})
}

func TestTransactionMsgSerialization(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	topic := [2]byte{'T', 'T'}

	t.Run("serialize and deserialize message", func(t *testing.T) {
		tx := transactionsDefinition.EmptyTransaction()
		txs := []transactionsDefinition.Transaction{tx}
		originalMsg, err := GenerateTransactionMsg(txs, []byte("tx"), topic)
		assert.NoError(t, err)

		// Serialize to bytes
		msgBytes := originalMsg.GetBytes()
		assert.NotEmpty(t, msgBytes)

		// Deserialize back
		newMsg := message.TransactionsMessage{}
		parsedMsg, err := newMsg.GetFromBytes(msgBytes)
		assert.NoError(t, err)
		assert.NotNil(t, parsedMsg)

		// Check head and chain ID are preserved
		assert.Equal(t, originalMsg.GetHead(), parsedMsg.GetHead())
		assert.Equal(t, originalMsg.GetChainID(), parsedMsg.GetChainID())
	})
}

func TestTransactionMsgTopics(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	topics := [][2]byte{
		{'T', 'T'}, // Transaction topic
		{'N', 'N'}, // Nonce topic
		{'S', 'S'}, // Sync topic
		{'B', 'B'}, // Block topic
	}

	tx := transactionsDefinition.EmptyTransaction()
	txs := []transactionsDefinition.Transaction{tx}

	for _, topic := range topics {
		t.Run("topic_"+string(topic[:]), func(t *testing.T) {
			msg, err := GenerateTransactionMsg(txs, []byte("tx"), topic)
			assert.NoError(t, err)
			assert.Contains(t, msg.TransactionsBytes, topic)
			assert.Len(t, msg.TransactionsBytes[topic], 1)
		})
	}
}

func TestBaseMessageFields(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	topic := [2]byte{'T', 'T'}
	tx := transactionsDefinition.EmptyTransaction()
	txs := []transactionsDefinition.Transaction{tx}

	msg, err := GenerateTransactionMsg(txs, []byte("tx"), topic)
	assert.NoError(t, err)

	// Verify BaseMessage fields
	assert.Equal(t, common.GetChainID(), msg.BaseMessage.ChainID)
	assert.Equal(t, []byte("tx"), msg.BaseMessage.Head)
}

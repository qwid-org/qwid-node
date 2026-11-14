package transactionServices

import (
	"testing"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/tcpip"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
)

// Audit 2026-11-13 (F-NET-01, second part): transaction messages are cut to a
// byte budget, so the transaction topic no longer needs a 151 MB frame cap -
// a frame a peer may keep half-sent costs that much memory per connection.
func bigTx(marker byte, optData int) transactionsDefinition.Transaction {
	sig, _ := common.GetSignatureFromBytes(make([]byte, common.SignatureLength(false)+1), common.EmptyAddress())
	tx := transactionsDefinition.Transaction{
		TxParam:   transactionsDefinition.TxParam{ChainID: common.GetChainID(), Nonce: int64(marker)},
		TxData:    transactionsDefinition.TxData{OptData: make([]byte, optData)},
		Signature: sig,
		GasPrice:  1,
	}
	_ = tx.CalcHashAndSet()
	return tx
}

func TestTransactionMessagesStayWithinTheBudget(t *testing.T) {
	var txs []transactionsDefinition.Transaction
	for i := 0; i < 400; i++ {
		txs = append(txs, bigTx(byte(i), 100_000)) // ~40 MB in all
	}
	msgs := GenerateTransactionMsgs(txs, []byte("tx"), tcpip.TransactionTopic)
	if len(msgs) < 2 {
		t.Fatalf("40 MB of transactions went out in %d message(s)", len(msgs))
	}
	n := 0
	for _, m := range msgs {
		if size := len(m.GetBytes()); size > int(tcpip.MaxMessageSizeForTopic(tcpip.TransactionTopic)) {
			t.Fatalf("a message of %d bytes exceeds the topic cap %d", size, tcpip.MaxMessageSizeForTopic(tcpip.TransactionTopic))
		}
		n += len(m.TransactionsBytes[tcpip.TransactionTopic])
	}
	if n != len(txs) {
		t.Fatalf("%d of %d transactions were sent", n, len(txs))
	}
	if len(GenerateTransactionMsgs(nil, []byte("tx"), tcpip.TransactionTopic)) != 1 {
		t.Fatal("an empty batch (the keepalive) must still be one message")
	}
}

func TestTransactionTopicCapIsBounded(t *testing.T) {
	if c := tcpip.MaxMessageSizeForTopic(tcpip.TransactionTopic); c > 17<<20 {
		t.Fatalf("the transaction topic accepts %d-byte frames", c)
	}
}

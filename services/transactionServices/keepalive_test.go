package transactionServices

import (
	"testing"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
	"github.com/qwid-org/qwid-node/message"
	"github.com/qwid-org/qwid-node/tcpip"
)

// The transaction-topic keepalive is an EMPTY "tx" message. It must round-trip
// the wire encoding, pass CheckValidMessage on the receiver (an invalid message
// triggers a ban), and carry zero transactions so the handler treats it as a
// no-op.
func TestKeepaliveMessageIsValidAndEmpty(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	ka, err := GenerateTransactionMsg(nil, []byte("tx"), tcpip.TransactionTopic)
	if err != nil {
		t.Fatalf("GenerateTransactionMsg: %v", err)
	}
	isValid, amsg := message.CheckValidMessage(ka.GetBytes())
	if !isValid {
		t.Fatal("keepalive message failed CheckValidMessage - receivers would ban the sender")
	}
	txn, err := amsg.(message.TransactionsMessage).GetTransactionsFromBytes(
		common.SigName(), common.SigName2(), common.IsPaused(), common.IsPaused2())
	if err != nil {
		t.Fatalf("GetTransactionsFromBytes: %v", err)
	}
	total := 0
	for _, v := range txn {
		total += len(v)
	}
	if total != 0 {
		t.Fatalf("keepalive must carry zero transactions, got %d", total)
	}
}

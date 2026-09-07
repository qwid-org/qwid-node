package transactionServices

import (
	"bytes"
	"testing"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/message"
	"github.com/qwid-org/qwid-node/tcpip"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
)

func TestQWID02ProductionBatchCompatibility(t *testing.T) {
	for _, tc := range []struct {
		head  string
		count int
	}{{"tx", int(common.MaxTransactionsPerBlock)}, {"bx", common.MaxNumberTransactionInChunk}} {
		t.Run(tc.head, func(t *testing.T) {
			txs := make([]transactionsDefinition.Transaction, tc.count)
			for i := range txs {
				txs[i] = transactionsDefinition.EmptyTransaction()
				txs[i].TxParam.Nonce = int64(i)
			}
			original, err := GenerateTransactionMsg(txs, []byte(tc.head), tcpip.TransactionTopic)
			if err != nil {
				t.Fatal(err)
			}
			ok, decoded := message.CheckValidMessage(original.GetBytes())
			if !ok {
				t.Fatal("production batch rejected")
			}
			got := decoded.GetTransactionsBytes()[tcpip.TransactionTopic]
			if len(got) != tc.count {
				t.Fatalf("got %d items, want %d", len(got), tc.count)
			}
			for i := range got {
				if !bytes.Equal(got[i], txs[i].GetBytes()) {
					t.Fatalf("transaction %d changed", i)
				}
			}
		})
	}
	for _, tc := range []struct {
		head  string
		count int
	}{{"st", int(common.MaxTransactionsPerBlock)}, {"bt", common.MaxNumberTransactionInChunk}} {
		t.Run(tc.head, func(t *testing.T) {
			hashes := make([][]byte, tc.count)
			for i := range hashes {
				hashes[i] = bytes.Repeat([]byte{byte(i)}, common.HashLength)
			}
			original, err := GenerateTransactionMsgGT(hashes, []byte(tc.head), tcpip.TransactionTopic)
			if err != nil {
				t.Fatal(err)
			}
			ok, decoded := message.CheckValidMessage(original.GetBytes())
			if !ok || len(decoded.GetTransactionsBytes()[tcpip.TransactionTopic]) != tc.count {
				t.Fatal("production missing-transaction request rejected or truncated")
			}
		})
	}
}

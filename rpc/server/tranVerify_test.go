package serverrpc

import (
	"strings"
	"testing"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
	"github.com/qwid-org/qwid-node/services/transactionServices"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
)

// GetTransactionsFromBytes drops every transaction it cannot verify and
// returns the rest without an error, so handleTRAN used to answer
// "transaction sent" for a submission it had silently discarded - the wallet
// reported success for a transfer that never existed (found in the recovery
// commitment harness: a transfer refused by the dual-key rule).
func TestTRANReportsTransactionsThatFailVerification(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	initTestAccountsRPC()

	tx := transactionsDefinition.Transaction{
		TxParam: transactionsDefinition.TxParam{ChainID: common.GetChainID(), Sender: rpcAddress(7), SendingTime: 1, Nonce: 1},
		TxData:  transactionsDefinition.TxData{Recipient: rpcAddress(8), Amount: 1},
		Height:  1, GasPrice: 1, GasUsage: 100000,
	}
	if err := tx.CalcHashAndSet(); err != nil {
		t.Fatal(err)
	}
	msg, err := transactionServices.GenerateTransactionMsg([]transactionsDefinition.Transaction{tx}, []byte("tx"), [2]byte{'T', 'T'})
	if err != nil {
		t.Fatal(err)
	}
	var reply []byte
	handleTRAN(msg.GetBytes(), &reply)
	if !strings.HasPrefix(string(reply), "transaction rejected") {
		t.Fatalf("an unverifiable submission was answered %q", reply)
	}
}

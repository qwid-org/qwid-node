package serverrpc

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
	"github.com/qwid-org/qwid-node/transactionsPool"
)

// Three operations used to mean "the wallet this node mines with", implicitly:
// CNCL checked ownership against it, CHCK reported ITS key registration, and
// PEND returned every pool in full. A webui unlocked with any other wallet
// therefore could not cancel its own transaction, was told about somebody
// else's missing keys, and saw a pending list it could not attribute.
//
// Each now carries the address it is about, and answers for that account. The
// older payload shapes still work and still mean the node's own wallet, so a
// wallet built before this change keeps working.

func txFrom(sender common.Address, marker byte) transactionsDefinition.Transaction {
	tx := transactionsDefinition.Transaction{
		TxParam: transactionsDefinition.TxParam{Sender: sender},
		TxData:  transactionsDefinition.TxData{Recipient: common.EmptyAddress()},
	}
	b := make([]byte, common.HashLength)
	b[common.HashLength-1] = marker
	tx.Hash.Set(b)
	return tx
}

// withEmptyPools gives a test its own pools; the package-level ones are shared
// singletons and would otherwise leak transactions between tests.
func withEmptyPools(t *testing.T) {
	t.Helper()
	savedTx, savedEscrow, savedMulti := transactionsPool.PoolsTx, transactionsPool.PoolTxEscrow, transactionsPool.PoolTxMultiSign
	transactionsPool.PoolsTx = transactionsPool.NewTransactionPool(common.MaxTransactionInPool, 0)
	transactionsPool.PoolTxEscrow = transactionsPool.NewTransactionPool(common.MaxTransactionInPool, 1)
	transactionsPool.PoolTxMultiSign = transactionsPool.NewTransactionPool(common.MaxTransactionInPool, 2)
	t.Cleanup(func() {
		transactionsPool.PoolsTx, transactionsPool.PoolTxEscrow, transactionsPool.PoolTxMultiSign = savedTx, savedEscrow, savedMulti
	})
}

func TestCancelPayloadNamesTheCallersAccount(t *testing.T) {
	payload := append(addressBytesEndingIn(7), make([]byte, common.HashLength)...)

	addr, named := requestAccountAddress("CNCL", payload)

	if !named {
		t.Fatal("a cancellation carrying an address was treated as anonymous")
	}
	if addr.ByteValue[common.AddressLength-1] != 7 {
		t.Fatalf("read the wrong address: %x", addr.ByteValue)
	}
}

// The older form is a bare 32-byte hash. Reading its first 20 bytes as an
// address would authenticate the request against whatever account those bytes
// happen to name.
func TestBareHashCancelNamesNoAccount(t *testing.T) {
	if _, named := requestAccountAddress("CNCL", make([]byte, common.HashLength)); named {
		t.Fatal("a bare transaction hash was read as an address")
	}
}

func TestPendingAndCheckPayloadsNameTheCallersAccount(t *testing.T) {
	cases := []struct {
		operation string
		payload   []byte
		named     bool
	}{
		{"PEND", addressBytesEndingIn(8), true},
		{"PEND", nil, false},
		{"CHCK", append(addressBytesEndingIn(9), addressBytesEndingIn(10)...), true},
		{"CHCK", nil, false},
	}
	for _, c := range cases {
		addr, named := requestAccountAddress(c.operation, c.payload)
		if named != c.named {
			t.Errorf("%s with a %d-byte payload: named=%v, want %v", c.operation, len(c.payload), named, c.named)
			continue
		}
		if named && addr.ByteValue[common.AddressLength-1] != c.payload[common.AddressLength-1] {
			t.Errorf("%s read the wrong address: %x", c.operation, addr.ByteValue)
		}
	}
}

func TestCancelActsForTheAccountInTheRequest(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	withEmptyPools(t)

	owner := addressEndingIn(21)
	tx := txFrom(owner, 1)
	transactionsPool.PoolsTx.AddTransaction(tx, tx.Hash)

	reply := []byte{}
	handleCNCL(append(owner.GetBytes(), tx.Hash.GetBytes()...), &reply)

	if !strings.Contains(string(reply), "cancelled") {
		t.Fatalf("the owner could not cancel its own transaction: %q", reply)
	}
	if transactionsPool.PoolsTx.TransactionExists(tx.Hash.GetBytes()) {
		t.Error("the transaction is still in the pool")
	}
}

// Naming an address must not become a way to cancel somebody else's
// transaction: the pooled sender still has to match, and a refused
// cancellation must put the transaction back.
func TestCancelRefusesAnotherAccountsTransaction(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	withEmptyPools(t)

	owner, stranger := addressEndingIn(21), addressEndingIn(22)
	tx := txFrom(owner, 2)
	transactionsPool.PoolsTx.AddTransaction(tx, tx.Hash)

	reply := []byte{}
	handleCNCL(append(stranger.GetBytes(), tx.Hash.GetBytes()...), &reply)

	if !strings.Contains(string(reply), "not the owner") {
		t.Fatalf("a stranger's cancellation was not refused: %q", reply)
	}
	if !transactionsPool.PoolsTx.TransactionExists(tx.Hash.GetBytes()) {
		t.Error("a refused cancellation dropped the transaction from the pool")
	}
}

// GetActiveWallet returns nil until a wallet is loaded. The old handler
// dereferenced it unconditionally, so a cancellation arriving first would panic
// inside the RPC server rather than answer.
func TestBareHashCancelWithoutAWalletDoesNotPanic(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	withEmptyPools(t)

	tx := txFrom(addressEndingIn(21), 3)
	transactionsPool.PoolsTx.AddTransaction(tx, tx.Hash)

	reply := []byte{}
	handleCNCL(tx.Hash.GetBytes(), &reply)

	if len(reply) == 0 {
		t.Fatal("the handler answered nothing")
	}
}

func pendingSenders(t *testing.T, reply []byte) []string {
	t.Helper()
	var txs []struct {
		Sender string `json:"sender"`
	}
	if err := json.Unmarshal(reply, &txs); err != nil {
		t.Fatalf("PEND did not answer JSON: %v (%q)", err, reply)
	}
	out := make([]string, 0, len(txs))
	for _, tx := range txs {
		out = append(out, tx.Sender)
	}
	return out
}

func TestPendingIsNarrowedToTheAccountInTheRequest(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	withEmptyPools(t)

	mine, theirs := addressEndingIn(31), addressEndingIn(32)
	mineTx, theirsTx := txFrom(mine, 4), txFrom(theirs, 5)
	transactionsPool.PoolsTx.AddTransaction(mineTx, mineTx.Hash)
	transactionsPool.PoolsTx.AddTransaction(theirsTx, theirsTx.Hash)

	reply := []byte{}
	handlePEND(mine.GetBytes(), &reply)

	senders := pendingSenders(t, reply)
	if len(senders) != 1 || senders[0] != mine.GetHex() {
		t.Fatalf("PEND returned %v, want only %s", senders, mine.GetHex())
	}
}

// A transaction addressed TO the account is equally the account's business:
// the wallet shows incoming pending transfers, not just outgoing ones.
func TestPendingIncludesIncomingTransactions(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	withEmptyPools(t)

	mine, theirs := addressEndingIn(31), addressEndingIn(32)
	incoming := txFrom(theirs, 6)
	incoming.TxData.Recipient = mine
	transactionsPool.PoolsTx.AddTransaction(incoming, incoming.Hash)

	reply := []byte{}
	handlePEND(mine.GetBytes(), &reply)

	if senders := pendingSenders(t, reply); len(senders) != 1 {
		t.Fatalf("an incoming pending transfer was hidden: %v", senders)
	}
}

// Wallets built before this change send a bare PEND. They must keep seeing the
// pools rather than an empty list.
func TestBarePendingStillReturnsEverything(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	withEmptyPools(t)

	a, b := txFrom(addressEndingIn(31), 7), txFrom(addressEndingIn(32), 8)
	transactionsPool.PoolsTx.AddTransaction(a, a.Hash)
	transactionsPool.PoolsTx.AddTransaction(b, b.Hash)

	reply := []byte{}
	handlePEND(nil, &reply)

	if senders := pendingSenders(t, reply); len(senders) != 2 {
		t.Fatalf("a bare PEND returned %v, want both transactions", senders)
	}
}

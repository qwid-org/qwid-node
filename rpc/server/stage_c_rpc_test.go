package serverrpc

import (
	"strings"
	"testing"

	"github.com/qwid-org/qwid-node/logger"
	"github.com/qwid-org/qwid-node/transactionsPool"
)

// S7-06: the multisig pool decides settlement in ProcessTransactionsMultiSign,
// so removing a transaction from it on one node makes that node settle
// differently from the network. CNCL refuses.
func TestCancelLeavesMultisigPoolToConsensus(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	withEmptyPools(t)

	owner := addressEndingIn(31)
	tx := txFrom(owner, 7)
	transactionsPool.PoolTxMultiSign.AddTransaction(tx, tx.Hash)

	reply := []byte{}
	handleCNCL(append(owner.GetBytes(), tx.Hash.GetBytes()...), &reply)

	if !strings.Contains(string(reply), "cannot be cancelled locally") {
		t.Fatalf("reply = %q", reply)
	}
	if !transactionsPool.PoolTxMultiSign.TransactionExists(tx.Hash.GetBytes()) {
		t.Fatal("a multisig transaction was removed from this node's pool only")
	}
}

// S7-06: a second MINE used to start the nonce listeners again, and the second
// Listen on a bound port panicked the node.
func TestMiningStartsOnlyOnce(t *testing.T) {
	miningStarted.Store(false)
	defer miningStarted.Store(false)
	runs := 0
	if !startMiningOnce(func() { runs++ }) {
		t.Fatal("first start refused")
	}
	if startMiningOnce(func() { runs++ }) {
		t.Fatal("second start accepted")
	}
	if runs != 1 {
		t.Fatalf("mining start ran %d times", runs)
	}
}

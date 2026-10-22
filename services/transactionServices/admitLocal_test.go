package transactionServices

import (
	"strings"
	"testing"

	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
	"github.com/qwid-org/qwid-node/transactionsPool"
)

// A locally submitted transaction used to be admitted to the pool only after
// RPC TRAN had answered "transaction sent": a wallet whose sender could not
// pay was told the transfer was on its way while the pool dropped it a moment
// later (found in the recovery-commitment harness). AdmitLocalTransactions
// runs the same admission rules synchronously, so TRAN can answer with them.

func admitTx(sender, recipient common.Address, amount, height, nonce int64) transactionsDefinition.Transaction {
	tx := transactionsDefinition.Transaction{
		TxParam: transactionsDefinition.TxParam{ChainID: common.GetChainID(), Sender: sender, SendingTime: 1, Nonce: nonce},
		TxData:  transactionsDefinition.TxData{Recipient: recipient, Amount: amount},
		Height:  height, GasPrice: 1, GasUsage: 100000,
	}
	_ = tx.CalcHashAndSet()
	return tx
}

func admitAddr(marker byte) common.Address {
	a := common.Address{}
	a.ByteValue[common.AddressLength-1] = marker
	return a
}

func withAdmissionState(t *testing.T, balances map[common.Address]int64) {
	t.Helper()
	logger.InitLogger()
	withBxTestDB(t)
	all := map[[common.AddressLength]byte]account.Account{}
	for a, b := range balances {
		all[a.ByteValue] = account.Account{Address: a.ByteValue, Balance: b}
	}
	account.AccountsRWMutex.Lock()
	account.Accounts = account.AccountsType{AllAccounts: all}
	account.AccountsRWMutex.Unlock()
	saved := transactionsPool.PoolsTx
	transactionsPool.PoolsTx = transactionsPool.NewTransactionPool(common.MaxTransactionInPool, 0)
	t.Cleanup(func() { transactionsPool.PoolsTx = saved })
}

func TestAdmitLocalReportsInsufficientFunds(t *testing.T) {
	poor := admitAddr(1)
	withAdmissionState(t, map[common.Address]int64{poor: 0})
	err := AdmitLocalTransactions([]transactionsDefinition.Transaction{admitTx(poor, admitAddr(2), 5, common.GetHeight(), 1)})
	if err == nil || !strings.Contains(err.Error(), "insufficient funds") {
		t.Fatalf("an unpayable submission was answered %v", err)
	}
}

func TestAdmitLocalReportsHeightOutsideWindow(t *testing.T) {
	rich := admitAddr(3)
	withAdmissionState(t, map[common.Address]int64{rich: 1_000_000_000})
	err := AdmitLocalTransactions([]transactionsDefinition.Transaction{admitTx(rich, admitAddr(2), 5, common.GetHeight()+50, 1)})
	if err == nil || !strings.Contains(err.Error(), "height") {
		t.Fatalf("a transaction from the future was answered %v", err)
	}
}

func TestAdmitLocalReportsTransferBelowMinimumStake(t *testing.T) {
	rich := admitAddr(4)
	withAdmissionState(t, map[common.Address]int64{rich: 1_000_000_000_000})
	tx := admitTx(rich, common.GetDelegatedAccountAddress(1), common.MinStakingUser-1, common.GetHeight(), 1)
	if err := AdmitLocalTransactions([]transactionsDefinition.Transaction{tx}); err == nil || !strings.Contains(err.Error(), "minimum") {
		t.Fatalf("a stake below the minimum was answered %v", err)
	}
}

func TestAdmitLocalAcceptsAndIsIdempotent(t *testing.T) {
	rich := admitAddr(5)
	withAdmissionState(t, map[common.Address]int64{rich: 1_000_000_000})
	tx := admitTx(rich, admitAddr(2), 5, common.GetHeight(), 1)
	if err := AdmitLocalTransactions([]transactionsDefinition.Transaction{tx}); err != nil {
		t.Fatalf("a payable transaction was refused: %v", err)
	}
	if !transactionsPool.PoolsTx.TransactionExists(tx.Hash.GetBytes()) {
		t.Fatal("an admitted transaction is not in the pool")
	}
	if err := AdmitLocalTransactions([]transactionsDefinition.Transaction{tx}); err != nil {
		t.Fatalf("resubmitting a pooled transaction was refused: %v", err)
	}
}

func TestAdmitLocalReportsFullPool(t *testing.T) {
	rich := admitAddr(6)
	withAdmissionState(t, map[common.Address]int64{rich: 1_000_000_000})
	pooled := admitTx(rich, admitAddr(7), 1, common.GetHeight(), 100)
	transactionsPool.PoolsTx.AddTransaction(pooled, pooled.Hash)
	saved := common.MaxTransactionInPool
	common.MaxTransactionInPool = 0
	t.Cleanup(func() { common.MaxTransactionInPool = saved })
	if err := AdmitLocalTransactions([]transactionsDefinition.Transaction{admitTx(rich, admitAddr(2), 5, common.GetHeight(), 1)}); err == nil || !strings.Contains(err.Error(), "full") {
		t.Fatalf("a submission to a full pool was answered %v", err)
	}
}

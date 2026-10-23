package serverrpc

import (
	"errors"
	"strings"
	"testing"

	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/blocks"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
)

// handleTRAN answered "transaction sent" before looking at the transaction and
// then handed it to the network unconditionally. A submission that the chain
// will refuse — a contract deployment from an escrow or multi-signature
// account, which cannot execute — was therefore reported to the wallet as
// accepted, and the user's only evidence of failure was that it never
// confirmed.
//
// The decoded transactions are checked before the reply so the wallet gets the
// reason instead of silence.

func initTestAccountsRPC() {
	account.AccountsRWMutex.Lock()
	account.Accounts.AllAccounts = make(map[[common.AddressLength]byte]account.Account)
	account.AccountsRWMutex.Unlock()
}

func rpcAddress(marker byte) common.Address {
	a := common.Address{}
	a.ByteValue[common.AddressLength-1] = marker
	return a
}

func deployment(sender common.Address) transactionsDefinition.Transaction {
	return transactionsDefinition.Transaction{
		TxParam: transactionsDefinition.TxParam{Sender: sender},
		TxData: transactionsDefinition.TxData{
			Recipient: common.EmptyAddress(),
			OptData:   []byte{0x60, 0x80, 0x60, 0x40, 0x52},
		},
	}
}

func TestSubmissionFromEscrowAccountIsRefused(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	initTestAccountsRPC()

	sender := rpcAddress(1)
	account.Accounts.AllAccounts[sender.ByteValue] = account.Account{
		Address: sender.ByteValue, Balance: 1_000, TransactionDelay: 20,
	}

	err := rejectUnacceptableTransactions([]transactionsDefinition.Transaction{deployment(sender)})
	if err == nil {
		t.Fatal("a deployment from an escrow account was accepted for submission")
	}
	if !errors.Is(err, blocks.ErrDeployFromRestrictedAccount) {
		t.Fatalf("error does not identify the cause: %v", err)
	}
}

func TestSubmissionFromMultiSignAccountIsRefused(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	initTestAccountsRPC()

	sender := rpcAddress(2)
	account.Accounts.AllAccounts[sender.ByteValue] = account.Account{
		Address: sender.ByteValue, Balance: 1_000, MultiSignNumber: 2,
	}

	if err := rejectUnacceptableTransactions([]transactionsDefinition.Transaction{deployment(sender)}); err == nil {
		t.Fatal("a deployment from a multi-signature account was accepted for submission")
	}
}

func TestOrdinarySubmissionsAreAccepted(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	initTestAccountsRPC()

	sender := rpcAddress(3)
	account.Accounts.AllAccounts[sender.ByteValue] = account.Account{
		Address: sender.ByteValue, Balance: 1_000,
	}

	transfer := transactionsDefinition.Transaction{
		TxParam: transactionsDefinition.TxParam{Sender: sender},
		TxData:  transactionsDefinition.TxData{Recipient: rpcAddress(4), Amount: 10},
	}

	txs := []transactionsDefinition.Transaction{deployment(sender), transfer}
	if err := rejectUnacceptableTransactions(txs); err != nil {
		t.Fatalf("valid submissions were refused: %v", err)
	}
}

// One bad transaction in a batch must refuse the batch: the whole payload is
// broadcast or not, so accepting part of it is not an option the caller has.
func TestOneBadTransactionRefusesTheWholeBatch(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	initTestAccountsRPC()

	good := rpcAddress(5)
	bad := rpcAddress(6)
	account.Accounts.AllAccounts[good.ByteValue] = account.Account{
		Address: good.ByteValue, Balance: 1_000,
	}
	account.Accounts.AllAccounts[bad.ByteValue] = account.Account{
		Address: bad.ByteValue, Balance: 1_000, TransactionDelay: 20,
	}

	txs := []transactionsDefinition.Transaction{deployment(good), deployment(bad)}
	if err := rejectUnacceptableTransactions(txs); err == nil {
		t.Fatal("a batch containing an unacceptable deployment was accepted")
	}
}

// The message the wallet displays has to name the problem; "failed" would leave
// the user exactly where they were.
func TestRefusalMessageNamesTheReason(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	initTestAccountsRPC()

	sender := rpcAddress(7)
	account.Accounts.AllAccounts[sender.ByteValue] = account.Account{
		Address: sender.ByteValue, Balance: 1_000, TransactionDelay: 20,
	}

	err := rejectUnacceptableTransactions([]transactionsDefinition.Transaction{deployment(sender)})
	if err == nil {
		t.Fatal("expected a refusal")
	}
	msg := strings.ToLower(err.Error())
	if !strings.Contains(msg, "escrow") || !strings.Contains(msg, "deploy") {
		t.Fatalf("refusal does not explain itself: %q", err.Error())
	}
}

func TestEmptyBatchIsAccepted(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	initTestAccountsRPC()

	if err := rejectUnacceptableTransactions(nil); err != nil {
		t.Fatalf("an empty batch was refused: %v", err)
	}
}

// An operational stake into a delegated account this node does not run took
// that account away from the node producing for it (2026-10-23: a stake from
// node 2 into account 1 halted node 1).
func TestOperatorIntentOnlyForThisNodesDelegatedAccount(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	mine := common.GetDelegatedAccountAddress(2)
	stake := func(da int16, amount int64, opt []byte, locked int64) transactionsDefinition.Transaction {
		return transactionsDefinition.Transaction{TxData: transactionsDefinition.TxData{
			Recipient: common.GetDelegatedAccountAddress(da), Amount: amount, OptData: opt, LockedAmount: locked}}
	}
	cases := []struct {
		name string
		tx   transactionsDefinition.Transaction
		ok   bool
	}{
		{"operator stake into another account", stake(1, 1000, []byte{1}, 0), false},
		{"operator stake into this node's account", stake(2, 1000, []byte{1}, 0), true},
		{"plain stake into another account", stake(1, 1000, nil, 0), true},
		{"unstake with the flag", stake(1, -1000, []byte{1}, 0), true},
		{"locked stake cannot make an operator", stake(1, 1000, []byte{1}, 500), true},
		{"withdraw account", stake(1+256, 1000, []byte{1}, 0), true},
		{"ordinary transfer with data", transactionsDefinition.Transaction{TxData: transactionsDefinition.TxData{
			Recipient: rpcAddress(9), Amount: 1000, OptData: []byte{1}}}, true},
	}
	for _, c := range cases {
		err := checkOperatorIntent(c.tx, mine)
		if (err == nil) != c.ok {
			t.Errorf("%s: err=%v, want ok=%v", c.name, err, c.ok)
		}
	}
	if err := checkOperatorIntent(stake(1, 1000, []byte{1}, 0), common.Address{}); err == nil ||
		!strings.Contains(err.Error(), "runs delegated account none") {
		t.Errorf("a node without DELEGATED_ACCOUNT accepted an operator stake: %v", err)
	}
}

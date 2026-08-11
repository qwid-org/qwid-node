package blocks

import (
	"testing"

	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
	"github.com/qwid-org/qwid-node/transactionsPool"
)

// EvaluateSCForBlock skips contract execution when the sender is an escrow or
// multi-signature account (two TODOs in evaluate.go). The transaction was still
// validated, included in a block and charged for, and then did nothing: no
// contract, no address, no logs, no error. The only trace was a zero contract
// address on a confirmed transaction, which is unreadable as a diagnosis —
// observed at height 145530.
//
// Since the execution cannot happen, the transaction must not be accepted at
// all. Neither conversion can be undone (ModifyAccountToEscrow and
// ModifyAccountToMultiSign both refuse to convert back), so such a deployment
// can never become valid and is safe to drop permanently.

func deployTx(t *testing.T, sender common.Address, marker byte) transactionsDefinition.Transaction {
	t.Helper()
	sigBytes := make([]byte, common.SignatureLength(false)+1)
	sig, _ := common.GetSignatureFromBytes(sigBytes, common.EmptyAddress())
	tx := transactionsDefinition.Transaction{
		TxParam: transactionsDefinition.TxParam{
			ChainID:     common.GetChainID(),
			Sender:      sender,
			SendingTime: int64(marker),
			Nonce:       int64(marker),
		},
		TxData: transactionsDefinition.TxData{
			Recipient: common.EmptyAddress(), // deployment: no recipient
			Amount:    0,
			OptData:   []byte{0x60, 0x80, 0x60, 0x40, 0x52}, // contract bytecode
		},
		Height:    100,
		GasPrice:  1,
		GasUsage:  1,
		Signature: sig,
	}
	if err := tx.CalcHashAndSet(); err != nil {
		t.Fatalf("CalcHashAndSet: %v", err)
	}
	return tx
}

func TestDeploymentFromEscrowAccountIsRejected(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	initTestAccounts()

	sender := testAddress(40)
	account.Accounts.AllAccounts[sender.ByteValue] = account.Account{
		Address: sender.ByteValue, Balance: 1_000_000, TransactionDelay: 20,
	}

	if err := ValidateContractDeployment(deployTx(t, sender, 40)); err == nil {
		t.Fatal("a deployment from an escrow account was accepted; it cannot execute")
	}
}

func TestDeploymentFromMultiSignAccountIsRejected(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	initTestAccounts()

	sender := testAddress(41)
	account.Accounts.AllAccounts[sender.ByteValue] = account.Account{
		Address: sender.ByteValue, Balance: 1_000_000, MultiSignNumber: 2,
	}

	if err := ValidateContractDeployment(deployTx(t, sender, 41)); err == nil {
		t.Fatal("a deployment from a multi-signature account was accepted")
	}
}

func TestDeploymentFromOrdinaryAccountIsAllowed(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	initTestAccounts()

	sender := testAddress(42)
	account.Accounts.AllAccounts[sender.ByteValue] = account.Account{
		Address: sender.ByteValue, Balance: 1_000_000,
	}

	if err := ValidateContractDeployment(deployTx(t, sender, 42)); err != nil {
		t.Fatalf("an ordinary account was refused a deployment: %v", err)
	}
}

// Only deployments are restricted. An escrow account must still be able to send
// coin and to call an existing contract — the restriction exists because
// EvaluateSCForBlock skips execution, not to freeze the account.
func TestNonDeploymentsFromEscrowAreUntouched(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	initTestAccounts()

	sender := testAddress(43)
	account.Accounts.AllAccounts[sender.ByteValue] = account.Account{
		Address: sender.ByteValue, Balance: 1_000_000, TransactionDelay: 20,
	}

	plain := deployTx(t, sender, 43)
	plain.TxData.OptData = nil
	plain.TxData.Recipient = testAddress(44)
	if err := ValidateContractDeployment(plain); err != nil {
		t.Errorf("a plain transfer from an escrow account was refused: %v", err)
	}

	call := deployTx(t, sender, 45)
	call.TxData.Recipient = testAddress(46) // calling an existing contract
	if err := ValidateContractDeployment(call); err != nil {
		t.Errorf("a contract call from an escrow account was refused: %v", err)
	}
}

// An unknown sender is not this rule's business; the balance checks elsewhere
// deal with it. Refusing here would turn a missing account into a deployment
// error and hide the real cause.
func TestUnknownSenderIsNotRejectedByThisRule(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	initTestAccounts()

	if err := ValidateContractDeployment(deployTx(t, testAddress(47), 47)); err != nil {
		t.Fatalf("an unknown sender was refused by the deployment rule: %v", err)
	}
}

// Making it a validation rule without also keeping it out of block assembly
// would repeat the escrow-cancellation stall: the producer would fail
// CheckBlockTransfers on every attempt while the transaction sat in the pool,
// and stop producing blocks entirely.
func TestUnbuildableDeploymentIsDroppedFromThePool(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	initTestAccounts()
	transactionsPool.PoolsTx = transactionsPool.NewTransactionPool(common.MaxTransactionInPool, 0)
	transactionsPool.PoolTxEscrow = transactionsPool.NewTransactionPool(common.MaxTransactionInPool, 1)

	sender := testAddress(48)
	account.Accounts.AllAccounts[sender.ByteValue] = account.Account{
		Address: sender.ByteValue, Balance: 1_000_000, TransactionDelay: 20,
	}
	tx := deployTx(t, sender, 48)
	if !transactionsPool.PoolsTx.AddTransaction(tx, tx.Hash) {
		t.Fatal("could not pool the transaction")
	}

	kept := FilterUnbuildableTransactions([]transactionsDefinition.Transaction{tx}, 120)

	if len(kept) != 0 {
		t.Fatalf("an unexecutable deployment was still offered to the block: %d", len(kept))
	}
	// The account conversion is one-way, so this can never become valid.
	if transactionsPool.PoolsTx.HasTransaction(tx.Hash.GetBytes()) {
		t.Error("a permanently unexecutable deployment was left in the pool")
	}
}

func TestOrdinaryDeploymentSurvivesAssemblyFiltering(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	initTestAccounts()
	transactionsPool.PoolsTx = transactionsPool.NewTransactionPool(common.MaxTransactionInPool, 0)
	transactionsPool.PoolTxEscrow = transactionsPool.NewTransactionPool(common.MaxTransactionInPool, 1)

	sender := testAddress(49)
	account.Accounts.AllAccounts[sender.ByteValue] = account.Account{
		Address: sender.ByteValue, Balance: 1_000_000,
	}
	tx := deployTx(t, sender, 49)
	if !transactionsPool.PoolsTx.AddTransaction(tx, tx.Hash) {
		t.Fatal("could not pool the transaction")
	}

	kept := FilterUnbuildableTransactions([]transactionsDefinition.Transaction{tx}, 120)

	if len(kept) != 1 {
		t.Fatalf("a valid deployment was dropped from the block: %d", len(kept))
	}
	if !transactionsPool.PoolsTx.HasTransaction(tx.Hash.GetBytes()) {
		t.Error("a valid deployment was evicted from the pool")
	}
}

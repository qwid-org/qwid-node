package blocks

import (
	"path/filepath"
	"testing"

	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/database"
	"github.com/qwid-org/qwid-node/logger"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
	"github.com/qwid-org/qwid-node/transactionsPool"
)

// End-to-end timing of balance movement for the two deferred transaction
// kinds. "Confirmed" and "paid" are different events here, and conflating them
// is what made the wallet report an unsettled escrow transfer as done:
//
//	escrow    inclusion in a block charges the FEE only; the amount moves at
//	          tx.Height + account.TransactionDelay, in ProcessTransactionsEscrow.
//	multisig  inclusion charges the FEE only; the amount moves when the
//	          threshold of valid approvals is reached, in
//	          ProcessTransactionsMultiSign.
//
// A plain transfer is included for contrast: there, both happen at once.

func withBalanceTestDB(t *testing.T) {
	t.Helper()
	db := &database.BlockchainDB{}
	pdb, err := db.InitPermanent(filepath.Join(t.TempDir(), "blockchain"))
	if err != nil {
		t.Skipf("RocksDB unavailable: %v", err)
	}
	saved := database.MainDB
	database.MainDB = pdb
	t.Cleanup(func() {
		pdb.Close()
		database.MainDB = saved
	})
}

// testAddress returns an address that is NOT a delegated account. A delegated
// address is two big-endian id bytes followed by zeros, so an address whose
// only non-zero byte sits at the front would be routed down the staking path
// instead of the standard transfer path.
func testAddress(marker byte) common.Address {
	a := common.Address{}
	a.ByteValue[common.AddressLength-1] = marker
	return a
}

func balanceOf(t *testing.T, a common.Address) int64 {
	t.Helper()
	acc, ok := account.GetAccountByAddressBytes(a.GetBytes())
	if !ok {
		return 0
	}
	return acc.Balance
}

func transferTx(t *testing.T, sender, recipient common.Address, amount int64, multiSignTx common.Hash, marker byte) transactionsDefinition.Transaction {
	t.Helper()
	sigBytes := make([]byte, common.SignatureLength(false)+1)
	sig, _ := common.GetSignatureFromBytes(sigBytes, common.EmptyAddress())
	tx := transactionsDefinition.Transaction{
		TxParam: transactionsDefinition.TxParam{
			ChainID:     common.GetChainID(),
			Sender:      sender,
			SendingTime: int64(marker),
			Nonce:       int64(marker),
			MultiSignTx: multiSignTx,
		},
		TxData: transactionsDefinition.TxData{
			Recipient: recipient,
			Amount:    amount,
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

func feeOf(t *testing.T, tx transactionsDefinition.Transaction) int64 {
	t.Helper()
	fee, err := tx.CalcFee()
	if err != nil {
		t.Fatalf("CalcFee: %v", err)
	}
	return fee
}

func TestPlainTransferMovesBalanceImmediately(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	withBalanceTestDB(t)
	initTestAccounts()

	sender, recipient := testAddress(1), testAddress(2)
	const start, amount = int64(1_000_000_000), int64(100_000_000)
	account.Accounts.AllAccounts[sender.ByteValue] = account.Account{
		Address: sender.ByteValue, Balance: start,
	}

	tx := transferTx(t, sender, recipient, amount, common.EmptyHash(), 1)
	fee := feeOf(t, tx)

	if err := ProcessTransaction(tx, 100, 1000); err != nil {
		t.Fatalf("ProcessTransaction: %v", err)
	}

	if got := balanceOf(t, sender); got != start-amount-fee {
		t.Errorf("sender = %d, want %d (amount and fee taken at once)", got, start-amount-fee)
	}
	if got := balanceOf(t, recipient); got != amount {
		t.Errorf("recipient = %d, want %d", got, amount)
	}
}

func TestEscrowChargesFeeAtInclusionAndAmountAtSettlement(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	withBalanceTestDB(t)
	initTestAccounts()
	transactionsPool.PoolTxEscrow = transactionsPool.NewTransactionPool(common.MaxTransactionInPool, 1)

	sender, recipient := testAddress(3), testAddress(4)
	const start, amount, delay = int64(1_000_000_000), int64(100_000_000), int64(20)
	account.Accounts.AllAccounts[sender.ByteValue] = account.Account{
		Address: sender.ByteValue, Balance: start, TransactionDelay: delay,
	}

	tx := transferTx(t, sender, recipient, amount, common.EmptyHash(), 3)
	fee := feeOf(t, tx)

	// --- inclusion in the block at height 100 -------------------------------
	if err := ProcessTransaction(tx, 100, 1000); err != nil {
		t.Fatalf("ProcessTransaction: %v", err)
	}
	if got := balanceOf(t, sender); got != start-fee {
		t.Fatalf("after inclusion sender = %d, want %d — only the fee may be "+
			"taken; the amount must wait for settlement", got, start-fee)
	}
	if got := balanceOf(t, recipient); got != 0 {
		t.Fatalf("after inclusion recipient = %d, want 0 — the transfer is "+
			"confirmed but not settled", got)
	}

	// --- one block before maturity -----------------------------------------
	//
	// The return value is deliberately ignored. An immature transaction makes
	// ProcessTransactionsEscrow return "transaction should not be executed"
	// rather than skipping it and carrying on with the batch — the AC-M7 fix
	// four lines above it in the source changed exactly that for the
	// delegated-account branch but left this one. ProcessBlockTransfers only
	// logs the error, so it is not fatal, and asserting on it here would
	// freeze a shape that should probably become a `continue`. What must hold
	// either way is that no money moved.
	maturity := int64(100) + delay
	_ = ProcessTransactionsEscrow(maturity-1, nil)
	if got := balanceOf(t, recipient); got != 0 {
		t.Fatalf("recipient = %d at height %d, want 0 — settled one block early",
			got, maturity-1)
	}
	if got := balanceOf(t, sender); got != start-fee {
		t.Fatalf("sender = %d at height %d, want %d — nothing may move before maturity",
			got, maturity-1, start-fee)
	}

	// --- at maturity --------------------------------------------------------
	if err := ProcessTransactionsEscrow(maturity, nil); err != nil {
		t.Fatalf("ProcessTransactionsEscrow at maturity: %v", err)
	}
	if got := balanceOf(t, sender); got != start-fee-amount {
		t.Errorf("after settlement sender = %d, want %d", got, start-fee-amount)
	}
	if got := balanceOf(t, recipient); got != amount {
		t.Errorf("after settlement recipient = %d, want %d", got, amount)
	}
	if transactionsPool.PoolTxEscrow.HasTransaction(tx.Hash.GetBytes()) {
		t.Error("settled transaction still sits in the escrow pool")
	}
}

func TestMultiSignMovesBalanceOnlyWhenThresholdReached(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	withBalanceTestDB(t)
	initTestAccounts()
	transactionsPool.PoolTxMultiSign = transactionsPool.NewTransactionPool(common.MaxTransactionInPool, 2)

	owner, recipient := testAddress(5), testAddress(6)
	signerA, signerB := testAddress(7), testAddress(8)
	const start, amount = int64(1_000_000_000), int64(100_000_000)

	account.Accounts.AllAccounts[owner.ByteValue] = account.Account{
		Address: owner.ByteValue, Balance: start, MultiSignNumber: 2,
		MultiSignAddresses: [][common.AddressLength]byte{signerA.ByteValue, signerB.ByteValue},
	}
	for _, s := range []common.Address{signerA, signerB} {
		account.Accounts.AllAccounts[s.ByteValue] = account.Account{
			Address: s.ByteValue, Balance: start,
		}
	}

	mainTx := transferTx(t, owner, recipient, amount, common.EmptyHash(), 5)
	mainFee := feeOf(t, mainTx)

	// --- the transfer itself ------------------------------------------------
	if err := ProcessTransaction(mainTx, 100, 1000); err != nil {
		t.Fatalf("ProcessTransaction(main): %v", err)
	}
	if got := balanceOf(t, owner); got != start-mainFee {
		t.Fatalf("after submission owner = %d, want %d — fee only", got, start-mainFee)
	}
	if got := balanceOf(t, recipient); got != 0 {
		t.Fatalf("after submission recipient = %d, want 0", got)
	}

	// --- first approval: not enough ----------------------------------------
	approvalA := transferTx(t, signerA, recipient, 0, mainTx.Hash, 7)
	if err := ProcessTransaction(approvalA, 101, 1010); err != nil {
		t.Fatalf("ProcessTransaction(approval A): %v", err)
	}
	if err := ProcessTransactionsMultiSign(approvalA, 101, nil); err != nil {
		t.Fatalf("ProcessTransactionsMultiSign after one approval: %v", err)
	}
	if got := balanceOf(t, recipient); got != 0 {
		t.Fatalf("recipient = %d after one of two approvals, want 0", got)
	}
	if got := balanceOf(t, owner); got != start-mainFee {
		t.Fatalf("owner = %d after one approval, want %d — nothing may move yet",
			got, start-mainFee)
	}

	// --- second approval: threshold reached ---------------------------------
	approvalB := transferTx(t, signerB, recipient, 0, mainTx.Hash, 8)
	if err := ProcessTransaction(approvalB, 102, 1020); err != nil {
		t.Fatalf("ProcessTransaction(approval B): %v", err)
	}
	if err := ProcessTransactionsMultiSign(approvalB, 102, nil); err != nil {
		t.Fatalf("ProcessTransactionsMultiSign after two approvals: %v", err)
	}
	if got := balanceOf(t, recipient); got != amount {
		t.Errorf("recipient = %d once both signers approved, want %d", got, amount)
	}
	if got := balanceOf(t, owner); got != start-mainFee-amount {
		t.Errorf("owner = %d after settlement, want %d", got, start-mainFee-amount)
	}
}

// Signing twice from the same authorised address must not reach a threshold of
// two: the value must stay put.
func TestMultiSignDuplicateApprovalDoesNotRelease(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	withBalanceTestDB(t)
	initTestAccounts()
	transactionsPool.PoolTxMultiSign = transactionsPool.NewTransactionPool(common.MaxTransactionInPool, 2)

	owner, recipient := testAddress(9), testAddress(10)
	signerA, signerB := testAddress(11), testAddress(12)
	const start, amount = int64(1_000_000_000), int64(100_000_000)

	account.Accounts.AllAccounts[owner.ByteValue] = account.Account{
		Address: owner.ByteValue, Balance: start, MultiSignNumber: 2,
		MultiSignAddresses: [][common.AddressLength]byte{signerA.ByteValue, signerB.ByteValue},
	}
	account.Accounts.AllAccounts[signerA.ByteValue] = account.Account{
		Address: signerA.ByteValue, Balance: start,
	}

	mainTx := transferTx(t, owner, recipient, amount, common.EmptyHash(), 9)
	if err := ProcessTransaction(mainTx, 100, 1000); err != nil {
		t.Fatalf("ProcessTransaction(main): %v", err)
	}

	for i, marker := range []byte{11, 13} { // same signer, two distinct transactions
		ap := transferTx(t, signerA, recipient, 0, mainTx.Hash, marker)
		if err := ProcessTransaction(ap, int64(101+i), int64(1010+i)); err != nil {
			t.Fatalf("ProcessTransaction(approval %d): %v", i, err)
		}
		if err := ProcessTransactionsMultiSign(ap, int64(101+i), nil); err != nil {
			t.Fatalf("ProcessTransactionsMultiSign(%d): %v", i, err)
		}
	}

	if got := balanceOf(t, recipient); got != 0 {
		t.Fatalf("recipient = %d, want 0 — one address signing twice is one "+
			"approval and must not satisfy a threshold of two", got)
	}
}

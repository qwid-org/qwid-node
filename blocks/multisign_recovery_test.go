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

// msTestTx builds a minimal transaction; mainHash zero => main multisig tx,
// otherwise a confirmation of mainHash.
func msTestTx(t *testing.T, nonce int64, mainHash common.Hash) transactionsDefinition.Transaction {
	t.Helper()
	sigBytes := make([]byte, common.SignatureLength(false)+1)
	sig, _ := common.GetSignatureFromBytes(sigBytes, common.EmptyAddress())
	tx := transactionsDefinition.Transaction{
		TxParam: transactionsDefinition.TxParam{
			ChainID:     common.GetChainID(),
			Sender:      common.EmptyAddress(),
			SendingTime: nonce,
			Nonce:       nonce,
			MultiSignTx: mainHash,
		},
		TxData: transactionsDefinition.TxData{
			Recipient: common.EmptyAddress(),
			Amount:    0,
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

// TestProcessTransactionsMultiSignRecoversMainFromDB reproduces the stuck
// chain from production: block 140080 carried a multisig confirmation, the
// in-memory multisig pool was empty after restarts, and the block failed with
// "no main transaction in multi signature pool" on every retry, forever. The
// main tx sits in the confirmed transaction DB (its block was applied long
// ago), so it must be recovered from there and the block must apply.
func TestProcessTransactionsMultiSignRecoversMainFromDB(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	db := &database.BlockchainDB{}
	pdb, err := db.InitPermanent(filepath.Join(t.TempDir(), "blockchain"))
	if err != nil {
		t.Skipf("RocksDB unavailable: %v", err)
	}
	savedDB := database.MainDB
	database.MainDB = pdb
	t.Cleanup(func() {
		pdb.Close()
		database.MainDB = savedDB
	})

	savedPool := transactionsPool.PoolTxMultiSign
	transactionsPool.PoolTxMultiSign = transactionsPool.NewTransactionPool(common.MaxTransactionInPool, 2)
	t.Cleanup(func() { transactionsPool.PoolTxMultiSign = savedPool })

	// The multisig account: 2 required signatures, so a single recovered
	// confirmation must NOT settle - just accumulate and let the block apply.
	account.AccountsRWMutex.Lock()
	savedAccounts := account.Accounts
	account.Accounts = account.AccountsType{AllAccounts: map[[common.AddressLength]byte]account.Account{}}
	var sender [common.AddressLength]byte
	account.Accounts.AllAccounts[sender] = account.Account{
		Address:            sender,
		Balance:            1000,
		MultiSignNumber:    2,
		MultiSignAddresses: [][common.AddressLength]byte{{1}, {2}},
	}
	account.AccountsRWMutex.Unlock()
	t.Cleanup(func() {
		account.AccountsRWMutex.Lock()
		account.Accounts = savedAccounts
		account.AccountsRWMutex.Unlock()
	})

	// The main tx lives ONLY in the confirmed DB - the pool is empty.
	main := msTestTx(t, 1, common.EmptyHash())
	if err := main.StoreToDBPoolTx(common.TransactionDBPrefix[:]); err != nil {
		t.Fatalf("StoreToDBPoolTx: %v", err)
	}

	conf := msTestTx(t, 2, main.GetHash())
	if err := ProcessTransactionsMultiSign(conf, 120, nil); err != nil {
		t.Fatalf("ProcessTransactionsMultiSign = %v; a block carrying a multisig confirmation "+
			"must apply once the main tx is recovered from the database", err)
	}

	// The recovered main tx is back in the pool (and persisted), so the next
	// confirmations can count toward settlement.
	if !transactionsPool.PoolTxMultiSign.HasTransaction(main.GetHash().GetBytes()) {
		t.Fatal("the recovered main tx did not go back into the multisig pool")
	}
}

// TestProcessTransactionsMultiSignStillFailsWhenTrulyAbsent: when the main tx
// is nowhere to be found the error must stand (with the hash named) - applying
// blind would be worse than stopping.
func TestProcessTransactionsMultiSignStillFailsWhenTrulyAbsent(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	db := &database.BlockchainDB{}
	pdb, err := db.InitPermanent(filepath.Join(t.TempDir(), "blockchain"))
	if err != nil {
		t.Skipf("RocksDB unavailable: %v", err)
	}
	savedDB := database.MainDB
	database.MainDB = pdb
	t.Cleanup(func() {
		pdb.Close()
		database.MainDB = savedDB
	})

	savedPool := transactionsPool.PoolTxMultiSign
	transactionsPool.PoolTxMultiSign = transactionsPool.NewTransactionPool(common.MaxTransactionInPool, 2)
	t.Cleanup(func() { transactionsPool.PoolTxMultiSign = savedPool })

	missing := common.Hash{}
	missing[0] = 0xFF
	conf := msTestTx(t, 3, missing)
	if err := ProcessTransactionsMultiSign(conf, 120, nil); err == nil {
		t.Fatal("a main tx missing from every source must stay an error")
	}
}

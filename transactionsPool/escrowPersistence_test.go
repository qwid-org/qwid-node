package transactionsPool

import (
	"testing"

	"github.com/wonabru/qwid-node/common"
	"github.com/wonabru/qwid-node/database"
	"github.com/wonabru/qwid-node/logger"
	"github.com/wonabru/qwid-node/transactionsDefinition"
	"github.com/stretchr/testify/assert"
)

// buildEscrowTx returns a serializable delayed transaction for persistence tests.
func buildEscrowTx(marker byte) transactionsDefinition.Transaction {
	// A full-length primary signature (selector byte 0 + SignatureLength bytes)
	// so the transaction serializes and decodes through GetBytes/GetFromBytes.
	sigBytes := make([]byte, common.SignatureLength(false)+1)
	sig, _ := common.GetSignatureFromBytes(sigBytes, common.EmptyAddress())
	tx := transactionsDefinition.Transaction{
		TxParam: transactionsDefinition.TxParam{
			ChainID:     common.GetChainID(),
			Sender:      common.EmptyAddress(),
			SendingTime: 1,
			Nonce:       int64(marker),
		},
		TxData: transactionsDefinition.TxData{
			Recipient:               common.EmptyAddress(),
			Amount:                  5,
			OptData:                 []byte{marker},
			EscrowTransactionsDelay: 20,
		},
		Height:    100,
		GasPrice:  1,
		GasUsage:  1,
		Signature: sig,
	}
	_ = tx.CalcHashAndSet()
	return tx
}

func withInMemoryDB(t *testing.T) func() {
	t.Helper()
	db := &database.BlockchainDB{}
	mem, err := db.InitPermanent(t.TempDir())
	if err != nil {
		t.Skipf("RocksDB unavailable: %v", err)
	}
	saved := database.MainDB
	database.MainDB = mem
	return func() {
		database.MainDB = saved
		mem.Close()
	}
}

func TestEscrowPoolPersistsAcrossReload(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	cleanup := withInMemoryDB(t)
	defer cleanup()

	PoolTxEscrow = NewTransactionPool(common.MaxTransactionInPool, 1)
	tx := buildEscrowTx(7)
	hash := tx.GetHash().GetBytes()

	assert.True(t, AddEscrowTransaction(tx))
	assert.True(t, PoolTxEscrow.HasTransaction(hash), "escrow tx must be in the pool after add")

	// Simulate a node restart: the in-memory pool is lost.
	PoolTxEscrow = NewTransactionPool(common.MaxTransactionInPool, 1)
	assert.False(t, PoolTxEscrow.HasTransaction(hash))

	// Reload from the database restores the pending escrow.
	assert.NoError(t, LoadEscrowPoolFromDB())
	assert.True(t, PoolTxEscrow.HasTransaction(hash), "escrow tx must be restored from DB after restart")
}

func TestRemoveEscrowTransactionDeletesFromDB(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	cleanup := withInMemoryDB(t)
	defer cleanup()

	PoolTxEscrow = NewTransactionPool(common.MaxTransactionInPool, 1)
	tx := buildEscrowTx(9)
	hash := tx.GetHash().GetBytes()

	assert.True(t, AddEscrowTransaction(tx))
	RemoveEscrowTransaction(hash)
	assert.False(t, PoolTxEscrow.HasTransaction(hash))

	// After a restart the removed escrow must NOT reappear.
	PoolTxEscrow = NewTransactionPool(common.MaxTransactionInPool, 1)
	assert.NoError(t, LoadEscrowPoolFromDB())
	assert.False(t, PoolTxEscrow.HasTransaction(hash), "removed escrow must not be restored from DB")
}

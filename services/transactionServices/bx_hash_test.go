package transactionServices

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/database"
	"github.com/qwid-org/qwid-node/message"
	"github.com/qwid-org/qwid-node/pubkeys"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
)

func withBxTestDB(t *testing.T) {
	t.Helper()
	db := &database.BlockchainDB{}
	pdb, err := db.InitPermanent(filepath.Join(t.TempDir(), "blockchain"))
	if err != nil {
		t.Fatalf("RocksDB unavailable: %v", err)
	}
	saved, savedTrie := database.MainDB, pubkeys.GlobalMerkleTree
	database.MainDB = pdb
	pubkeys.InitPermanentTrie()
	t.Cleanup(func() { pdb.Close(); database.MainDB, pubkeys.GlobalMerkleTree = saved, savedTrie })
}

func bxMessage(txs ...transactionsDefinition.Transaction) []byte {
	items := [][]byte{}
	for _, tx := range txs {
		items = append(items, tx.GetBytes())
	}
	m := message.TransactionsMessage{
		BaseMessage:       message.BaseMessage{Head: []byte("bx"), ChainID: common.GetChainID()},
		TransactionsBytes: map[[2]byte][][]byte{{'T', 'T'}: items},
	}
	return m.GetBytes()
}

func keylessTx(t *testing.T, marker byte) transactionsDefinition.Transaction {
	t.Helper()
	var sender, recipient common.Address
	sender.ByteValue[0], recipient.ByteValue[0] = 0xAA, marker
	sig, err := common.GetSignatureFromBytes(make([]byte, common.SignatureLength(false)), sender)
	if err != nil {
		t.Fatal(err)
	}
	tx := transactionsDefinition.Transaction{
		TxParam:   transactionsDefinition.TxParam{ChainID: common.GetChainID(), Sender: sender, SendingTime: 1, Nonce: int64(marker)},
		TxData:    transactionsDefinition.TxData{Recipient: recipient, Amount: 123456789},
		Signature: sig,
		Height:    5, GasPrice: 1, GasUsage: 1000,
	}
	if err := tx.CalcHashAndSet(); err != nil {
		t.Fatal(err)
	}
	return tx
}

// S2-02: a bx carrying a body under a hash that body does not produce must
// not be stored - block application would later execute it as that hash.
func TestBxRejectsBodyUnderForeignHash(t *testing.T) {
	withBxTestDB(t)
	common.IsSyncing.Store(false)
	forged := keylessTx(t, 0xBB)
	victimHash := common.GetHashFromBytes(bytes.Repeat([]byte{0x77}, 32))
	forged.Hash = victimHash

	OnMessage([4]byte{203, 0, 113, 80}, bxMessage(forged))

	if transactionsDefinition.CheckFromDBPoolTx(common.TransactionPoolHashesDBPrefix[:], victimHash.GetBytes()) {
		t.Fatal("a body was stored under a hash it does not produce")
	}
}

// The fix must not lose honest answers: a body whose hash is its own is kept.
func TestBxStoresBodyWithMatchingHash(t *testing.T) {
	withBxTestDB(t)
	common.IsSyncing.Store(false)
	honest := keylessTx(t, 0xCC)

	OnMessage([4]byte{203, 0, 113, 81}, bxMessage(honest))

	if !transactionsDefinition.CheckFromDBPoolTx(common.TransactionPoolHashesDBPrefix[:], honest.Hash.GetBytes()) {
		t.Fatal("an honest bx answer was not stored")
	}
}

// S2-10: a panic while processing one transaction of a bx answer must not
// take the node down (the worker goroutines had no recover).
func TestBxWorkerPanicDoesNotCrashTheNode(t *testing.T) {
	withBxTestDB(t)
	common.IsSyncing.Store(false)
	saved := pubkeys.GlobalMerkleTree
	pubkeys.GlobalMerkleTree = nil // the pubkey lookup in the worker now panics
	t.Cleanup(func() { pubkeys.GlobalMerkleTree = saved })

	OnMessage([4]byte{203, 0, 113, 82}, bxMessage(keylessTx(t, 0xDD)))
}

// S4-01: the pool admits only transactions that a next block could include.
func TestGossipAdmitsOnlyTransactionsInHeightWindow(t *testing.T) {
	saved := common.GetHeight()
	t.Cleanup(func() { common.SetHeight(saved) })
	common.SetHeight(100_000)
	if !admissibleTxHeight(100_000) {
		t.Fatal("a transaction stamped with the current tip was refused")
	}
	if admissibleTxHeight(0) {
		t.Fatal("a transaction claiming Height 0 was admitted")
	}
	if admissibleTxHeight(100_002) {
		t.Fatal("a transaction from the future was admitted")
	}
}

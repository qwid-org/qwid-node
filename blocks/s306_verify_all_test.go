package blocks

import (
	"testing"

	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/crypto/oqs"
	"github.com/qwid-org/qwid-node/pubkeys"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
	"github.com/qwid-org/qwid-node/transactionsPool"
)

// parentAt is a parent block that leaves the current signature schemes in
// force, which block application reads its verification config from.
func parentAt(t *testing.T, height int64) Block {
	t.Helper()
	enc1, err := oqs.GenerateBytesFromParams(common.SigName(), common.PubKeyLength(false), common.PrivateKeyLength(), common.SignatureLength(false), common.IsPaused())
	if err != nil {
		t.Fatal(err)
	}
	enc2, err := oqs.GenerateBytesFromParams(common.SigName2(), common.PubKeyLength2(false), common.PrivateKeyLength2(), common.SignatureLength2(false), common.IsPaused2())
	if err != nil {
		t.Fatal(err)
	}
	return Block{BaseBlock: BaseBlock{
		BaseHeader: BaseHeader{Height: height, Encryption1: enc1, Encryption2: enc2},
		Supply:     1_000_000_000_000,
	}}
}

func childOf(last Block, hashes ...common.Hash) Block {
	return Block{
		BaseBlock: BaseBlock{
			BaseHeader: BaseHeader{Height: last.GetHeader().Height + 1},
			Supply:     last.GetBlockSupply() + account.GetReward(last.GetBlockSupply()),
		},
		TransactionsHashes: hashes,
	}
}

// signedTx is an ordinary transfer from k, signed with k's registered key.
func signedTx(t *testing.T, k stageBKey, recipient common.Address, amount, height, nonce int64) transactionsDefinition.Transaction {
	t.Helper()
	tx := transactionsDefinition.Transaction{
		TxParam: transactionsDefinition.TxParam{ChainID: common.GetChainID(), Sender: k.addr, SendingTime: 1, Nonce: nonce},
		TxData:  transactionsDefinition.TxData{Recipient: recipient, Amount: amount},
		Height:  height, GasPrice: 1, GasUsage: 100000,
	}
	k.sign(t, &tx)
	return tx
}

func pooled(t *testing.T, txs ...transactionsDefinition.Transaction) []common.Hash {
	t.Helper()
	hashes := []common.Hash{}
	for _, tx := range txs {
		if err := tx.StoreToDBPoolTx(common.TransactionPoolHashesDBPrefix[:]); err != nil {
			t.Fatal(err)
		}
		transactionsPool.PoolsTx.AddTransaction(tx, tx.Hash)
		h := tx.Hash
		t.Cleanup(func() { transactionsPool.PoolsTx.RemoveTransactionByHash(h.GetBytes()) })
		hashes = append(hashes, tx.Hash)
	}
	return hashes
}

func fund(addrs ...common.Address) {
	all := map[[common.AddressLength]byte]account.Account{}
	for _, a := range addrs {
		all[a.ByteValue] = account.Account{Address: a.ByteValue, Balance: 1_000_000_000}
	}
	account.Accounts = account.AccountsType{AllAccounts: all}
}

// Every transaction of a block is verified when it is applied, whatever the
// node's mode: a pool body with a forged signature - which bx stores
// unverified while syncing - rejects the block.
func TestApplyVerifiesEveryTransactionSignature(t *testing.T) {
	k := registeredStageBKey(t)
	fund(k.addr)
	last := parentAt(t, 99)

	honest := signedTx(t, k, testAddress(0x81), 5, 99, 1)
	if _, _, err := CheckBlockTransfers(childOf(last, pooled(t, honest)...), last, nil, true); err != nil {
		t.Fatalf("an honestly signed transaction was rejected: %v", err)
	}

	for _, syncing := range []bool{false, true} {
		saved := common.IsSyncing.Load()
		common.IsSyncing.Store(syncing)
		forged := signedTx(t, k, testAddress(0x82), 5, 99, 2)
		forged.TxData.Amount = 500 // body changed after signing, hash recomputed
		if err := forged.CalcHashAndSet(); err != nil {
			t.Fatal(err)
		}
		_, _, err := CheckBlockTransfers(childOf(last, pooled(t, forged)...), last, nil, true)
		common.IsSyncing.Store(saved)
		if err == nil {
			t.Fatalf("syncing=%v: a transaction whose signature does not cover its body was accepted", syncing)
		}
	}
}

// A forged transaction is rejected BEFORE balances are accounted, so it cannot
// make an honest transaction of the same sender look unpayable and get it
// banned from the pool.
func TestForgedTransactionDoesNotGetHonestOneBanned(t *testing.T) {
	k := registeredStageBKey(t)
	account.Accounts = account.AccountsType{AllAccounts: map[[common.AddressLength]byte]account.Account{
		k.addr.ByteValue: {Address: k.addr.ByteValue, Balance: 1_000_000},
	}}
	last := parentAt(t, 99)
	forged := signedTx(t, k, testAddress(0x83), 1, 99, 1)
	forged.TxData.Amount = 900_000
	if err := forged.CalcHashAndSet(); err != nil {
		t.Fatal(err)
	}
	honest := signedTx(t, k, testAddress(0x84), 500_000, 99, 2)
	if _, _, err := CheckBlockTransfers(childOf(last, pooled(t, forged, honest)...), last, nil, true); err == nil {
		t.Fatal("a block with a forged transaction was accepted")
	}
	if !transactionsPool.PoolsTx.HasTransaction(honest.Hash.GetBytes()) {
		t.Fatal("the honest transaction was dropped because a forged one spent its balance first")
	}
	if transactionsPool.PoolsTx.HasTransaction(forged.Hash.GetBytes()) {
		t.Fatal("the forged transaction is still in the pool")
	}
}

// Signatures are checked against the keys registered by the PARENT block: a
// key registered in block 100 signs nothing in block 100, and does from 101.
func TestApplyUsesRegistryAsOfParent(t *testing.T) {
	k := registeredStageBKey(t)
	if err := pubkeys.StoreRegistrationHeight(k.addr, 100); err != nil {
		t.Fatal(err)
	}
	fund(k.addr)
	tx := signedTx(t, k, testAddress(0x85), 5, 100, 1)

	at100 := parentAt(t, 99)
	if _, _, err := CheckBlockTransfers(childOf(at100, pooled(t, tx)...), at100, nil, true); err == nil {
		t.Fatal("a key registered in block 100 verified a transaction of block 100")
	}
	tx2 := signedTx(t, k, testAddress(0x85), 5, 100, 2)
	at101 := parentAt(t, 100)
	if _, _, err := CheckBlockTransfers(childOf(at101, pooled(t, tx2)...), at101, nil, true); err != nil {
		t.Fatalf("a key registered in block 100 must verify in block 101: %v", err)
	}
}

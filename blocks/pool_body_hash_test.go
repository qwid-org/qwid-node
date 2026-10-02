package blocks

import (
	"bytes"
	"testing"

	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
	"github.com/qwid-org/qwid-node/transactionsPool"
)

// S3-01: block application loads transaction bodies from the pool DB by hash.
// A body stored under a hash it does not produce must never be executed.
func TestCheckBlockTransfersRejectsPoolBodyWithForeignHash(t *testing.T) {
	withBalanceTestDB(t)
	victim, attacker := testAddress(0x51), testAddress(0x52)
	const start = int64(1_000_000_000)
	account.Accounts = account.AccountsType{AllAccounts: map[[common.AddressLength]byte]account.Account{
		victim.ByteValue:   {Address: victim.ByteValue, Balance: start},
		attacker.ByteValue: {Address: attacker.ByteValue},
	}}
	committed := common.GetHashFromBytes(bytes.Repeat([]byte{0x42}, 32))
	forged := transferTx(t, victim, attacker, start-1000, common.Hash{}, 9)
	forged.Hash = committed
	if err := forged.StoreToDBPoolTx(common.TransactionPoolHashesDBPrefix[:]); err != nil {
		t.Fatal(err)
	}

	if _, err := transactionsDefinition.LoadFromDBPoolTx(common.TransactionPoolHashesDBPrefix[:], committed.GetBytes()); err == nil {
		t.Fatal("LoadFromDBPoolTx returned a body that does not hash to its key")
	}
	last := Block{BaseBlock: BaseBlock{BaseHeader: BaseHeader{Height: 9}, Supply: 1_000_000_000_000}}
	blk := Block{
		BaseBlock:          BaseBlock{BaseHeader: BaseHeader{Height: 10}, Supply: last.GetBlockSupply() + account.GetReward(last.GetBlockSupply())},
		TransactionsHashes: []common.Hash{committed},
	}
	if _, _, err := CheckBlockTransfers(blk, last, nil, true); err == nil {
		t.Fatal("CheckBlockTransfers accepted a block whose transaction body does not match its hash")
	}
}

// Honest bodies still load.
func TestLoadFromDBPoolTxReturnsMatchingBody(t *testing.T) {
	withBalanceTestDB(t)
	tx := transferTx(t, testAddress(0x61), testAddress(0x62), 5, common.Hash{}, 3)
	if err := tx.StoreToDBPoolTx(common.TransactionPoolHashesDBPrefix[:]); err != nil {
		t.Fatal(err)
	}
	got, err := transactionsDefinition.LoadFromDBPoolTx(common.TransactionPoolHashesDBPrefix[:], tx.Hash.GetBytes())
	if err != nil || !bytes.Equal(got.Hash.GetBytes(), tx.Hash.GetBytes()) {
		t.Fatalf("honest body did not load: %v", err)
	}
}

// S4-04: a block attempt that meets invalid staking transactions must purge
// all of them from the pool in one pass, as it already does for unpayable
// ones - otherwise a flood of them stalls production one block at a time.
func TestCheckBlockTransfersPurgesAllInvalidStakingTransactions(t *testing.T) {
	withBalanceTestDB(t)
	sender := testAddress(0x71)
	account.Accounts = account.AccountsType{AllAccounts: map[[common.AddressLength]byte]account.Account{
		sender.ByteValue: {Address: sender.ByteValue, Balance: 1_000_000},
	}}
	for i := 0; i < 256; i++ {
		account.StakingAccounts[i] = account.StakingAccountsType{AllStakingAccounts: map[[common.AddressLength]byte]account.StakingAccount{}}
	}
	hashes := []common.Hash{}
	for i := byte(1); i <= 3; i++ {
		tx := transferTx(t, sender, common.GetDelegatedAccountAddress(5), 0, common.Hash{}, i) // zero-amount "stake": invalid
		if err := tx.StoreToDBPoolTx(common.TransactionPoolHashesDBPrefix[:]); err != nil {
			t.Fatal(err)
		}
		transactionsPool.PoolsTx.AddTransaction(tx, tx.Hash)
		hashes = append(hashes, tx.Hash)
	}
	t.Cleanup(func() {
		for _, h := range hashes {
			transactionsPool.PoolsTx.RemoveTransactionByHash(h.GetBytes())
		}
	})
	last := Block{BaseBlock: BaseBlock{BaseHeader: BaseHeader{Height: 9}, Supply: 1_000_000_000_000}}
	blk := Block{
		BaseBlock:          BaseBlock{BaseHeader: BaseHeader{Height: 10}, Supply: last.GetBlockSupply() + account.GetReward(last.GetBlockSupply())},
		TransactionsHashes: hashes,
	}
	if _, _, err := CheckBlockTransfers(blk, last, nil, true); err == nil {
		t.Fatal("a block of invalid staking transactions was accepted")
	}
	for i, h := range hashes {
		if transactionsPool.PoolsTx.HasTransaction(h.GetBytes()) {
			t.Fatalf("invalid staking transaction %d is still in the pool", i)
		}
	}
}

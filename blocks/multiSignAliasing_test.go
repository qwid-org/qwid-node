package blocks

import (
	"testing"

	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
	"github.com/qwid-org/qwid-node/transactionsPool"
)

// ProcessTransactionsMultiSign tracked which authorised signers were still
// outstanding with
//
//	notApprovedYet := acc.MultiSignAddresses[:]
//
// which shares the backing array with the account held in the global map, and
// then removed matched entries with append(notApprovedYet[:i], ...[i+1:]...).
// That shifts elements inside the shared array, so counting approvals rewrote
// the account's list of authorised signers.
//
// With two signers nothing moves (the match is always first or last). From
// three upwards, removing a middle signer drops it and duplicates its
// successor: [A B C] becomes [A C C]. The dropped signer can no longer approve
// anything, and the duplicated one occupies two slots — so a single address
// can be counted twice and reach the threshold alone. That is a weakening of
// the multi-signature guarantee, not just a display fault.
func TestMultiSignSettlementDoesNotMutateSignerList(t *testing.T) {
	initTestAccounts()
	transactionsPool.PoolTxMultiSign = transactionsPool.NewTransactionPool(common.MaxTransactionInPool, 2)

	var owner, recipient, a, b, c common.Address
	owner.ByteValue[0] = 1
	recipient.ByteValue[0] = 2
	a.ByteValue[0] = 3
	b.ByteValue[0] = 4
	c.ByteValue[0] = 5

	account.Accounts.AllAccounts[owner.ByteValue] = account.Account{
		Address:         owner.ByteValue,
		Balance:         1_000_000,
		MultiSignNumber: 3,
		MultiSignAddresses: [][common.AddressLength]byte{
			a.ByteValue, b.ByteValue, c.ByteValue,
		},
	}

	var mainHash common.Hash
	mainBytes := make([]byte, common.HashLength)
	mainBytes[0] = 42
	mainHash.Set(mainBytes)
	mainTx := transactionsDefinition.Transaction{
		TxParam: transactionsDefinition.TxParam{Sender: owner},
		TxData:  transactionsDefinition.TxData{Recipient: recipient, Amount: 12300000000},
		Hash:    mainHash,
		Height:  100,
	}
	if !transactionsPool.PoolTxMultiSign.AddTransaction(mainTx, mainHash) {
		t.Fatal("failed to pool the main transaction")
	}

	// Approvals from B and C — B sits in the middle, which is what triggers
	// the in-place shift.
	for i, signer := range []common.Address{b, c} {
		var h common.Hash
		hb := make([]byte, common.HashLength)
		hb[0] = byte(100 + i)
		h.Set(hb)
		co := transactionsDefinition.Transaction{
			TxParam: transactionsDefinition.TxParam{Sender: signer, MultiSignTx: mainHash},
			TxData:  transactionsDefinition.TxData{Recipient: recipient, Amount: 0},
			Hash:    h,
			Height:  101,
		}
		if !transactionsPool.PoolTxMultiSign.AddTransaction(co, mainHash) {
			t.Fatalf("failed to pool approval %d", i)
		}
	}

	// Two of three approvals: settlement counts, finds it insufficient and
	// returns before it needs the merkle tree.
	trigger := transactionsDefinition.Transaction{
		TxParam: transactionsDefinition.TxParam{Sender: c, MultiSignTx: mainHash},
		TxData:  transactionsDefinition.TxData{Recipient: recipient, Amount: 0},
		Height:  101,
	}
	if err := ProcessTransactionsMultiSign(trigger, 102, nil); err != nil {
		t.Fatalf("settlement returned an error: %v", err)
	}

	acc, ok := account.GetAccountByAddressBytes(owner.GetBytes())
	if !ok {
		t.Fatal("owner account vanished")
	}
	want := [][common.AddressLength]byte{a.ByteValue, b.ByteValue, c.ByteValue}
	if len(acc.MultiSignAddresses) != len(want) {
		t.Fatalf("signer list length changed: %d", len(acc.MultiSignAddresses))
	}
	for i := range want {
		if acc.MultiSignAddresses[i] != want[i] {
			t.Fatalf("authorised signer list was rewritten by counting approvals:\n got %v\nwant %v",
				acc.MultiSignAddresses, want)
		}
	}
}

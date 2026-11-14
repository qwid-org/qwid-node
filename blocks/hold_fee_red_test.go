package blocks

import (
	"testing"

	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
	"github.com/qwid-org/qwid-node/transactionsPool"
)

// Pool-flooding (audit 2026-11-12 F-POOL-01): a transaction that holds a slot
// in the escrow or multisig pool pays for the time it holds it.

// secondIdentity is another identity with both keys registered, in the same
// test database as the first.
func secondIdentity(t *testing.T) stageBKey {
	t.Helper()
	k := unregisteredPrimary(t)
	registerKey(t, enclosed(t, k, k.addr, true))
	spare := secondaryKey(t)
	registerKey(t, enclosed(t, spare, k.addr, false))
	k.spare = &spare
	return k
}

func withFreshHeldPools(t *testing.T) {
	t.Helper()
	se, sm := transactionsPool.PoolTxEscrow, transactionsPool.PoolTxMultiSign
	t.Cleanup(func() { transactionsPool.PoolTxEscrow, transactionsPool.PoolTxMultiSign = se, sm })
	transactionsPool.PoolTxEscrow = transactionsPool.NewTransactionPool(common.MaxTransactionInPool, 1)
	transactionsPool.PoolTxMultiSign = transactionsPool.NewTransactionPool(common.MaxTransactionInPool, 2)
}

func TestUnderpaidEscrowTransferIsRefusedByTheCheck(t *testing.T) {
	k := registeredStageBKey(t)
	fund(k.addr)
	withFreshHeldPools(t)
	acc := account.Accounts.AllAccounts[k.addr.ByteValue]
	acc.TransactionDelay = common.MaxTransactionDelay / 10
	account.Accounts.AllAccounts[k.addr.ByteValue] = acc
	last := parentAt(t, 99)
	cheap := signedTx(t, k, testAddress(0x71), 5, 99, 1) // fee 100 000 base units
	if _, _, err := CheckBlockTransfers(childOf(last, pooled(t, cheap)...), last, nil, true); err == nil {
		t.Fatal("an escrow transfer held for a tenth of a week paid only the minimum fee and passed the check")
	}
}

func TestUnderpaidMultiSigTransactionIsRefusedByTheCheck(t *testing.T) {
	owner := registeredStageBKey(t)
	signer := secondIdentity(t)
	fund(owner.addr, signer.addr)
	withFreshHeldPools(t)
	acc := account.Accounts.AllAccounts[owner.addr.ByteValue]
	acc.MultiSignNumber = 1
	acc.MultiSignAddresses = [][common.AddressLength]byte{signer.addr.ByteValue}
	account.Accounts.AllAccounts[owner.addr.ByteValue] = acc
	last := parentAt(t, 99)
	main := signedTx(t, owner, testAddress(0x72), 5, 99, 1)
	if _, _, err := CheckBlockTransfers(childOf(last, pooled(t, main)...), last, nil, true); err == nil {
		t.Fatal("a multisig transaction held up to a week paid only the minimum fee and passed the check")
	}
}

func TestApprovalFromANonSignerIsRefusedByTheCheck(t *testing.T) {
	owner := registeredStageBKey(t)
	stranger := secondIdentity(t)
	fund(owner.addr, stranger.addr)
	withFreshHeldPools(t)
	acc := account.Accounts.AllAccounts[owner.addr.ByteValue]
	acc.MultiSignNumber = 1
	acc.MultiSignAddresses = [][common.AddressLength]byte{testAddress(0x99).ByteValue}
	account.Accounts.AllAccounts[owner.addr.ByteValue] = acc
	main := signedTx(t, owner, testAddress(0x73), 5, 99, 1)
	if err := ProcessTransaction(main, 99, 1); err != nil { // the main is pending in the pool
		t.Fatal(err)
	}
	approval := transactionsDefinition.Transaction{
		TxParam: transactionsDefinition.TxParam{ChainID: common.GetChainID(), Sender: stranger.addr, SendingTime: 1, Nonce: 2, MultiSignTx: main.Hash},
		TxData:  transactionsDefinition.TxData{Recipient: testAddress(0x73)},
		Height:  99, GasPrice: 1, GasUsage: 100000,
	}
	stranger.sign(t, &approval)
	last := parentAt(t, 99)
	if _, _, err := CheckBlockTransfers(childOf(last, pooled(t, approval)...), last, nil, true); err == nil {
		t.Fatal("an approval from an address that is no signer of the account passed the check")
	}
}

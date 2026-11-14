package blocks

import (
	"testing"

	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
)

func paidTx(t *testing.T, k stageBKey, recipient common.Address, amount int64, nonce int64, hold int64, multiSignTx common.Hash) transactionsDefinition.Transaction {
	t.Helper()
	tx := transactionsDefinition.Transaction{
		TxParam: transactionsDefinition.TxParam{ChainID: common.GetChainID(), Sender: k.addr, SendingTime: 1, Nonce: nonce, MultiSignTx: multiSignTx},
		TxData:  transactionsDefinition.TxData{Recipient: recipient, Amount: amount},
		Height:  99, GasPrice: 1, GasUsage: 100000,
	}
	if err := transactionsDefinition.ApplyHoldFee(&tx, hold); err != nil {
		t.Fatal(err)
	}
	k.sign(t, &tx)
	return tx
}

func TestPaidEscrowTransferPassesTheCheck(t *testing.T) {
	k := registeredStageBKey(t)
	fund(k.addr)
	withFreshHeldPools(t)
	acc := account.Accounts.AllAccounts[k.addr.ByteValue]
	acc.TransactionDelay = common.MaxTransactionDelay / 10
	account.Accounts.AllAccounts[k.addr.ByteValue] = acc
	last := parentAt(t, 99)
	tx := paidTx(t, k, testAddress(0x71), 5, 1, common.HoldFee(acc.TransactionDelay), common.Hash{})
	if _, _, err := CheckBlockTransfers(childOf(last, pooled(t, tx)...), last, nil, true); err != nil {
		t.Fatalf("a paid escrow transfer was refused: %v", err)
	}
}

func multisigSetup(t *testing.T) (owner, signer stageBKey, acc account.Account) {
	t.Helper()
	owner = registeredStageBKey(t)
	signer = secondIdentity(t)
	fund(owner.addr, signer.addr)
	withFreshHeldPools(t)
	acc = account.Accounts.AllAccounts[owner.addr.ByteValue]
	acc.MultiSignNumber = 1
	acc.MultiSignAddresses = [][common.AddressLength]byte{signer.addr.ByteValue}
	account.Accounts.AllAccounts[owner.addr.ByteValue] = acc
	return owner, signer, acc
}

func TestMultiSigApprovalRules(t *testing.T) {
	owner, signer, acc := multisigSetup(t)
	last := parentAt(t, 99)
	recipient := testAddress(0x74)
	hold := transactionsDefinition.RequiredHoldFee(transactionsDefinition.Transaction{TxData: transactionsDefinition.TxData{Recipient: recipient, Amount: 5}}, acc, true)
	main := paidTx(t, owner, recipient, 5, 1, hold, common.Hash{})
	approval := paidTx(t, signer, recipient, 0, 2, 0, main.Hash)

	if _, _, err := CheckBlockTransfers(childOf(last, pooled(t, approval)...), last, nil, true); err == nil {
		t.Fatal("an approval of a transaction that is not pending passed the check")
	}
	if _, _, err := CheckBlockTransfers(childOf(last, pooled(t, main, approval)...), last, nil, true); err != nil {
		t.Fatalf("a paid multisig transaction with its approval later in the block was refused: %v", err)
	}
	if _, _, err := CheckBlockTransfers(childOf(last, pooled(t, approval, main)...), last, nil, true); err == nil {
		t.Fatal("an approval placed before its transaction passed the check; it would approve nothing when applied")
	}
	if err := ProcessTransaction(main, 99, 1); err != nil {
		t.Fatal(err)
	}
	if _, _, err := CheckBlockTransfers(childOf(last, pooled(t, approval)...), last, nil, true); err != nil {
		t.Fatalf("an approval of a pending transaction was refused: %v", err)
	}
	if err := ProcessTransaction(approval, 99, 1); err != nil {
		t.Fatal(err)
	}
	again := paidTx(t, signer, recipient, 0, 3, 0, main.Hash)
	if _, _, err := CheckBlockTransfers(childOf(last, pooled(t, again)...), last, nil, true); err == nil {
		t.Fatal("a second approval by the same signer passed the check")
	}
}

// The multisig transaction paid for the whole window; settled early, it gets
// the unused part back, taken from the fees the chain holds.
func TestSettledMultiSigTransactionGetsTheUnusedHoldBack(t *testing.T) {
	owner, signer, acc := multisigSetup(t)
	recipient := testAddress(0x75)
	hold := transactionsDefinition.RequiredHoldFee(transactionsDefinition.Transaction{TxData: transactionsDefinition.TxData{Recipient: recipient, Amount: 5}}, acc, true)
	main := paidTx(t, owner, recipient, 5, 1, hold, common.Hash{})
	approval := paidTx(t, signer, recipient, 0, 2, 0, main.Hash)
	if err := ProcessTransaction(main, 100, 1); err != nil {
		t.Fatal(err)
	}
	if err := ProcessTransaction(approval, 110, 1); err != nil {
		t.Fatal(err)
	}
	before := balanceOf(t, owner.addr)
	takeHoldRefunds()
	if err := ProcessTransactionsMultiSign(approval, 110, nil); err != nil {
		t.Fatal(err)
	}
	want := 2 * (common.HoldFee(common.MaxTransactionInMultiSigPool) - common.HoldFee(10))
	if got := takeHoldRefunds(); got != want {
		t.Fatalf("refund %d, want %d", got, want)
	}
	if got := balanceOf(t, owner.addr); got != before-5+want {
		t.Fatalf("owner balance %d, want %d", got, before-5+want)
	}
	if balanceOf(t, recipient) != 5 {
		t.Fatal("the transfer did not settle")
	}
}

package blocks

import (
	"testing"

	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
)

// A co-signature counts only when its sender is an authorised signer, its
// recipient matches the main transaction's, and its amount is zero
// (processTransaction.go). The wallet had no way to show any of that: the
// pending list showed "Awaiting co-signers" and nothing else, so an owner
// could not tell how many signatures were in, nor that the main transaction
// does not approve itself.

func multiSignFixture(t *testing.T, required uint8, signers []common.Address) (transactionsDefinition.Transaction, common.Address, common.Address) {
	t.Helper()
	initTestAccounts()

	var owner, recipient common.Address
	owner.ByteValue[0] = 1
	recipient.ByteValue[0] = 2

	addrs := make([][common.AddressLength]byte, len(signers))
	for i, s := range signers {
		addrs[i] = s.ByteValue
	}
	account.Accounts.AllAccounts[owner.ByteValue] = account.Account{
		Address:            owner.ByteValue,
		Balance:            1_000_000,
		MultiSignNumber:    required,
		MultiSignAddresses: addrs,
	}

	mainTx := transactionsDefinition.Transaction{
		TxParam: transactionsDefinition.TxParam{Sender: owner},
		TxData:  transactionsDefinition.TxData{Recipient: recipient, Amount: 12300000000},
		Height:  100,
	}
	return mainTx, owner, recipient
}

func approval(sender, recipient common.Address) transactionsDefinition.Transaction {
	return transactionsDefinition.Transaction{
		TxParam: transactionsDefinition.TxParam{Sender: sender},
		TxData:  transactionsDefinition.TxData{Recipient: recipient, Amount: 0},
	}
}

func TestCountMultiSignApprovalsCountsDistinctSigners(t *testing.T) {
	var a, b common.Address
	a.ByteValue[0] = 3
	b.ByteValue[0] = 4
	mainTx, _, recipient := multiSignFixture(t, 2, []common.Address{a, b})

	group := []transactionsDefinition.Transaction{mainTx, approval(a, recipient)}
	got, required := CountMultiSignApprovals(mainTx, group)

	if required != 2 {
		t.Fatalf("required = %d, want 2", required)
	}
	if got != 1 {
		t.Fatalf("approvals = %d, want 1 — the main transaction must not approve itself", got)
	}

	group = append(group, approval(b, recipient))
	if got, _ = CountMultiSignApprovals(mainTx, group); got != 2 {
		t.Fatalf("approvals = %d, want 2 once both signers have signed", got)
	}
}

// The same authorised address signing twice is one approval, not two.
func TestCountMultiSignApprovalsIgnoresDuplicateSigner(t *testing.T) {
	var a, b common.Address
	a.ByteValue[0] = 3
	b.ByteValue[0] = 4
	mainTx, _, recipient := multiSignFixture(t, 2, []common.Address{a, b})

	group := []transactionsDefinition.Transaction{
		mainTx, approval(a, recipient), approval(a, recipient),
	}

	if got, _ := CountMultiSignApprovals(mainTx, group); got != 1 {
		t.Fatalf("approvals = %d, want 1 for one signer signing twice", got)
	}
}

func TestCountMultiSignApprovalsRejectsWrongRecipientOrAmount(t *testing.T) {
	var a, b, other common.Address
	a.ByteValue[0] = 3
	b.ByteValue[0] = 4
	other.ByteValue[0] = 9
	mainTx, _, recipient := multiSignFixture(t, 2, []common.Address{a, b})

	wrongRecipient := approval(a, other)
	if got, _ := CountMultiSignApprovals(mainTx, []transactionsDefinition.Transaction{mainTx, wrongRecipient}); got != 0 {
		t.Errorf("approvals = %d, want 0 when the recipient does not match", got)
	}

	nonZero := approval(b, recipient)
	nonZero.TxData.Amount = 1
	if got, _ := CountMultiSignApprovals(mainTx, []transactionsDefinition.Transaction{mainTx, nonZero}); got != 0 {
		t.Errorf("approvals = %d, want 0 when the amount is not zero", got)
	}
}

// The counting must not disturb the account's authorised-signer list. The
// settlement loop aliases that slice and corrupts it for three or more
// signers; this helper must not repeat that.
func TestCountMultiSignApprovalsLeavesSignerListIntact(t *testing.T) {
	var a, b, c common.Address
	a.ByteValue[0] = 3
	b.ByteValue[0] = 4
	c.ByteValue[0] = 5
	mainTx, owner, recipient := multiSignFixture(t, 3, []common.Address{a, b, c})

	group := []transactionsDefinition.Transaction{mainTx, approval(b, recipient)}
	CountMultiSignApprovals(mainTx, group)

	acc, _ := account.GetAccountByAddressBytes(owner.GetBytes())
	want := [][common.AddressLength]byte{a.ByteValue, b.ByteValue, c.ByteValue}
	for i := range want {
		if acc.MultiSignAddresses[i] != want[i] {
			t.Fatalf("authorised signer list was mutated: %v", acc.MultiSignAddresses)
		}
	}
}

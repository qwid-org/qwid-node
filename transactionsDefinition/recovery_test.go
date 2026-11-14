package transactionsDefinition

import (
	"bytes"
	"testing"

	"github.com/qwid-org/qwid-node/common"
)

func TestBindOptDataRoundTrip(t *testing.T) {
	id := addr(t, 0x10)
	tag, payload := [32]byte{1}, [32]byte{2}
	gotID, gotTag, gotPayload, err := ParseRecoveryBind(BuildRecoveryBindOptData(id, tag, payload))
	if err != nil || gotID != id || gotTag != tag || gotPayload != payload {
		t.Fatalf("round trip failed: %v", err)
	}
	if _, _, _, err := ParseRecoveryBind(make([]byte, common.RecoveryBindOptDataLength-1)); err == nil {
		t.Fatal("short bind accepted")
	}
}

func TestRevealOptDataRoundTrip(t *testing.T) {
	s := bytes.Repeat([]byte{7}, common.RecoverySecretLength)
	next := addr(t, 0x20)
	gotS, gotNext, err := ParseRecoveryReveal(BuildRecoveryRevealOptData(s, next))
	if err != nil || !bytes.Equal(gotS, s) || gotNext != next {
		t.Fatalf("round trip failed: %v", err)
	}
	if _, _, err := ParseRecoveryReveal(make([]byte, common.RecoveryRevealOptDataLength+1)); err == nil {
		t.Fatal("long reveal accepted")
	}
}

func regTx(t *testing.T, sender, recipient common.Address) Transaction {
	t.Helper()
	tx := Transaction{
		TxParam: TxParam{Sender: sender},
		TxData:  TxData{Recipient: recipient},
	}
	tx.TxData.Pubkey.ByteValue = bytes.Repeat([]byte{1}, 40)
	return tx
}

// commitTx is a commitment registration as wallets build it.
func commitTx(t *testing.T, sender, spare common.Address, recovery []byte) Transaction {
	t.Helper()
	tx := regTx(t, sender, common.RecoveryCommitAddress)
	tx.TxData.Recipient, tx.TxData.OptData = CommitmentRegistration(spare, recovery)
	return tx
}

// P-05: a commitment registration is marked as one - sent to the reserved
// commitment address, with the spare key's address in OptData. It used to be
// inferred from the shape "a key, no amount, somebody else's address", so an
// ordinary zero-amount transaction that happened to carry a key made its
// recipient the sender's committed spare: whoever held that address's
// unregistered key could then register it under the sender's identity.
func TestKeyCarryingTransactionToAnAddressSetsNoCommitment(t *testing.T) {
	me, other := addr(t, 0x10), addr(t, 0x40)
	if tx := regTx(t, me, other); tx.IsCommitmentRegistration() {
		t.Fatal("a zero-amount transaction carrying a key made its recipient the committed spare")
	}
}

func TestCommitmentRegistrationShape(t *testing.T) {
	me, spare, c := addr(t, 0x10), addr(t, 0x40), addr(t, 0x50)
	tx := commitTx(t, me, spare, c.GetBytes())
	if !tx.IsCommitmentRegistration() || !tx.IsKeyRegistration() {
		t.Fatal("a commitment registration was not recognised")
	}
	if s, r := tx.CommitmentValues(); s != spare.ByteValue || r != c.ByteValue {
		t.Fatalf("commitment values: spare %x recovery %x", s, r)
	}
	spareOnly := commitTx(t, me, spare, nil)
	if s, r := spareOnly.CommitmentValues(); !spareOnly.IsCommitmentRegistration() || s != spare.ByteValue || r != ([common.AddressLength]byte{}) {
		t.Fatal("a registration committing only to the spare was not read back")
	}
	self := regTx(t, me, me)
	if self.IsCommitmentRegistration() || !self.IsKeyRegistration() {
		t.Fatal("registration to self misclassified")
	}
	bad := map[string]func(*Transaction){
		"an amount":           func(x *Transaction) { x.TxData.Amount = 1 },
		"no key":              func(x *Transaction) { x.TxData.Pubkey.ByteValue = nil },
		"no data":             func(x *Transaction) { x.TxData.OptData = nil },
		"data of a odd size":  func(x *Transaction) { x.TxData.OptData = make([]byte, common.AddressLength+1) },
		"a zero spare":        func(x *Transaction) { x.TxData.OptData = make([]byte, common.AddressLength) },
		"an escrow setting":   func(x *Transaction) { x.TxData.EscrowTransactionsDelay = 5 },
		"another recipient":   func(x *Transaction) { x.TxData.Recipient = common.RecoveryBindAddress },
		"a delegated account": func(x *Transaction) { x.TxData.Recipient = common.GetDelegatedAccountAddress(1) },
	}
	for name, spoil := range bad {
		x := commitTx(t, me, spare, c.GetBytes())
		spoil(&x)
		if x.IsCommitmentRegistration() {
			t.Fatalf("a registration with %s counted as a commitment", name)
		}
	}
}

// Nothing else may be sent to the commitment address: coins would be lost and
// a malformed registration would silently commit to nothing.
func TestMalformedCommitmentRegistrationIsRefused(t *testing.T) {
	me, spare := addr(t, 0x10), addr(t, 0x40)
	ok := commitTx(t, me, spare, nil)
	if err := ok.verifyCommitmentShape(); err != nil {
		t.Fatalf("a well-formed commitment registration was refused: %v", err)
	}
	withAmount := commitTx(t, me, spare, nil)
	withAmount.TxData.Amount = 1
	if withAmount.verifyCommitmentShape() == nil {
		t.Fatal("coins sent to the commitment address were accepted")
	}
}

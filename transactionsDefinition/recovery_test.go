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

func TestCommitmentRegistrationShape(t *testing.T) {
	me, c := addr(t, 0x10), addr(t, 0x40)
	if !func() bool { tx := regTx(t, me, c); return tx.IsCommitmentRegistration() && tx.IsKeyRegistration() }() {
		t.Fatal("registration to a commitment not recognised")
	}
	self := regTx(t, me, me)
	if self.IsCommitmentRegistration() || !self.IsKeyRegistration() {
		t.Fatal("registration to self misclassified")
	}
	withAmount := regTx(t, me, c)
	withAmount.TxData.Amount = 1
	if withAmount.IsCommitmentRegistration() {
		t.Fatal("a transfer carrying a key counted as a commitment")
	}
	reserved := regTx(t, me, common.RecoveryBindAddress)
	if reserved.IsCommitmentRegistration() {
		t.Fatal("reserved address accepted as a commitment")
	}
	delegated := regTx(t, me, common.GetDelegatedAccountAddress(1))
	if delegated.IsCommitmentRegistration() {
		t.Fatal("delegated address accepted as a commitment")
	}
}

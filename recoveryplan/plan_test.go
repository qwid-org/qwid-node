package recoveryplan

import (
	"bytes"
	"testing"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
	"github.com/qwid-org/qwid-node/wallet"
)

func TestPlanRecoversTheUnregisteredSlotWithTheCurrentSecret(t *testing.T) {
	w := wallet.NewTestRecoveryWallet(bytes.Repeat([]byte{7}, 64), bytes.Repeat([]byte{3}, common.PubKeyLength(false)))
	c2, _ := w.RecoveryCommitmentAddress(2)
	c3, _ := w.RecoveryCommitmentAddress(3)
	p, err := Make(w, wallet.RegisteredKeys{HasPrimary: false, HasSecondary: true, RecoveryCommit: c2}, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !p.SlotPrimary || p.Next != c3 {
		t.Fatalf("wrong slot or next commitment: %+v", p)
	}
	s2, _ := w.RecoverySecret(2)
	if !bytes.Equal(p.Secret, s2) {
		t.Fatal("not the secret that opens the current commitment")
	}
	id, tag, payload, err := transactionsDefinition.ParseRecoveryBind(p.BindData)
	if err != nil || id != w.MainAddress {
		t.Fatalf("bind data names %v (%v)", id, err)
	}
	wantTag, _ := common.RecoveryTag(s2)
	wantPayload, _ := common.RecoveryPayload(w.MainAddress, p.NewKey.Address, c3, s2)
	if tag != wantTag || payload != wantPayload {
		t.Fatal("bind data does not commit to this reveal")
	}
	if p.BindKey != common.RecoveryBindKey(w.MainAddress, wantTag) {
		t.Fatal("the plan names the wrong bind key")
	}
	if !bytes.Equal(p.RevealOptData(), transactionsDefinition.BuildRecoveryRevealOptData(s2, c3)) {
		t.Fatal("the reveal data does not open this plan's commitment")
	}
}

func TestPlanRefusesWhenNothingToRecover(t *testing.T) {
	w := wallet.NewTestRecoveryWallet(bytes.Repeat([]byte{7}, 64), bytes.Repeat([]byte{3}, common.PubKeyLength(false)))
	c0, _ := w.RecoveryCommitmentAddress(0)
	if _, err := Make(w, wallet.RegisteredKeys{HasPrimary: true, HasSecondary: true, RecoveryCommit: c0}, false, nil); err == nil {
		t.Fatal("planned a recovery with both current keys registered")
	}
	if _, err := Make(w, wallet.RegisteredKeys{}, false, nil); err == nil {
		t.Fatal("planned a recovery without a commitment")
	}
}

// An account whose registered key belongs to the live scheme needs no
// recovery, even though its spare is not registered: the spare stays
// unpublished on purpose, behind its committed address.
func TestNothingToRecoverWithALiveRegisteredKey(t *testing.T) {
	w := wallet.NewTestRecoveryWallet(bytes.Repeat([]byte{7}, 64), bytes.Repeat([]byte{3}, common.PubKeyLength(false)))
	c0, _ := w.RecoveryCommitmentAddress(0)
	var spare common.Address
	spare.ByteValue[0] = 9
	keys := wallet.RegisteredKeys{HasPrimary: true, AnyPrimary: true, RecoveryCommit: c0, SpareCommit: spare}
	if _, err := Make(w, keys, false, nil); err == nil {
		t.Fatal("a recovery was planned for an account whose live-scheme key works")
	}
	// The same account once its primary scheme is paused does need one.
	if _, err := Make(w, keys, true, nil); err != nil && err.Error() == errNothingToRecover.Error() {
		t.Fatal("no recovery offered although the only registered key is paused")
	}
}

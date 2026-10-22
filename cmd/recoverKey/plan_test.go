package main

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
	p, err := planRecovery(w, wallet.RegisteredKeys{HasPrimary: false, HasSecondary: true, RecoveryCommit: c2})
	if err != nil {
		t.Fatal(err)
	}
	if !p.slotPrimary || p.next != c3 {
		t.Fatalf("wrong slot or next commitment: %+v", p)
	}
	s2, _ := w.RecoverySecret(2)
	if !bytes.Equal(p.secret, s2) {
		t.Fatal("not the secret that opens the current commitment")
	}
	id, tag, payload, err := transactionsDefinition.ParseRecoveryBind(p.bindData)
	if err != nil || id != w.MainAddress {
		t.Fatalf("bind data names %v (%v)", id, err)
	}
	wantTag, _ := common.RecoveryTag(s2)
	wantPayload, _ := common.RecoveryPayload(w.MainAddress, p.newKey.Address, c3, s2)
	if tag != wantTag || payload != wantPayload {
		t.Fatal("bind data does not commit to this reveal")
	}
}

func TestPlanRefusesWhenNothingToRecover(t *testing.T) {
	w := wallet.NewTestRecoveryWallet(bytes.Repeat([]byte{7}, 64), bytes.Repeat([]byte{3}, common.PubKeyLength(false)))
	c0, _ := w.RecoveryCommitmentAddress(0)
	if _, err := planRecovery(w, wallet.RegisteredKeys{HasPrimary: true, HasSecondary: true, RecoveryCommit: c0}); err == nil {
		t.Fatal("planned a recovery with both current keys registered")
	}
	if _, err := planRecovery(w, wallet.RegisteredKeys{}); err == nil {
		t.Fatal("planned a recovery without a commitment")
	}
}

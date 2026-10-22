package wallet

import (
	"bytes"
	"testing"

	"github.com/qwid-org/qwid-node/common"
)

func recoveryWallet(seedByte, addrByte byte) *Wallet {
	w := &Wallet{seed: bytes.Repeat([]byte{seedByte}, 64)}
	w.MainAddress.ByteValue[0] = addrByte
	return w
}

func TestRecoverySecretIsDeterministicAndIndexed(t *testing.T) {
	w := recoveryWallet(7, 1)
	s0, err := w.RecoverySecret(0)
	if err != nil || len(s0) != common.RecoverySecretLength {
		t.Fatalf("secret: %v len %d", err, len(s0))
	}
	again, _ := w.RecoverySecret(0)
	s1, _ := w.RecoverySecret(1)
	if !bytes.Equal(s0, again) || bytes.Equal(s0, s1) {
		t.Fatal("secret not deterministic per index")
	}
	if other, _ := recoveryWallet(7, 2).RecoverySecret(0); bytes.Equal(s0, other) {
		t.Fatal("two identities from one phrase share a secret")
	}
	if r, _ := w.RandaoSeed(0); bytes.Equal(r, s0) {
		t.Fatal("recovery secret collides with the RANDAO seed domain")
	}
}

// A scheme break may reveal secret keys, never the phrase: no fallback.
func TestRecoverySecretRequiresThePhrase(t *testing.T) {
	if _, err := (&Wallet{}).RecoverySecret(0); err == nil {
		t.Fatal("a phrase-less wallet produced a recovery secret")
	}
}

func TestFindRecoveryIndex(t *testing.T) {
	w := recoveryWallet(7, 1)
	c3, _ := w.RecoveryCommitmentAddress(3)
	n, err := w.FindRecoveryIndex(c3, 10)
	if err != nil || n != 3 {
		t.Fatalf("found %d, %v; want 3", n, err)
	}
	var unknown common.Address
	unknown.ByteValue[5] = 9
	if _, err := w.FindRecoveryIndex(unknown, 10); err == nil {
		t.Fatal("an unknown commitment was matched")
	}
}

func TestCommitmentForRegistration(t *testing.T) {
	w := recoveryWallet(7, 1)
	c0, _ := w.RecoveryCommitmentAddress(0)
	got, err := w.CommitmentForRegistration(RegisteredKeys{})
	if err != nil || got != c0 {
		t.Fatalf("fresh identity should commit to C_0, got %v %v", got, err)
	}
	var some common.Address
	some.ByteValue[0] = 5
	for _, k := range []RegisteredKeys{{RecoveryCommit: some}, {RecoveryPending: some}} {
		if got, _ := w.CommitmentForRegistration(k); got != w.MainAddress {
			t.Fatalf("existing commitment overwritten: %+v", k)
		}
	}
	if _, err := (&Wallet{}).CommitmentForRegistration(RegisteredKeys{}); err == nil {
		t.Fatal("phrase-less wallet produced a commitment")
	}
}

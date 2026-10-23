package wallet

import (
	"bytes"
	"testing"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/crypto/oqs"
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

// Opening an account: the registration points at the spare key's ADDRESS (the
// wallet's key in the other slot) and carries the recovery commitment C_0.
func TestOpeningCommitments(t *testing.T) {
	w := recoveryWallet(7, 1)
	w.Account1.Address.ByteValue[0] = 0x11
	w.Account2.Address.ByteValue[0] = 0x22
	c0, _ := w.RecoveryCommitmentAddress(0)

	spare, rec, ok := w.OpeningCommitments(RegisteredKeys{}, true)
	if !ok || spare != w.Account2.Address || !bytes.Equal(rec, c0.GetBytes()) {
		t.Fatalf("opening with the primary key: spare %v rec %x ok %v", spare, rec, ok)
	}
	spare, _, _ = w.OpeningCommitments(RegisteredKeys{}, false)
	if spare != w.Account1.Address {
		t.Fatal("opening with the spare-slot key must point at the primary-slot key")
	}
	var some common.Address
	some.ByteValue[0] = 5
	for _, k := range []RegisteredKeys{{RecoveryCommit: some}, {SpareCommit: some}, {RecoveryPending: some}, {SparePending: some}} {
		if _, _, ok := w.OpeningCommitments(k, true); ok {
			t.Fatalf("existing commitments would be overwritten: %+v", k)
		}
	}
	// Without a phrase there is no recovery secret, but the spare still counts.
	nophrase := &Wallet{}
	nophrase.Account2.Address.ByteValue[0] = 0x22
	spare, rec, ok = nophrase.OpeningCommitments(RegisteredKeys{}, true)
	if !ok || spare != nophrase.Account2.Address || rec != nil {
		t.Fatalf("phrase-less opening: spare %v rec %x ok %v", spare, rec, ok)
	}
}

// An identity's first key must be the one its address comes from, and while
// the primary scheme is paused only the spare can sign that first
// registration and then vouch for the primary key. A wallet created during a
// pause whose address came from the (paused) primary key could register that
// key but never add its spare: a paused scheme vouches for nothing. So the
// address comes from the key of the scheme that is live at creation.
func TestMainAddressComesFromTheLiveSchemesKey(t *testing.T) {
	var w Wallet
	w.Account1.Address.ByteValue[0] = 1
	w.Account2.Address.ByteValue[0] = 2

	w.SetMainAddressFromLiveScheme(false)
	if w.MainAddress != w.Account1.Address {
		t.Fatal("with the primary live, the identity must be the primary key's address")
	}
	w.SetMainAddressFromLiveScheme(true)
	if w.MainAddress != w.Account2.Address {
		t.Fatal("with the primary paused, the identity must be the spare key's address")
	}
	if w.Account1.PublicKey.MainAddress != w.MainAddress || w.Account2.PublicKey.MainAddress != w.MainAddress {
		t.Fatal("both keys must name the chosen identity")
	}
}

// Opening an old account means signing with the key its address came from,
// whichever scheme that was - possibly one the chain no longer uses, so the
// wallet no longer holds it as Account1/Account2. The phrase rederives it.
func TestSignWithAddressKeyFindsTheKeyBehindTheAddress(t *testing.T) {
	w := &Wallet{seed: bytes.Repeat([]byte{7}, 64)}
	w.SetPassword("harness-password")
	w.Iv = GenerateNewIv()
	old, err := GenerateNewAccountFromSeed(*w, common.SigName(), true)
	if err != nil {
		t.Skipf("liboqs unavailable: %v", err)
	}
	w.MainAddress = old.Address

	msg := []byte("open me")
	scheme, pub, sig, err := w.SignWithAddressKey(msg, []string{common.SigName2(), common.SigName()})
	if err != nil {
		t.Fatal(err)
	}
	if scheme != common.SigName() || !bytes.Equal(pub, old.PublicKey.GetBytes()) {
		t.Fatalf("found %s key %x, want the %s address key", scheme, pub[:4], common.SigName())
	}
	var v oqs.Signature
	defer v.Clean()
	if err := v.Init(scheme, nil); err != nil {
		t.Fatal(err)
	}
	if ok, err := v.Verify(msg, sig, pub); err != nil || !ok {
		t.Fatal("the signature does not verify against the address key")
	}

	w.MainAddress.ByteValue[0] ^= 1
	if _, _, _, err := w.SignWithAddressKey(msg, []string{common.SigName()}); err == nil {
		t.Fatal("signed although no key hashes to the address")
	}
}

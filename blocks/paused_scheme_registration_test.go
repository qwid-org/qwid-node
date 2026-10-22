package blocks

import (
	"testing"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/crypto/oqs"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
)

// A paused scheme is paused because it is presumed broken: whoever can forge
// its signatures can sign as anyone whose key of that scheme is published, and
// a registered key IS published. So a signature under the paused scheme must
// authorise nothing a forger could produce against a registered key.
//
// The stranded-identity escape hatch (incident 2026-09-08) broke that: a pure
// registration of a key in a slot the sender did not yet hold, signed with the
// paused primary, was admitted. The attacker encloses its OWN spare key, names
// the victim, forges the victim's primary signature, and from then on signs
// with the live spare as the victim.

// secondaryKey generates a key of the secondary scheme. Its address is the one
// it derives; whose identity it serves is decided by registration.
func secondaryKey(t *testing.T) stageBKey {
	t.Helper()
	var k stageBKey
	if err := k.s.Init(common.SigName2(), nil); err != nil {
		t.Skipf("liboqs unavailable: %v", err)
	}
	var err error
	if k.pub, err = k.s.GenerateKeyPair(); err != nil {
		t.Fatal(err)
	}
	if k.addr, err = common.PubKeyToAddress(k.pub, false); err != nil {
		t.Fatal(err)
	}
	return k
}

// enclosed is k's public key naming identity, as a registration carries it.
func enclosed(t *testing.T, k stageBKey, identity common.Address, primary bool) common.PubKey {
	t.Helper()
	var pk common.PubKey
	if err := pk.Init(k.pub, identity); err != nil {
		t.Fatal(err)
	}
	pk.Primary = primary
	pk.Address = k.addr
	pk.MainAddress = identity
	return pk
}

// pureRegistration encloses pk in a transaction from identity to itself, with
// no amount and no data, signed with signer in the given slot.
func pureRegistration(t *testing.T, identity common.Address, pk common.PubKey, signer stageBKey, signPrimary bool) transactionsDefinition.Transaction {
	t.Helper()
	tx := transactionsDefinition.Transaction{
		TxParam: transactionsDefinition.TxParam{ChainID: common.GetChainID(), Sender: identity, SendingTime: 1, Nonce: 7},
		TxData:  transactionsDefinition.TxData{Recipient: identity, Pubkey: pk},
		Height:  common.GetHeight(), GasPrice: 1, GasUsage: 1_000_000,
	}
	signIn(t, &tx, signer, signPrimary)
	return tx
}

func signIn(t *testing.T, tx *transactionsDefinition.Transaction, signer stageBKey, primary bool) {
	t.Helper()
	if err := tx.CalcHashAndSet(); err != nil {
		t.Fatal(err)
	}
	raw, err := signer.s.Sign(tx.Hash.GetBytes())
	if err != nil {
		t.Fatal(err)
	}
	flag := byte(1)
	if primary {
		flag = 0
	}
	sig, err := common.GetSignatureFromBytes(append([]byte{flag}, raw...), signer.addr)
	if err != nil {
		t.Fatal(err)
	}
	tx.Signature = sig
}

func registerKey(t *testing.T, pk common.PubKey) {
	t.Helper()
	if err := registerPubKeyAtHeight(pk, 0); err != nil {
		t.Fatal(err)
	}
}

const primaryPaused, secondaryLive = true, false

// The attack. In the test the "forged" primary signature is made with the
// victim's real key — exactly what a forger of the broken scheme produces.
func TestPausedPrimaryCannotAttachAForeignSpare(t *testing.T) {
	victim := primaryOnlyStageBKey(t)
	attacker := secondaryKey(t)

	hijack := pureRegistration(t, victim.addr, enclosed(t, attacker, victim.addr, false), victim, true)
	if hijack.Verify(common.SigName(), common.SigName2(), primaryPaused, secondaryLive) {
		t.Fatal("a signature under the PAUSED primary attached a foreign spare key to the victim's identity")
	}
}

// Outside a pause the same transaction is the legitimate way an identity adds
// its spare: authorised by a key already registered to it.
func TestLivePrimaryAuthorisesTheSpare(t *testing.T) {
	owner := primaryOnlyStageBKey(t)
	spare := secondaryKey(t)

	reg := pureRegistration(t, owner.addr, enclosed(t, spare, owner.addr, false), owner, true)
	if !reg.Verify(common.SigName(), common.SigName2(), false, true) {
		t.Fatal("the live primary could not register the identity's spare")
	}
}

// A forger of the paused scheme must not even be able to re-register the
// victim's own published key: harmless as a binding, but every such
// transaction burns the victim's gas.
func TestPausedPrimaryCannotReRegisterAPublishedKey(t *testing.T) {
	victim := primaryOnlyStageBKey(t)
	again := pureRegistration(t, victim.addr, enclosed(t, victim, victim.addr, true), victim, true)
	if again.Verify(common.SigName(), common.SigName2(), primaryPaused, secondaryLive) {
		t.Fatal("a paused-scheme signature over an already published key was admitted")
	}
}

// Self-registration of a key nobody has seen stays admitted under a pause:
// forging it needs a preimage of the address, not a signature forgery.
func TestPausedPrimaryStillBootstrapsAnUnpublishedKey(t *testing.T) {
	registeredStageBKey(t) // fresh registry
	var k stageBKey
	if err := k.s.Init(common.SigName(), nil); err != nil {
		t.Skipf("liboqs unavailable: %v", err)
	}
	var err error
	if k.pub, err = k.s.GenerateKeyPair(); err != nil {
		t.Fatal(err)
	}
	if k.addr, err = common.PubKeyToAddress(k.pub, true); err != nil {
		t.Fatal(err)
	}
	reg := pureRegistration(t, k.addr, enclosed(t, k, k.addr, true), k, true)
	if !reg.Verify(common.SigName(), common.SigName2(), primaryPaused, secondaryLive) {
		t.Fatal("an unpublished key could not register itself under a pause")
	}
}

// Every identity must hold BOTH keys before it can do anything but register
// them, so that when one scheme breaks a second, independent key exists to
// authorise the replacement — no identity is left with only a forgeable key.
func TestTransactionsRequireBothKeys(t *testing.T) {
	owner := primaryOnlyStageBKey(t)
	fund(owner.addr)

	transfer := signedTx(t, owner, testAddress(0x55), 1, common.GetHeight(), 3)
	if verifyNow(transfer) {
		t.Fatal("an identity holding only its primary key sent a transfer")
	}

	spare := secondaryKey(t)
	registerKey(t, enclosed(t, spare, owner.addr, false))
	if !verifyNow(transfer) {
		t.Fatal("an identity holding both keys could not send a transfer")
	}
}

// A key may still ride along a transfer, but the transfer itself is subject to
// the rule: registering the spare is a pure registration.
func TestSpareCannotRideAlongTheFirstTransfer(t *testing.T) {
	owner := primaryOnlyStageBKey(t)
	fund(owner.addr)
	spare := secondaryKey(t)

	tx := transactionsDefinition.Transaction{
		TxParam: transactionsDefinition.TxParam{ChainID: common.GetChainID(), Sender: owner.addr, SendingTime: 1, Nonce: 9},
		TxData:  transactionsDefinition.TxData{Recipient: testAddress(0x56), Amount: 1, Pubkey: enclosed(t, spare, owner.addr, false)},
		Height:  common.GetHeight(), GasPrice: 1, GasUsage: 1_000_000,
	}
	signIn(t, &tx, owner, true)
	if verifyNow(tx) {
		t.Fatal("a transfer from an identity without its spare was admitted because it carried the spare")
	}
}

// A replacement scheme has to be authorised by the identity's other key. With
// both keys held that is always possible: the spare signs for the new primary.
func TestSpareAuthorisesReplacementPrimary(t *testing.T) {
	owner := registeredStageBKey(t)
	if owner.spare == nil {
		t.Fatal("registeredStageBKey must register both keys")
	}
	// A second key of the primary scheme stands in for the replacement's key:
	// what matters is that it is new and is vouched for by the spare.
	var next stageBKey
	if err := next.s.Init(common.SigName(), nil); err != nil {
		t.Skipf("liboqs unavailable: %v", err)
	}
	var err error
	if next.pub, err = next.s.GenerateKeyPair(); err != nil {
		t.Fatal(err)
	}
	if next.addr, err = common.PubKeyToAddress(next.pub, true); err != nil {
		t.Fatal(err)
	}
	if _, err := oqs.PubKeyLength(common.SigName2()); err != nil {
		t.Skip(err)
	}
	reg := pureRegistration(t, owner.addr, enclosed(t, next, owner.addr, true), *owner.spare, false)
	if !reg.Verify(common.SigName(), common.SigName2(), primaryPaused, secondaryLive) {
		t.Fatal("the live spare could not authorise a new primary key while the primary is paused")
	}
}

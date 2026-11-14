package blocks

import (
	"bytes"
	"testing"

	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
	"github.com/qwid-org/qwid-node/pubkeys"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
)

// P-01. A key that joins an identity on the strength of ANOTHER key's
// signature is only as trustworthy as that signature. If the signing scheme is
// marked broken within RecoveryCommitMaturityBlocks, the signature may have
// been a forgery, so the block that marks the break voids the key - exactly as
// it voids unmatured commitments. Without this a forger of the primary scheme
// attached its own spare to any identity before the pause, and after it held a
// legitimate key of the live scheme: the newest in the slot, so it signed
// blocks as the validator and the validator's own signatures stopped verifying.

func applyRegistration(t *testing.T, tx transactionsDefinition.Transaction, height int64) {
	t.Helper()
	if err := tx.StoreToDBPoolTx(common.TransactionPoolHashesDBPrefix[:]); err != nil {
		t.Fatal(err)
	}
	bl := Block{BaseBlock: BaseBlock{BaseHeader: BaseHeader{Height: height}}, TransactionsHashes: []common.Hash{tx.Hash}}
	if err := ProcessBlockPubKey(bl); err != nil {
		t.Fatal(err)
	}
}

func pausePrimaryAt(t *testing.T, height int64) {
	t.Helper()
	applyRecoveryMaintenance(blockWithEnc(height, falcon512(t, true), mayo5(t)), blockWithEnc(height-1, falcon512(t, false), mayo5(t)))
}

func secondaryAsOf(t *testing.T, id common.Address, asOf int64) []byte {
	t.Helper()
	pk, err := pubkeys.LoadPubKeyWithPrimaryOfLengthAsOf(id, false, common.PubKeyLength2(false), asOf)
	if err != nil {
		return nil
	}
	return pk.GetBytes()
}

// plantedSpare: the attacker's secondary key registered under victim at
// height 100 by a transaction signed in the primary slot (a forgery, made in
// the test with the victim's real key).
func plantedSpare(t *testing.T, victim stageBKey) stageBKey {
	t.Helper()
	attacker := secondaryKey(t)
	plant := pureRegistration(t, victim.addr, enclosed(t, attacker, victim.addr, false), victim, true)
	if !verifyNow(plant) {
		t.Fatal("setup: the live primary did not authorise a new spare")
	}
	applyRegistration(t, plant, 100)
	if !bytes.Equal(secondaryAsOf(t, victim.addr, 100), attacker.pub) {
		t.Fatal("setup: the planted key is not the identity's newest spare")
	}
	return attacker
}

func TestKeyPlantedBeforeAPauseIsVoidedByIt(t *testing.T) {
	logger.InitLogger()
	victim := registeredStageBKey(t)
	fund(victim.addr)
	attacker := plantedSpare(t, victim)

	pausePrimaryAt(t, 101)

	for _, asOf := range []int64{101, 5000, pubkeys.NoHeightLimit} {
		if got := secondaryAsOf(t, victim.addr, asOf); !bytes.Equal(got, victim.spare.pub) {
			t.Fatalf("as of %d the identity's spare is not the validator's own key (planted key in force: %v)",
				asOf, bytes.Equal(got, attacker.pub))
		}
	}
	// History is not rewritten: the block that carries the pause was itself
	// judged against the registry as of its parent.
	if !bytes.Equal(secondaryAsOf(t, victim.addr, 100), attacker.pub) {
		t.Fatal("the registry as of the block before the break changed")
	}
}

// A key registered long enough before the break is as good as a matured
// commitment.
func TestKeyOlderThanMaturitySurvivesABreak(t *testing.T) {
	logger.InitLogger()
	victim := registeredStageBKey(t)
	fund(victim.addr)
	added := plantedSpare(t, victim)
	at := 100 + common.RecoveryCommitMaturityBlocks
	pausePrimaryAt(t, at)
	if !bytes.Equal(secondaryAsOf(t, victim.addr, at), added.pub) {
		t.Fatal("a key registered a full maturity period before the break was voided")
	}
}

// The spare an identity committed to (in force - so set at opening or matured)
// is not the attacker's choice, whoever signed its registration.
func TestCommittedSpareSurvivesABreak(t *testing.T) {
	logger.InitLogger()
	owner := primaryOnlyStageBKey(t)
	fund(owner.addr)
	spare := secondaryKey(t)
	acc := account.Accounts.AllAccounts[owner.addr.ByteValue]
	acc.SpareCommit = spare.addr.ByteValue
	account.Accounts.AllAccounts[owner.addr.ByteValue] = acc
	reg := pureRegistration(t, owner.addr, enclosed(t, spare, owner.addr, false), owner, true)
	applyRegistration(t, reg, 100)
	pausePrimaryAt(t, 101)
	if !bytes.Equal(secondaryAsOf(t, owner.addr, 101), spare.pub) {
		t.Fatal("the committed spare was voided by the break")
	}
}

// A rewind below the break takes the voiding back with it.
func TestRewindBelowTheBreakRestoresTheKey(t *testing.T) {
	logger.InitLogger()
	victim := registeredStageBKey(t)
	fund(victim.addr)
	attacker := plantedSpare(t, victim)
	pausePrimaryAt(t, 101)
	UnregisterPubKeysAboveHeight(100, 101)
	if !bytes.Equal(secondaryAsOf(t, victim.addr, pubkeys.NoHeightLimit), attacker.pub) {
		t.Fatal("after rewinding the break the key registered at 100 is still voided")
	}
}

// A voided key can come back through a path that needs no signature of the
// broken scheme (committed spare, reveal). It then counts from the new height,
// and rewinding that block leaves it voided again, not deleted.
func TestVoidedKeyCanBeRegisteredAgain(t *testing.T) {
	logger.InitLogger()
	victim := registeredStageBKey(t)
	fund(victim.addr)
	key := plantedSpare(t, victim)
	pausePrimaryAt(t, 101)

	if err := registerPubKey(enclosed(t, key, victim.addr, false), 200, false); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(secondaryAsOf(t, victim.addr, 199), key.pub) {
		t.Fatal("the key is in force before it was registered again")
	}
	if !bytes.Equal(secondaryAsOf(t, victim.addr, 200), key.pub) {
		t.Fatal("a voided key registered again is not in force")
	}
	UnregisterPubKeysAboveHeight(150, 200)
	if !bytes.Equal(secondaryAsOf(t, victim.addr, pubkeys.NoHeightLimit), victim.spare.pub) {
		t.Fatal("rewinding the second registration did not leave the key voided")
	}
	if !pubkeys.IsRegisteredUnder(victim.addr, key.addr) || pubkeys.RegistrationHeight(key.addr.GetBytes()) != 100 {
		t.Fatal("rewinding the second registration lost the first one's record")
	}
}

// Voided keys do not use up the identity's key allowance - a forger could
// otherwise fill it and leave no room for the owner's next key.
func TestVoidedKeysDoNotCountAgainstTheKeyLimit(t *testing.T) {
	logger.InitLogger()
	victim := registeredStageBKey(t)
	fund(victim.addr)
	for i := 2; i < common.MaxKeysPerIdentity; i++ {
		if err := registerPubKey(enclosed(t, secondaryKey(t), victim.addr, false), 100, true); err != nil {
			t.Fatal(err)
		}
	}
	pausePrimaryAt(t, 101)
	if err := registerPubKey(enclosed(t, secondaryKey(t), victim.addr, false), 102, false); err != nil {
		t.Fatalf("the owner cannot register a key after the planted ones were voided: %v", err)
	}
}

// The producer of a pausing block signs the next ones with the scheme that
// becomes active, so it must hold a key of it that the pause itself does not
// void - and, like every consensus rule, as of the parent block.
func TestPauseProducerNeedsAKeyThePauseDoesNotVoid(t *testing.T) {
	logger.InitLogger()
	primary := func(paused bool) []byte {
		return encCfg(t, common.SigName(), common.PubKeyLength(false), common.PrivateKeyLength(), common.SignatureLength(false), paused)
	}
	spare := encCfg(t, common.SigName2(), common.PubKeyLength2(false), common.PrivateKeyLength2(), common.SignatureLength2(false), false)
	parent := blockWithEnc(100, primary(false), spare)
	pausing := func(op common.Address) error {
		b := blockWithEnc(101, primary(true), spare)
		b.BaseBlock.BaseHeader.OperatorAccount = op
		return checkPauseLeavesRegisteredKey(b, parent, primary(true), true)
	}

	settled := registeredStageBKey(t) // spare registered at height 0
	if err := pausing(settled.addr); err != nil {
		t.Fatalf("a producer with a settled spare was refused: %v", err)
	}

	recent := primaryOnlyStageBKey(t)
	if err := registerPubKey(enclosed(t, secondaryKey(t), recent.addr, false), 100, true); err != nil {
		t.Fatal(err)
	}
	if err := pausing(recent.addr); err == nil {
		t.Fatal("a producer whose only spare the pause voids was accepted")
	}

	late := primaryOnlyStageBKey(t)
	if err := registerPubKey(enclosed(t, secondaryKey(t), late.addr, false), 101, false); err != nil {
		t.Fatal(err)
	}
	if err := pausing(late.addr); err == nil {
		t.Fatal("a spare registered by the pausing block itself counted")
	}
}

// P-07: a header is judged against the key registry as of its parent, like
// everything else in consensus - a key the producer registers in a later block
// (or one left over from an abandoned apply) does not count.
func TestHeaderIsVerifiedAgainstKeysAsOfItsParent(t *testing.T) {
	k, parent := headerTestSetup(t)
	bl := signedTestBlock(t, k, 10, parent, common.Hash{})
	h := bl.GetHeader()
	if !h.Verify(common.SigName(), common.SigName2(), common.IsPaused(), common.IsPaused2()) {
		t.Fatal("setup: a header signed with a key registered before the parent was refused")
	}
	if err := pubkeys.StoreRegistrationHeight(k.addr, 10); err != nil {
		t.Fatal(err)
	}
	if h.Verify(common.SigName(), common.SigName2(), common.IsPaused(), common.IsPaused2()) {
		t.Fatal("a header verified against a key registered after its parent block")
	}
}

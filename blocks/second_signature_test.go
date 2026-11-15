package blocks

import (
	"testing"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/pubkeys"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
)

// Second signature on validator nonces (audit 2026-11-14): a validator holding
// an eligible spare key must sign its nonce with BOTH schemes for its vote and
// price to count - forging them then takes breaking both schemes.

// pricedNonce is a validator nonce for delegated account 1 carrying a price,
// signed with the primary key only.
func pricedNonce(t *testing.T, k stageBKey, height, price int64) transactionsDefinition.Transaction {
	t.Helper()
	tx := *nonceTxFor(1, height, price, 0)
	tx.TxParam = transactionsDefinition.TxParam{ChainID: common.GetChainID(), Sender: k.addr, SendingTime: 1}
	tx.TxData.OptData = append(tx.TxData.OptData, common.BytesToLenAndBytes(nil)...)
	tx.TxData.OptData = append(tx.TxData.OptData, common.BytesToLenAndBytes(nil)...)
	k.sign(t, &tx)
	return tx
}

func blockWithProofs(parent Block, proofs ...transactionsDefinition.Transaction) Block {
	blk := childOf(parent)
	blk.BaseBlock.BaseHeader.Encryption1 = parent.BaseBlock.BaseHeader.Encryption1
	blk.BaseBlock.BaseHeader.Encryption2 = parent.BaseBlock.BaseHeader.Encryption2
	subs := map[uint8]oracleSubmission{}
	for _, p := range proofs {
		p := p
		blk.BaseBlock.OracleProofs = append(blk.BaseBlock.OracleProofs, p.GetBytes())
		id, sub, _ := extractOracleSubmission(&p)
		subs[id] = sub
	}
	blk.BaseBlock.PriceOracleData = encodeOracleData(subs)
	return blk
}

func TestSingleSignedPriceOfAValidatorWithASpareDoesNotCount(t *testing.T) {
	k := registeredStageBKey(t) // primary and spare, both registered at genesis (eligible)
	fund(k.addr)
	parent := parentAt(t, 99)
	blk := blockWithProofs(parent, pricedNonce(t, k, 100, 60_000))
	if err := AuthenticateOracleProofs(blk, parent); err == nil {
		t.Fatal("a price signed with the primary scheme alone counted, although its validator holds a spare key")
	}
}

// signSecond adds the second signature, made with spare, then signs the whole
// nonce with k's primary key.
func signSecond(t *testing.T, k stageBKey, spare stageBKey, tx *transactionsDefinition.Transaction) {
	t.Helper()
	msg, err := transactionsDefinition.NonceSecondSignatureMessage(*tx)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := spare.s.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := transactionsDefinition.SetNonceSecondSignature(tx, append([]byte{1}, raw...)); err != nil {
		t.Fatal(err)
	}
	k.sign(t, tx)
}

func TestDualSignedPriceCounts(t *testing.T) {
	k := registeredStageBKey(t)
	fund(k.addr)
	parent := parentAt(t, 99)
	tx := pricedNonce(t, k, 100, 60_000)
	signSecond(t, k, *k.spare, &tx)
	if err := AuthenticateOracleProofs(blockWithProofs(parent, tx), parent); err != nil {
		t.Fatalf("a dual-signed price was refused: %v", err)
	}
}

// A proof that does not count is no reason to refuse the block: it is simply
// left out of the price.
func TestNonCountingProofLeavesTheBlockValid(t *testing.T) {
	k := registeredStageBKey(t)
	fund(k.addr)
	parent := parentAt(t, 99)
	blk := blockWithProofs(parent, pricedNonce(t, k, 100, 60_000))
	blk.BaseBlock.PriceOracleData = []byte{}
	if err := AuthenticateOracleProofs(blk, parent); err != nil {
		t.Fatalf("a block carrying a proof that does not count was refused: %v", err)
	}
}

// A validator whose spare key does not qualify yet (registered on the
// primary's word, recently) still counts with one signature.
func TestValidatorWithoutAnEligibleSpareCountsSingleSigned(t *testing.T) {
	k := primaryOnlyStageBKey(t)
	spare := secondaryKey(t)
	if err := registerPubKey(enclosed(t, spare, k.addr, false), 95, true); err != nil {
		t.Fatal(err)
	}
	fund(k.addr)
	parent := parentAt(t, 99)
	if err := AuthenticateOracleProofs(blockWithProofs(parent, pricedNonce(t, k, 100, 60_000)), parent); err != nil {
		t.Fatalf("a validator with no eligible spare could not price with one signature: %v", err)
	}
}

// The attack the eligibility rule stops: with the primary broken, an attacker
// attaches its own fresh spare to the victim and dual-signs with it.
func TestSubstitutedSpareKeyDoesNotCount(t *testing.T) {
	k := registeredStageBKey(t) // the honest spare is eligible
	fund(k.addr)
	planted := secondaryKey(t)
	if err := registerPubKey(enclosed(t, planted, k.addr, false), 98, true); err != nil {
		t.Fatal(err)
	}
	parent := parentAt(t, 99)
	tx := pricedNonce(t, k, 100, 60_000)
	signSecond(t, k, planted, &tx)
	if err := AuthenticateOracleProofs(blockWithProofs(parent, tx), parent); err == nil {
		t.Fatal("a second signature by a freshly planted spare key counted")
	}
}

func votedNonce(t *testing.T, k stageBKey, height int64, vote1 []byte, dual bool) transactionsDefinition.Transaction {
	t.Helper()
	tx := *nonceTxFor(1, height, 0, 0)
	tx.TxParam = transactionsDefinition.TxParam{ChainID: common.GetChainID(), Sender: k.addr, SendingTime: 1}
	tx.TxData.OptData = append(tx.TxData.OptData, common.BytesToLenAndBytes(vote1)...)
	tx.TxData.OptData = append(tx.TxData.OptData, common.BytesToLenAndBytes(nil)...)
	if dual {
		tx.TxData.OptData = append(tx.TxData.OptData, common.BytesToLenAndBytes(nil)...)
		signSecond(t, k, *k.spare, &tx)
	} else {
		k.sign(t, &tx)
	}
	return tx
}

func TestVotesCountOnlyDualSigned(t *testing.T) {
	k := registeredStageBKey(t)
	fund(k.addr)
	parent := parentAt(t, 99)
	want := []byte("some-scheme-config")
	counts := func(tx *transactionsDefinition.Transaction) bool { return proofCounts(tx, parent) }
	stake := func(int) int64 { return 1000 }
	for _, c := range []struct {
		dual bool
		want int64
	}{{false, 0}, {true, 1000}} {
		p := votedNonce(t, k, 100, want, c.dual)
		got, err := tallyEncryptionVotes([][]byte{p.GetBytes()}, true, want, decodeProof, stake, counts)
		if err != nil {
			t.Fatal(err)
		}
		if got != c.want {
			t.Fatalf("dual=%v: %d staked counted, want %d", c.dual, got, c.want)
		}
	}
}

func TestProducerLeavesOutProofsThatDoNotCount(t *testing.T) {
	k := registeredStageBKey(t)
	fund(k.addr)
	parent := parentAt(t, 99)
	single := pricedNonce(t, k, 100, 60_000)
	if got := filterPausedProofs([][]byte{single.GetBytes()}, parent); len(got) != 0 {
		t.Fatal("the producer kept a proof that does not count")
	}
	dual := pricedNonce(t, k, 100, 60_000)
	signSecond(t, k, *k.spare, &dual)
	if got := filterPausedProofs([][]byte{dual.GetBytes()}, parent); len(got) != 1 {
		t.Fatal("the producer left out a dual-signed proof")
	}
}

func TestSpareRegisteredOnAnotherKeysWordQualifiesAfterItsAge(t *testing.T) {
	k := primaryOnlyStageBKey(t)
	spare := secondaryKey(t)
	pk := enclosed(t, spare, k.addr, false)
	if err := registerPubKey(pk, 1000, true); err != nil {
		t.Fatal(err)
	}
	n := len(pk.GetBytes())
	if got := pubkeys.SecondFactorKeysAsOf(k.addr, false, n, 1000+common.SecondFactorKeyAgeBlocks-1); len(got) != 0 {
		t.Fatal("a spare registered on the primary's word qualified before its age")
	}
	if got := pubkeys.SecondFactorKeysAsOf(k.addr, false, n, 1000+common.SecondFactorKeyAgeBlocks); len(got) != 1 {
		t.Fatal("the spare did not qualify once old enough")
	}
}

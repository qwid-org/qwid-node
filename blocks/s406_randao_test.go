package blocks

import (
	"bytes"
	"testing"

	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/common"
)

func seedOf(b byte) []byte { return bytes.Repeat([]byte{b}, randaoSeedLength) }

// randaoBlock is a block at height on top of parent carrying the RANDAO fields
// an honest producer computes for (reveal, nextSeed).
func randaoBlock(parent Block, height int64, operator common.Address, reveal, nextSeed []byte) Block {
	b := Block{BaseBlock: BaseBlock{BaseHeader: BaseHeader{
		Height:           height,
		DelegatedAccount: common.GetDelegatedAccountAddress(1),
		OperatorAccount:  operator,
	}}}
	b.BaseBlock.RandReveal = reveal
	b.BaseBlock.RandCommit, b.BaseBlock.RandMix, b.BaseBlock.RandOracle = RandaoFields(parent, height, reveal, nextSeed)
	return b
}

func randaoParent(height int64) Block {
	p := Block{BaseBlock: BaseBlock{BaseHeader: BaseHeader{Height: height}}}
	p.BaseBlock.RandMix = common.GetHashFromBytes(bytes.Repeat([]byte{0x3C}, 32))
	p.BlockHash = common.GetHashFromBytes(bytes.Repeat([]byte{0x4D}, 32))
	return p
}

// withOperatorCommit gives operator a staking entry in delegated account 1
// holding a RANDAO commitment to seed made at commitHeight (0: none).
func withOperatorCommit(t *testing.T, operator common.Address, seed []byte, commitHeight int64) {
	t.Helper()
	saved := account.StakingAccounts
	t.Cleanup(func() { account.StakingAccounts = saved })
	account.StakingAccounts = [256]account.StakingAccountsType{}
	for i := range account.StakingAccounts {
		account.StakingAccounts[i] = account.StakingAccountsType{AllStakingAccounts: map[[common.AddressLength]byte]account.StakingAccount{}}
	}
	sa := account.StakingAccount{Address: operator.ByteValue, StakedBalance: 1, OperationalAccount: true}
	if commitHeight > 0 {
		copy(sa.RandCommit[:], RandaoCommitment(seed).GetBytes())
		sa.RandCommitHeight = commitHeight
	}
	account.StakingAccounts[1].AllStakingAccounts[operator.ByteValue] = sa
}

func TestRandaoStatelessRules(t *testing.T) {
	parent := randaoParent(9)
	op := testAddress(0x91)
	good := randaoBlock(parent, 10, op, seedOf(1), seedOf(2))
	if err := verifyRandaoStateless(good, parent); err != nil {
		t.Fatalf("an honest block was rejected: %v", err)
	}

	tamper := func(name string, edit func(b *Block)) {
		t.Helper()
		b := randaoBlock(parent, 10, op, seedOf(1), seedOf(2))
		edit(&b)
		if verifyRandaoStateless(b, parent) == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
	tamper("a mix not following from the reveal", func(b *Block) { b.BaseBlock.RandReveal = seedOf(9) })
	tamper("a chosen mix", func(b *Block) { b.BaseBlock.RandMix[0] ^= 1 })
	tamper("a RAND not derived from the mix", func(b *Block) { b.BaseBlock.RandOracle++ })
	tamper("a short reveal", func(b *Block) { b.BaseBlock.RandReveal = []byte{1, 2, 3} })
	tamper("a missing commitment", func(b *Block) { b.BaseBlock.RandCommit = common.Hash{} })
	tamper("validator rand data", func(b *Block) { b.BaseBlock.RandOracleData = []byte{1} })
}

// Block 1 builds on the genesis block's hash.
func TestRandaoStartsFromGenesisHash(t *testing.T) {
	genesis := randaoParent(0)
	b := randaoBlock(genesis, 1, testAddress(0x92), nil, seedOf(3))
	if b.BaseBlock.RandMix != mixHash(genesis.BlockHash, 1, nil) {
		t.Fatal("block 1 must mix onto the genesis block hash")
	}
	if err := verifyRandaoStateless(b, genesis); err != nil {
		t.Fatal(err)
	}
}

// The RAND an EVM contract sees is non-negative: the precompile clamps
// negatives to zero, which would make half of all values 0.
func TestRandFromMixIsNonNegative(t *testing.T) {
	for i := 0; i < 256; i++ {
		if r := randFromMix(mixHash(common.Hash{}, int64(i), nil)); r < 0 {
			t.Fatalf("negative RAND %d", r)
		}
	}
}

// The reveal is checked against the commitment the chain holds: a producer
// with a live commitment must open it, and can open it only one way.
func TestRandaoRevealMustOpenTheCommitment(t *testing.T) {
	parent := randaoParent(9)
	op := testAddress(0x93)
	withOperatorCommit(t, op, seedOf(5), 5)

	if err := verifyRandaoReveal(randaoBlock(parent, 10, op, seedOf(5), seedOf(6))); err != nil {
		t.Fatalf("the committed seed was rejected: %v", err)
	}
	if verifyRandaoReveal(randaoBlock(parent, 10, op, nil, seedOf(6))) == nil {
		t.Fatal("withholding a due reveal was accepted")
	}
	if verifyRandaoReveal(randaoBlock(parent, 10, op, seedOf(7), seedOf(6))) == nil {
		t.Fatal("a seed other than the committed one was accepted")
	}
}

func TestRandaoCommitmentLapses(t *testing.T) {
	op := testAddress(0x94)
	withOperatorCommit(t, op, seedOf(5), 5)
	last := 5 + common.RandaoCommitExpiry
	if err := verifyRandaoReveal(randaoBlock(randaoParent(last-1), last, op, seedOf(5), seedOf(6))); err != nil {
		t.Fatalf("the reveal is due through the expiry height: %v", err)
	}
	after := randaoBlock(randaoParent(last), last+1, op, nil, seedOf(6))
	if err := verifyRandaoReveal(after); err != nil {
		t.Fatalf("a lapsed commitment must not block production: %v", err)
	}
	if verifyRandaoReveal(randaoBlock(randaoParent(last), last+1, op, seedOf(5), seedOf(6))) == nil {
		t.Fatal("a reveal of a lapsed commitment must be refused: it would give the producer a choice")
	}
}

// An operator without a commitment contributes nothing - and may not pick a
// value to contribute.
func TestRandaoWithoutCommitmentTakesNoReveal(t *testing.T) {
	op := testAddress(0x95)
	withOperatorCommit(t, op, nil, 0)
	if err := verifyRandaoReveal(randaoBlock(randaoParent(9), 10, op, nil, seedOf(1))); err != nil {
		t.Fatal(err)
	}
	if verifyRandaoReveal(randaoBlock(randaoParent(9), 10, op, seedOf(4), seedOf(1))) == nil {
		t.Fatal("a reveal without a commitment was accepted")
	}
}

// Applying a block records its commitment; the operator's next block must
// open exactly that one.
func TestRandaoApplyRecordsTheNewCommitment(t *testing.T) {
	op := testAddress(0x96)
	withOperatorCommit(t, op, seedOf(5), 5)
	b10 := randaoBlock(randaoParent(9), 10, op, seedOf(5), seedOf(6))
	if err := applyRandaoCommit(b10); err != nil {
		t.Fatal(err)
	}
	commit, h := account.GetRandCommit(1, op.ByteValue)
	if h != 10 || !bytes.Equal(commit[:], RandaoCommitment(seedOf(6)).GetBytes()) {
		t.Fatalf("commitment not recorded: height %d", h)
	}
	if verifyRandaoReveal(randaoBlock(b10, 11, op, seedOf(5), seedOf(7))) == nil {
		t.Fatal("re-revealing the opened seed was accepted")
	}
	if err := verifyRandaoReveal(randaoBlock(b10, 11, op, seedOf(6), seedOf(7))); err != nil {
		t.Fatalf("the new commitment does not open: %v", err)
	}
}

func TestRandaoFieldsRoundTrip(t *testing.T) {
	k, parent := headerTestSetup(t)
	for _, reveal := range [][]byte{nil, seedOf(8)} {
		b := signedTestBlock(t, k, 10, parent, common.Hash{})
		b.BaseBlock.RandReveal = reveal
		got, err := Block{}.GetFromBytes(b.GetBytes())
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if !bytes.Equal(got.BaseBlock.RandReveal, reveal) || got.BaseBlock.RandCommit != b.BaseBlock.RandCommit || got.BaseBlock.RandMix != b.BaseBlock.RandMix {
			t.Fatal("RANDAO fields lost in serialization")
		}
		if !bytes.Equal(got.BaseBlock.bodyBytes(), b.BaseBlock.bodyBytes()) {
			t.Fatal("the body hash input changed across serialization")
		}
	}
}

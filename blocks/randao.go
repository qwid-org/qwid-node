package blocks

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/common"
)

// RANDAO: the chain's randomness as a commit-reveal accumulator (S4-06).
//
// RAND used to be the hash of the validator proposals a producer chose to
// embed. Any subset carrying more than 2/3 of the stake verified, so the
// producer could grind subsets for the RAND it liked - or embed too little and
// publish 0. Commit-reveal among the validators would not have fixed it: the
// producer would still pick which reveals to include, since nodes see
// different gossip and no rule can demand a reveal a validator never saw.
//
// So every block mixes exactly one contribution, its producer's own:
//
//	block H by operator O:
//	  RandReveal = seed whose commitment O recorded in the last block it
//	               produced (required while that commitment is younger than
//	               RandaoCommitExpiry; empty when O has none or it lapsed)
//	  RandCommit = commitment to the seed O will reveal in its next block
//	  RandMix    = mixHash(parentMix, H, RandReveal)
//	  RandOracle = randFromMix(RandMix)
//
// The seed was fixed before O could know the parent mix, and the reveal is
// checked against the chain's record, so O's only lever is whether to produce
// at all: one bit per block, paid for with the block reward. RandOracle is
// derived from the block's OWN mix, so a transaction cannot be placed knowing
// the value it will see.
//
// Seeds derive from the producer's wallet secret and the commitment height
// (wallet.RandaoSeed), so a restart or rewind never loses them.

const (
	randaoMixDomain    = "QWID-RANDAO-mix-v1"
	randaoCommitDomain = "QWID-RANDAO-commit-v1"
	randaoRandDomain   = "QWID-RAND-v1"
	randaoSeedLength   = common.HashLength
)

func domainHash(domain string, parts ...[]byte) common.Hash {
	b := append([]byte{}, common.BytesToLenAndBytes([]byte(domain))...)
	for _, p := range parts {
		b = append(b, common.BytesToLenAndBytes(p)...)
	}
	h, err := common.CalcHashToByte(b)
	if err != nil {
		// Blake2b over an in-memory buffer cannot fail.
		panic(fmt.Sprintf("RANDAO hash: %v", err))
	}
	return common.GetHashFromBytes(h)
}

// RandaoCommitment is the commitment to a seed.
func RandaoCommitment(seed []byte) common.Hash {
	return domainHash(randaoCommitDomain, seed)
}

// parentMix is the accumulator a block at height parent.Height+1 builds on.
// Genesis carries no RANDAO fields; its hash seeds the chain.
func parentMix(parent Block) common.Hash {
	if parent.GetHeader().Height == 0 {
		return parent.BlockHash
	}
	return parent.BaseBlock.RandMix
}

// mixHash folds one block's reveal (possibly empty) into the accumulator.
func mixHash(prev common.Hash, height int64, reveal []byte) common.Hash {
	return domainHash(randaoMixDomain, prev.GetBytes(), common.GetByteInt64(height), reveal)
}

// randFromMix is the RandOracle value of a block: 63 bits of a hash of its
// mix, non-negative because the EVM precompile clamps negatives to zero.
func randFromMix(mix common.Hash) int64 {
	h := domainHash(randaoRandDomain, mix.GetBytes())
	return int64(binary.BigEndian.Uint64(h[:8]) >> 1)
}

// RandaoFields computes what a producer puts in its block at height on top of
// parent, given the seed it reveals (nil for none) and its next seed.
func RandaoFields(parent Block, height int64, reveal, nextSeed []byte) (commit, mix common.Hash, rand int64) {
	mix = mixHash(parentMix(parent), height, reveal)
	return RandaoCommitment(nextSeed), mix, randFromMix(mix)
}

// RevealDue reports whether an operator whose recorded commitment was made at
// commitHeight must reveal in a block at height.
func RevealDue(commitHeight, height int64) bool {
	return commitHeight > 0 && height-commitHeight <= common.RandaoCommitExpiry
}

// verifyRandaoStateless checks what needs only the block and its parent: the
// field shapes, the mix and the RAND derived from it. Called from
// CheckBaseBlock, so batched sync checks it ahead of application.
func verifyRandaoStateless(newBlock, lastBlock Block) error {
	if newBlock.GetHeader().Height == 0 {
		return nil
	}
	bb := newBlock.BaseBlock
	if len(bb.RandReveal) != 0 && len(bb.RandReveal) != randaoSeedLength {
		return fmt.Errorf("RANDAO reveal has %d bytes, want 0 or %d", len(bb.RandReveal), randaoSeedLength)
	}
	if bb.RandCommit == (common.Hash{}) {
		return fmt.Errorf("block carries no RANDAO commitment")
	}
	// The validator-proposal RAND is gone; nothing may ride in its place.
	if len(bb.RandOracleData) != 0 {
		return fmt.Errorf("rand oracle data must be empty, RAND comes from RANDAO")
	}
	want := mixHash(parentMix(lastBlock), newBlock.GetHeader().Height, bb.RandReveal)
	if bb.RandMix != want {
		return fmt.Errorf("RANDAO mix does not follow from the parent and the reveal")
	}
	if bb.RandOracle != randFromMix(bb.RandMix) {
		return fmt.Errorf("rand oracle is not derived from the RANDAO mix")
	}
	return nil
}

// verifyRandaoReveal checks the reveal against the commitment the chain holds
// for the block's operator. Needs the parent's staking state, so it runs in
// VerifyStakeDependent.
func verifyRandaoReveal(newBlock Block) error {
	height := newBlock.GetHeader().Height
	if height == 0 {
		return nil
	}
	n := mustDelegatedAccountID(newBlock.GetHeader().DelegatedAccount)
	if n < 1 || n > 255 {
		return fmt.Errorf("wrong delegated account for RANDAO")
	}
	commit, commitHeight := account.GetRandCommit(n, newBlock.GetHeader().OperatorAccount.ByteValue)
	reveal := newBlock.BaseBlock.RandReveal
	if !RevealDue(commitHeight, height) {
		if len(reveal) != 0 {
			return fmt.Errorf("RANDAO reveal without a live commitment")
		}
		return nil
	}
	if len(reveal) == 0 {
		return fmt.Errorf("operator committed at height %d and must reveal", commitHeight)
	}
	if !bytes.Equal(RandaoCommitment(reveal).GetBytes(), commit[:]) {
		return fmt.Errorf("RANDAO reveal does not open the operator's commitment from height %d", commitHeight)
	}
	return nil
}

// applyRandaoCommit records the block's commitment as its operator's live
// one. Part of block application.
func applyRandaoCommit(block Block) error {
	height := block.GetHeader().Height
	if height == 0 {
		return nil
	}
	n := mustDelegatedAccountID(block.GetHeader().DelegatedAccount)
	if n < 1 || n > 255 {
		return fmt.Errorf("wrong delegated account for RANDAO")
	}
	var commit [common.HashLength]byte
	copy(commit[:], block.BaseBlock.RandCommit.GetBytes())
	return account.SetRandCommit(n, block.GetHeader().OperatorAccount.ByteValue, commit, height)
}

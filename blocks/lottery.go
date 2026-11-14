package blocks

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"

	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/common"
)

// Proof-of-synergy lottery (whitepaper 3.3.3, audit 2026-11-12 F-CONS-01).
//
// A block wins when the hash of its NONCE passes the difficulty. The nonce is
// the whitepaper's "unique string value": the block's UNIX second, the
// operator's address, the delegated account, the parent's RANDAO mix and the
// height. It changes once a second, so an account holds exactly one ticket per
// second - "the first node to solve the PoW" without anything to grind.
//
// The lottery used to be the hash of the whole header, signature included.
// Falcon signs afresh, and validly, every time, and the header carries fields
// the producer chooses freely (RandCommit, its reward share, the transactions,
// which oracle proofs to embed): every signing or edit was a new ticket. None
// of that enters the nonce. The parent's RANDAO mix stands in for the parent's
// hash, which its producer could have ground to win this block too; the mix
// follows from a reveal committed before.
//
// The header carries the nonce in SignatureMessage; validators recompute it.
// Every input of the nonce is covered by the header signature (the second via
// BodyHash, the parent via PreviousHash), so the producer signs it.

const nonceDomain = "QWID-NONCE-v1"

// ErrNoWinningSecond: this producer holds no winning ticket in the seconds it
// may stamp a block with - not its turn.
var ErrNoWinningSecond = errors.New("no winning second for this producer")

// ErrStakeNotMatured: the producer's delegated account holds less than the
// node minimum once its recent deposits are left out.
var ErrStakeNotMatured = errors.New("delegated account stake not matured")

// NonceMessage is the block nonce for a block of height stamped ts, produced
// by operator for delegated on top of parent.
func NonceMessage(ts int64, operator, delegated common.Address, parent Block, height int64) []byte {
	b := common.BytesToLenAndBytes([]byte(nonceDomain))
	b = append(b, common.GetByteInt64(ts)...)
	b = append(b, operator.GetBytes()...)
	b = append(b, delegated.GetBytes()...)
	mix := parentMix(parent)
	b = append(b, mix.GetBytes()...)
	return append(b, common.GetByteInt64(height)...)
}

func blockNonce(newBlock, parent Block) []byte {
	h := newBlock.GetHeader()
	return NonceMessage(newBlock.GetBlockTimeStamp(), h.OperatorAccount, h.DelegatedAccount, parent, h.Height)
}

func lotteryHash(nonce []byte) common.Hash {
	b, err := common.CalcHashToByte(nonce)
	if err != nil {
		panic(fmt.Sprintf("lottery hash: %v", err))
	}
	return common.GetHashFromBytes(b)
}

// LotteryTicket is the ticket of newBlock built on parent.
func LotteryTicket(newBlock, parent Block) common.Hash {
	return lotteryHash(blockNonce(newBlock, parent))
}

// lotteryValue is the 128-bit AND of the ticket's halves; smaller is better.
func lotteryValue(h common.Hash) *big.Int {
	and := make([]byte, 16)
	for i := 0; i < 16; i++ {
		and[i] = h[i] & h[i+16]
	}
	return new(big.Int).SetBytes(and)
}

// CheckLottery verifies that newBlock carries its block nonce and that the
// nonce wins at the block's difficulty. Genesis has no parent and no lottery.
func CheckLottery(newBlock, parent Block) error {
	if newBlock.GetHeader().Height == 0 {
		return nil
	}
	nonce := blockNonce(newBlock, parent)
	if !bytes.Equal(nonce, newBlock.GetHeader().SignatureMessage) {
		return fmt.Errorf("the header does not carry the block nonce")
	}
	if !validProof(lotteryHash(nonce), newBlock.GetHeader().Difficulty) {
		return fmt.Errorf("proof of synergy fails of block")
	}
	return nil
}

// WinningSecond returns the earliest second in [from, to] - after the parent's
// - in which operator wins the lottery for delegated at height, with the
// difficulty that second implies.
func WinningSecond(parent Block, operator, delegated common.Address, height, from, to int64) (int64, int32, bool) {
	pts := parent.GetBlockTimeStamp()
	if from <= pts {
		from = pts + 1
	}
	pd := parent.GetHeader().Difficulty
	for s := from; s <= to; s++ {
		d := AdjustDifficulty(pd, s-pts)
		if validProof(lotteryHash(NonceMessage(s, operator, delegated, parent, height)), d) {
			return s, d, true
		}
	}
	return 0, 0, false
}

// BetterAtEqualHeight orders two blocks of the same height on the same parent:
// the earlier second wins ("the first node to solve"), then the smaller ticket,
// then the smaller block hash. The order is strict and every node agrees on it.
func BetterAtEqualHeight(a, b, parent Block) bool {
	if a.GetBlockTimeStamp() != b.GetBlockTimeStamp() {
		return a.GetBlockTimeStamp() < b.GetBlockTimeStamp()
	}
	if c := lotteryValue(LotteryTicket(a, parent)).Cmp(lotteryValue(LotteryTicket(b, parent))); c != 0 {
		return c < 0
	}
	return bytes.Compare(a.BlockHash.GetBytes(), b.BlockHash.GetBytes()) < 0
}

// ProducerStakeMatured reports whether delegated account n may produce the
// block of the given height: it holds the node minimum without the deposits
// of the last MinNumberOfBlocksInStake blocks. Whoever produces the parent
// knows the RANDAO mix this block's lottery uses; without the delay it could
// fund, in that very block, the delegated account whose ticket wins next.
func ProducerStakeMatured(n int, height int64) bool {
	return account.MaturedStakeInDelegatedAccount(n, height-1, common.MinNumberOfBlocksInStake) >= common.MinStakingForNode
}

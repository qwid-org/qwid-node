package blocks

import (
	"bytes"
	"math"
	"math/big"
	"math/rand"
	"testing"

	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
)

// The block nonce (whitepaper 3.3.3): timestamp, operator, delegated account,
// the parent's RANDAO mix and the height - and nothing the producer picks.
func TestLotteryIgnoresWhatTheProducerChooses(t *testing.T) {
	k, parent := headerTestSetup(t)
	bl := signedTestBlock(t, k, 10, parent, common.Hash{})
	want := LotteryTicket(bl, parent)

	other := bl
	other.BaseBlock.RandCommit = common.Hash{0x42}
	other.BaseBlock.RewardPercentage = 300
	other.BaseBlock.BaseHeader.RootMerkleTree = common.Hash{0x43}
	other = resealTestBlock(t, k, other)
	if LotteryTicket(other, parent) != want {
		t.Fatal("the lottery ticket changed with RandCommit, the reward share, the transactions or the signature")
	}
	later := bl
	later.BaseBlock.BlockTimeStamp++
	if LotteryTicket(later, parent) == want {
		t.Fatal("the lottery ticket does not change with the second")
	}
	if !bytes.Equal(bl.BaseBlock.BaseHeader.SignatureMessage, NonceMessage(bl.GetBlockTimeStamp(), k.addr, common.GetDelegatedAccountAddress(1), parent, 10)) {
		t.Fatal("the header does not carry the block nonce")
	}
}

func TestSignatureMessageMustBeTheBlockNonce(t *testing.T) {
	k, parent := headerTestSetup(t)
	bl := signedTestBlock(t, k, 10, parent, common.Hash{})
	if _, err := CheckBaseBlock(bl, parent, false); err != nil {
		t.Fatalf("a valid block was refused: %v", err)
	}
	bad := bl
	bad.BaseBlock.BaseHeader.SignatureMessage = append([]byte{}, bl.BaseBlock.BaseHeader.SignatureMessage...)
	bad.BaseBlock.BaseHeader.SignatureMessage[len(bad.BaseBlock.BaseHeader.SignatureMessage)-1] ^= 1
	bad.BaseBlock.BlockHeaderHash, _ = bad.BaseBlock.BaseHeader.CalcHash()
	bad.BlockHash, _ = bad.CalcBlockHash()
	if _, err := CheckBaseBlock(bad, parent, false); err == nil {
		t.Fatal("a block whose nonce is not the one its fields define was accepted")
	}
}

// The integer rule decides exactly as the former float rule did, away from
// float rounding at the boundary (audit F-CONS-04).
func TestIntegerLotteryMatchesTheFormerRule(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	r := rand.New(rand.NewSource(1))
	for i := 0; i < 20000; i++ {
		var h common.Hash
		r.Read(h[:])
		// thin the hash so that low values (winning ones) are covered too
		for j := 0; j < r.Intn(17); j++ {
			h[j], h[j+16] = 0, 0
		}
		d := int32(r.Intn(1400) + 1)
		and := make([]byte, 16)
		for j := 0; j < 16; j++ {
			and[j] = h[j] & h[j+16]
		}
		f, _ := new(big.Float).SetInt(new(big.Int).SetBytes(and)).Float64()
		old := math.Log2(f) <= 128.0-float64(d/10)/float64(common.DifficultyMultiplier)
		if math.Abs(math.Log2(f)-(128.0-float64(d/10)/10)) < 1e-9 {
			continue
		}
		if validProof(h, d) != old {
			t.Fatalf("hash %x difficulty %d: integer rule %v, float rule %v", h, d, validProof(h, d), old)
		}
	}
}

func TestWinningSecondIsTheEarliestThatWins(t *testing.T) {
	k, parent := headerTestSetup(t)
	parent.BaseBlock.BaseHeader.Difficulty = 600 // a few winners per hundred seconds
	del := common.GetDelegatedAccountAddress(1)
	from, to := parent.GetBlockTimeStamp()+1, parent.GetBlockTimeStamp()+400
	ts, diff, ok := WinningSecond(parent, k.addr, del, 10, from, to)
	if !ok {
		t.Skip("no winning second in the range for this key; cannot tell")
	}
	for s := from; s < ts; s++ {
		d := AdjustDifficulty(600, s-parent.GetBlockTimeStamp())
		if validProof(lotteryHash(NonceMessage(s, k.addr, del, parent, 10)), d) {
			t.Fatalf("second %d wins but %d was chosen", s, ts)
		}
	}
	if diff != AdjustDifficulty(600, ts-parent.GetBlockTimeStamp()) {
		t.Fatalf("difficulty %d is not the one the chosen second implies", diff)
	}
	if _, _, ok := WinningSecond(parent, k.addr, del, 10, parent.GetBlockTimeStamp(), parent.GetBlockTimeStamp()); ok {
		t.Fatal("the parent's own second was offered")
	}
}

// A delegated account funded within MinNumberOfBlocksInStake blocks cannot
// produce: the producer of the previous block knows the RANDAO mix and could
// otherwise fund, just in time, the account whose ticket wins next.
func TestFreshlyFundedAccountCannotProduce(t *testing.T) {
	logger.InitLogger()
	initTestStaking()
	var staker [common.AddressLength]byte
	staker[0] = 0x31
	if err := account.Stake(staker[:], common.MinStakingForNode, 100, 1, 3, false, 0, 0); err != nil {
		t.Fatal(err)
	}
	if ProducerStakeMatured(3, 101) {
		t.Fatal("an account funded in the parent block may produce")
	}
	if ProducerStakeMatured(3, 100+common.MinNumberOfBlocksInStake) {
		t.Fatal("the stake matured a block early")
	}
	if !ProducerStakeMatured(3, 100+common.MinNumberOfBlocksInStake+1) {
		t.Fatal("matured stake does not let the account produce")
	}
}

func TestEqualHeightPrefersTheEarlierWinner(t *testing.T) {
	k, parent := headerTestSetup(t)
	a := signedTestBlock(t, k, 10, parent, common.Hash{})
	b := a
	b.BaseBlock.BlockTimeStamp++
	b = resealTestBlock(t, k, b)
	if !BetterAtEqualHeight(a, b, parent) || BetterAtEqualHeight(b, a, parent) {
		t.Fatal("the block stamped earlier does not win")
	}
	c := resealTestBlock(t, k, a) // same second, same ticket
	if BetterAtEqualHeight(a, c, parent) == BetterAtEqualHeight(c, a, parent) && a.BlockHash != c.BlockHash {
		t.Fatal("no strict order between two different blocks")
	}
}

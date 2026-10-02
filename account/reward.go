package account

import (
	"math/bits"

	"github.com/qwid-org/qwid-node/common"
)

func getRemainingSupply(supply int64) int64 {
	return common.MaxTotalSupply - supply
}

// GetReward computes remaining*RewardRatio in exact integer arithmetic
// (AC-M9): the float path lost precision because remaining supply (up to
// MaxTotalSupply = 2.3e17) exceeds 2^53. Rounded half up, matching the
// previous math.Round behaviour.
func GetReward(supply int64) int64 {
	remaining := getRemainingSupply(supply)
	if remaining <= 0 || common.RewardRatioPerE10 <= 0 {
		return 0
	}
	// remaining * RewardRatioPerE10 / 1e10, rounded half up, in 128-bit
	// arithmetic: the product overflows int64 for larger ratios. The ratio
	// comes from genesis reward_ratio (S9-02); it used to be a hardcoded 2e-8
	// whatever the genesis file said.
	const scale = 10_000_000_000
	hi, lo := bits.Mul64(uint64(remaining), uint64(common.RewardRatioPerE10))
	lo, carry := bits.Add64(lo, scale/2, 0)
	hi += carry
	q, _ := bits.Div64(hi, lo, scale)
	return int64(q)
}

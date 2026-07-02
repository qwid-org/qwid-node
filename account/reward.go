package account

import (
	"github.com/wonabru/qwid-node/common"
)

func getRemainingSupply(supply int64) int64 {
	return common.MaxTotalSupply - supply
}

// GetReward computes remaining*RewardRatio in exact integer arithmetic
// (AC-M9). RewardRatio is 2e-8 = 2/1e8; the float path lost precision because
// remaining supply (up to MaxTotalSupply = 2.3e17) exceeds 2^53. remaining*2 is
// at most 4.6e17 and fits int64; the +5e7 gives round-half-up to match the
// previous math.Round behaviour.
func GetReward(supply int64) int64 {
	remaining := getRemainingSupply(supply)
	if remaining <= 0 {
		return 0
	}
	return (remaining*2 + 50000000) / 100000000
}

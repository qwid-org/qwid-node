package account

import (
	"testing"

	"github.com/qwid-org/qwid-node/common"
)

// S9-02: the emission rate is the genesis reward_ratio, not a constant that
// silently overrode it.
func TestGetRewardFollowsConfiguredRatio(t *testing.T) {
	saved := common.RewardRatioPerE10
	defer func() { common.RewardRatioPerE10 = saved }()
	supply := common.MaxTotalSupply / 2
	remaining := common.MaxTotalSupply - supply

	common.RewardRatioPerE10 = 200 // 2e-8
	if got, want := GetReward(supply), (remaining*2+50000000)/100000000; got != want {
		t.Fatalf("2e-8: got %d want %d", got, want)
	}
	low := GetReward(supply)
	common.RewardRatioPerE10 = 1000 // 1e-7
	if got := GetReward(supply); got < 5*low-1 || got > 5*low+1 {
		t.Fatalf("1e-7 must pay five times 2e-8: %d vs %d", got, low)
	}
}

package account

import (
	"testing"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
	"github.com/stretchr/testify/assert"
)

func TestGetRemainingSupply(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	t.Run("remaining supply with zero supply", func(t *testing.T) {
		remaining := getRemainingSupply(0)
		assert.Equal(t, common.MaxTotalSupply, remaining)
	})

	t.Run("remaining supply with partial supply", func(t *testing.T) {
		supply := int64(1000000000000)
		remaining := getRemainingSupply(supply)
		expected := common.MaxTotalSupply - supply
		assert.Equal(t, expected, remaining)
	})

	t.Run("remaining supply at max", func(t *testing.T) {
		remaining := getRemainingSupply(common.MaxTotalSupply)
		assert.Equal(t, int64(0), remaining)
	})
}

func TestGetReward(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	t.Run("reward with zero supply", func(t *testing.T) {
		reward := GetReward(0)
		// Reward should be RewardRatio * MaxTotalSupply
		assert.Greater(t, reward, int64(0))
	})

	t.Run("reward decreases as supply increases", func(t *testing.T) {
		reward1 := GetReward(1000000000000)
		reward2 := GetReward(2000000000000)
		assert.Greater(t, reward1, reward2)
	})

	t.Run("reward at max supply is zero", func(t *testing.T) {
		reward := GetReward(common.MaxTotalSupply)
		assert.Equal(t, int64(0), reward)
	})

	t.Run("reward is positive for normal supply", func(t *testing.T) {
		supply := common.InitSupply
		reward := GetReward(supply)
		assert.Greater(t, reward, int64(0))
	})

	t.Run("reward calculation is consistent", func(t *testing.T) {
		supply := int64(10000000000000)
		reward1 := GetReward(supply)
		reward2 := GetReward(supply)
		assert.Equal(t, reward1, reward2)
	})
}

func TestRewardRatioIntegration(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	t.Run("reward ratio produces reasonable rewards", func(t *testing.T) {
		// At initial supply, reward should be meaningful
		reward := GetReward(common.InitSupply)

		// Reward should be a fraction of remaining supply
		remaining := getRemainingSupply(common.InitSupply)
		assert.Less(t, reward, remaining)
		assert.Greater(t, reward, int64(0))
	})

	t.Run("cumulative rewards approach max supply", func(t *testing.T) {
		supply := common.InitSupply
		totalRewards := int64(0)

		// Simulate many blocks
		for i := 0; i < 1000; i++ {
			reward := GetReward(supply)
			if reward == 0 {
				break
			}
			totalRewards += reward
			supply += reward
		}

		// Supply should still be less than or equal to max
		assert.LessOrEqual(t, supply, common.MaxTotalSupply)
	})
}

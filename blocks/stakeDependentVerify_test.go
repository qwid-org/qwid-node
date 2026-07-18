package blocks

import (
	"testing"

	"github.com/wonabru/qwid-node/account"
	"github.com/wonabru/qwid-node/common"
	"github.com/wonabru/qwid-node/logger"
	"github.com/stretchr/testify/assert"
)

func stakeOperator(id byte) common.Address {
	var a common.Address
	a.ByteValue[0] = id
	return a
}

func stakeDependentBlock(id byte, priceOracle int64) Block {
	return Block{
		BaseBlock: BaseBlock{
			BaseHeader: BaseHeader{
				Height:           10,
				DelegatedAccount: common.GetDelegatedAccountAddress(int16(id)),
				OperatorAccount:  stakeOperator(id),
			},
			PriceOracle: priceOracle,
		},
	}
}

func TestVerifyStakeDependent(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	initTestStaking()

	// 129 equally-staked delegated accounts: later staking times rank lower, so
	// id 129 falls outside the top 128.
	for id := 1; id <= 129; id++ {
		op := stakeOperator(byte(id))
		assert.NoError(t, account.Stake(op.GetBytes(), common.MinStakingForNode, 100, int64(1000+id), id, true, 0, 0))
	}

	t.Run("top-128 producer with empty oracle data passes", func(t *testing.T) {
		assert.NoError(t, VerifyStakeDependent(stakeDependentBlock(128, 0)))
	})

	t.Run("non-top-128 producer is rejected", func(t *testing.T) {
		assert.Error(t, VerifyStakeDependent(stakeDependentBlock(129, 0)))
	})

	t.Run("unbacked non-zero price oracle is rejected", func(t *testing.T) {
		// PriceOracle != 0 but no oracle data reaches the 2/3 stake threshold.
		assert.Error(t, VerifyStakeDependent(stakeDependentBlock(128, 12345)))
	})
}

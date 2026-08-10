package account

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
)

func initTestStakingAccounts() {
	for i := 0; i < 256; i++ {
		StakingAccounts[i] = StakingAccountsType{
			AllStakingAccounts: make(map[[20]byte]StakingAccount),
		}
	}
}

func TestStakingAccountMarshalUnmarshal(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	t.Run("marshal and unmarshal basic staking account", func(t *testing.T) {
		addr := [common.AddressLength]byte{}
		copy(addr[:], []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20})

		original := StakingAccount{
			StakedBalance:      1000000,
			StakingRewards:     50000,
			LockedAmount:       []int64{},
			ReleasePerBlock:    []int64{},
			LockedInitBlock:    []int64{},
			DelegatedAccount:   addr,
			Address:            addr,
			OperationalAccount: true,
			StakingDetails:     make(map[int64][]StakingDetail),
		}

		data := original.Marshal()
		assert.NotEmpty(t, data)

		var restored StakingAccount
		err := restored.Unmarshal(data)
		assert.NoError(t, err)
		assert.Equal(t, original.StakedBalance, restored.StakedBalance)
		assert.Equal(t, original.StakingRewards, restored.StakingRewards)
		assert.Equal(t, original.OperationalAccount, restored.OperationalAccount)
	})

	t.Run("marshal and unmarshal with locked amounts", func(t *testing.T) {
		addr := [common.AddressLength]byte{}
		copy(addr[:], []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20})

		original := StakingAccount{
			StakedBalance:      2000000,
			StakingRewards:     100000,
			LockedAmount:       []int64{500000, 300000},
			ReleasePerBlock:    []int64{1000, 500},
			LockedInitBlock:    []int64{100, 200},
			DelegatedAccount:   addr,
			Address:            addr,
			OperationalAccount: false,
			StakingDetails:     make(map[int64][]StakingDetail),
		}

		data := original.Marshal()
		var restored StakingAccount
		err := restored.Unmarshal(data)
		assert.NoError(t, err)
		assert.Equal(t, len(original.LockedAmount), len(restored.LockedAmount))
		assert.Equal(t, original.LockedAmount[0], restored.LockedAmount[0])
	})

	t.Run("marshal and unmarshal with staking details", func(t *testing.T) {
		addr := [common.AddressLength]byte{}
		original := StakingAccount{
			StakedBalance:      1000000,
			StakingRewards:     0,
			LockedAmount:       []int64{},
			ReleasePerBlock:    []int64{},
			LockedInitBlock:    []int64{},
			DelegatedAccount:   addr,
			Address:            addr,
			OperationalAccount: true,
			StakingDetails: map[int64][]StakingDetail{
				100: {
					{Amount: 500000, Reward: 0, LastUpdated: 1234567890},
					{Amount: 500000, Reward: 1000, LastUpdated: 1234567900},
				},
			},
		}

		data := original.Marshal()
		var restored StakingAccount
		err := restored.Unmarshal(data)
		assert.NoError(t, err)
		assert.Equal(t, len(original.StakingDetails), len(restored.StakingDetails))
	})

	t.Run("unmarshal with insufficient data", func(t *testing.T) {
		var sa StakingAccount
		err := sa.Unmarshal([]byte{1, 2, 3})
		assert.Error(t, err)
	})
}

func TestStake(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	initTestStakingAccounts()

	t.Run("stake with valid params", func(t *testing.T) {
		addr := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
		err := Stake(addr, 1000000, 100, 100, 1, true, 0, 0)
		assert.NoError(t, err)

		sa := GetStakingAccountByAddressBytes(addr, 1)
		assert.Equal(t, int64(1000000), sa.StakedBalance)
		assert.True(t, sa.OperationalAccount)
	})

	t.Run("stake with locked amount", func(t *testing.T) {
		addr := []byte{2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21}
		err := Stake(addr, 1000000, 100, 100, 2, false, 500000, 1000)
		assert.NoError(t, err)

		sa := GetStakingAccountByAddressBytes(addr, 2)
		assert.Equal(t, int64(1000000), sa.StakedBalance)
		assert.Equal(t, 1, len(sa.LockedAmount))
		assert.Equal(t, int64(500000), sa.LockedAmount[0])
	})

	t.Run("stake with negative amount fails", func(t *testing.T) {
		addr := []byte{3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22}
		err := Stake(addr, -100, 100, 100, 1, false, 0, 0)
		assert.Error(t, err)
	})

	t.Run("stake with locked amount greater than amount fails", func(t *testing.T) {
		addr := []byte{4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23}
		err := Stake(addr, 1000, 100, 100, 1, false, 2000, 100)
		assert.Error(t, err)
	})

	t.Run("stake with release greater than locked fails", func(t *testing.T) {
		addr := []byte{5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24}
		err := Stake(addr, 1000, 100, 100, 1, false, 500, 600)
		assert.Error(t, err)
	})

	t.Run("stake with wrong address length fails", func(t *testing.T) {
		addr := []byte{1, 2, 3} // Too short
		err := Stake(addr, 1000, 100, 100, 1, false, 0, 0)
		assert.Error(t, err)
	})
}

// TestStakingDetailsHistoryPreserved verifies AC-C3: staking at successive
// heights accumulates history instead of erasing the map on each new height.
func TestStakingDetailsHistoryPreserved(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	initTestStakingAccounts()

	addr := []byte{40, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19}
	// Stake at three heights spaced beyond MinNumberOfBlocksInStake apart.
	h1 := int64(100)
	h2 := h1 + common.MinNumberOfBlocksInStake + 1
	h3 := h2 + common.MinNumberOfBlocksInStake + 1
	assert.NoError(t, Stake(addr, 1000, h1, h1, 20, true, 0, 0))
	assert.NoError(t, Stake(addr, 1000, h2, h2, 20, true, 0, 0))
	assert.NoError(t, Stake(addr, 1000, h3, h3, 20, true, 0, 0))

	sa := GetStakingAccountByAddressBytes(addr, 20)
	assert.Equal(t, 3, len(sa.StakingDetails), "all three heights must be retained")
	assert.Contains(t, sa.StakingDetails, h1)
	assert.Contains(t, sa.StakingDetails, h2)
	assert.Contains(t, sa.StakingDetails, h3)
}

// TestUnstakeLockedRemovalIndices verifies AC-H1: when several locked entries
// fully release at once, exactly those entries are removed and the remaining
// parallel slices stay aligned.
func TestUnstakeLockedRemovalIndices(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	initTestStakingAccounts()

	addr := [20]byte{41, 1, 2, 3}
	// Three locked entries: two release quickly, one large/slow entry survives.
	sa := StakingAccount{
		StakedBalance:   1000,
		LockedAmount:    []int64{10, 10, 900},
		ReleasePerBlock: []int64{10, 10, 1},
		LockedInitBlock: []int64{0, 0, 0},
		StakingDetails:  map[int64][]StakingDetail{},
	}
	copy(sa.Address[:], addr[:])
	StakingRWMutex.Lock()
	StakingAccounts[21].AllStakingAccounts[addr] = sa
	StakingRWMutex.Unlock()

	// At height 5, entries 0 and 1 have fully released (10 - 5*10 <= 0); entry 2
	// still locks 900 - 5*1 = 895.
	err := Unstake(addr[:], -10, common.MinNumberOfBlocksInStake+5, common.MinNumberOfBlocksInStake+5, 21)
	assert.NoError(t, err)

	res := GetStakingAccountByAddressBytes(addr[:], 21)
	assert.Equal(t, 1, len(res.LockedAmount), "only the surviving entry remains")
	assert.Equal(t, int64(900), res.LockedAmount[0])
	assert.Equal(t, int64(1), res.ReleasePerBlock[0])
	assert.Equal(t, len(res.LockedAmount), len(res.ReleasePerBlock))
	assert.Equal(t, len(res.LockedAmount), len(res.LockedInitBlock))
}

func TestUnstake(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	initTestStakingAccounts()

	t.Run("unstake with valid params", func(t *testing.T) {
		addr := []byte{10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29}
		// First stake
		err := Stake(addr, 1000000, 100, 100, 5, true, 0, 0)
		assert.NoError(t, err)

		// Then unstake (negative amount)
		err = Unstake(addr, -500000, 150, 150, 5)
		assert.NoError(t, err)

		sa := GetStakingAccountByAddressBytes(addr, 5)
		assert.Equal(t, int64(500000), sa.StakedBalance)
	})

	t.Run("unstake with positive amount fails", func(t *testing.T) {
		addr := []byte{11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30}
		_ = Stake(addr, 1000000, 100, 100, 6, true, 0, 0)

		err := Unstake(addr, 500000, 150, 150, 6)
		assert.Error(t, err)
	})

	t.Run("unstake more than balance fails", func(t *testing.T) {
		addr := []byte{12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31}
		_ = Stake(addr, 1000000, 100, 100, 7, true, 0, 0)

		err := Unstake(addr, -2000000, 150, 150, 7)
		assert.Error(t, err)
	})

	t.Run("unstake clears operational status when balance is zero", func(t *testing.T) {
		addr := []byte{13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
		_ = Stake(addr, 1000000, 100, 100, 8, true, 0, 0)

		err := Unstake(addr, -1000000, 150, 150, 8)
		assert.NoError(t, err)

		sa := GetStakingAccountByAddressBytes(addr, 8)
		assert.False(t, sa.OperationalAccount)
	})
}

func TestReward(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	initTestStakingAccounts()

	t.Run("reward with valid params", func(t *testing.T) {
		addr := []byte{20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39}
		_ = Stake(addr, 1000000, 100, 100, 10, true, 0, 0)

		err := Reward(addr, 50000, 150, 10)
		assert.NoError(t, err)

		sa := GetStakingAccountByAddressBytes(addr, 10)
		assert.Equal(t, int64(50000), sa.StakingRewards)
	})

	t.Run("reward with negative amount fails", func(t *testing.T) {
		addr := []byte{21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40}
		_ = Stake(addr, 1000000, 100, 100, 11, true, 0, 0)

		err := Reward(addr, -1000, 150, 11)
		assert.Error(t, err)
	})
}

func TestWithdrawReward(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	initTestStakingAccounts()

	t.Run("withdraw with valid params", func(t *testing.T) {
		addr := []byte{30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49}
		_ = Stake(addr, 1000000, 100, 100, 15, true, 0, 0)
		_ = Reward(addr, 100000, 150, 15)

		err := WithdrawReward(addr, -50000, 200, 15)
		assert.NoError(t, err)

		sa := GetStakingAccountByAddressBytes(addr, 15)
		assert.Equal(t, int64(50000), sa.StakingRewards)
	})

	t.Run("withdraw with positive amount fails", func(t *testing.T) {
		addr := []byte{31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50}
		_ = Stake(addr, 1000000, 100, 100, 16, true, 0, 0)
		_ = Reward(addr, 100000, 150, 16)

		err := WithdrawReward(addr, 50000, 200, 16)
		assert.Error(t, err)
	})

	t.Run("withdraw more than rewards fails", func(t *testing.T) {
		addr := []byte{32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51}
		_ = Stake(addr, 1000000, 100, 100, 17, true, 0, 0)
		_ = Reward(addr, 50000, 150, 17)

		err := WithdrawReward(addr, -100000, 200, 17)
		assert.Error(t, err)
	})
}

func TestGetLockedAmount(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	initTestStakingAccounts()

	t.Run("no locked amount", func(t *testing.T) {
		addr := []byte{40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59}
		_ = Stake(addr, 1000000, 100, 100, 20, true, 0, 0)

		locked, err := GetLockedAmount(addr, 150, 20)
		assert.NoError(t, err)
		assert.Equal(t, int64(0), locked)
	})

	t.Run("with locked amount before release", func(t *testing.T) {
		addr := []byte{41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60}
		_ = Stake(addr, 1000000, 100, 100, 21, true, 500000, 1000)

		locked, err := GetLockedAmount(addr, 110, 21)
		assert.NoError(t, err)
		// After 10 blocks: 500000 - 10*1000 = 490000
		assert.Equal(t, int64(490000), locked)
	})

	t.Run("wrong address length", func(t *testing.T) {
		addr := []byte{1, 2, 3}
		_, err := GetLockedAmount(addr, 100, 1)
		assert.Error(t, err)
	})
}

func TestGetStakedInDelegatedAccount(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	initTestStakingAccounts()

	t.Run("empty delegated account", func(t *testing.T) {
		accs, sum, opAcc := GetStakedInDelegatedAccount(50)
		assert.Empty(t, accs)
		assert.Equal(t, int64(0), sum)
		assert.Equal(t, int64(0), opAcc.Balance)
	})

	t.Run("with staked accounts", func(t *testing.T) {
		addr1 := []byte{50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69}
		addr2 := []byte{51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70}

		_ = Stake(addr1, 1000000, 100, 100, 51, true, 0, 0)
		_ = Stake(addr2, 2000000, 100, 100, 51, false, 0, 0)

		accs, sum, opAcc := GetStakedInDelegatedAccount(51)
		assert.Equal(t, 2, len(accs))
		assert.Equal(t, int64(3000000), sum)
		assert.Equal(t, int64(1000000), opAcc.Balance) // Operational account has 1000000
	})
}

func TestIsTop128StakingNode(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	initTestStakingAccounts()

	operator := func(id byte) common.Address {
		var address common.Address
		address.ByteValue[0] = id
		return address
	}

	// Fill 129 eligible delegated accounts with equal stakes. Earlier signed
	// timestamps win; the last one must therefore be outside the top 128.
	for id := 1; id <= 129; id++ {
		address := operator(byte(id))
		assert.NoError(t, Stake(address.GetBytes(), common.MinStakingForNode, 100, int64(1000+id), id, true, 0, 0))
	}
	assert.True(t, IsTop128StakingNode(128, operator(128)))
	assert.False(t, IsTop128StakingNode(129, operator(129)))

	// Moving account 129's current stake timestamp earlier puts it ahead of
	// account 128. This directly exercises the "first wins" tie rule.
	StakingAccounts[129].StakeChangedAt = 1000
	assert.True(t, IsTop128StakingNode(129, operator(129)))
	assert.False(t, IsTop128StakingNode(128, operator(128)))
}

func TestOperatorTieUsesFirstSignal(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	initTestStakingAccounts()

	var early, late common.Address
	early.ByteValue[0] = 1
	late.ByteValue[0] = 2
	assert.NoError(t, Stake(late.GetBytes(), common.MinStakingForNode, 100, 2000, 1, true, 0, 0))
	assert.NoError(t, Stake(early.GetBytes(), common.MinStakingForNode, 100, 1000, 1, true, 0, 0))

	assert.True(t, IsTop128StakingNode(1, early))
	assert.False(t, IsTop128StakingNode(1, late))
}

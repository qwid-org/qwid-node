package account

import (
	"testing"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
	"github.com/stretchr/testify/assert"
)

// LastStakeHeight gates the MinNumberOfBlocksInStake delay enforced by Stake
// and Unstake, so it is consensus data. It lived only in the in-memory map:
// Marshal never wrote it and Unmarshal never read it, so every restart or
// reload from a staking snapshot reset it to 0 and silently dropped the delay
// rule. Worse, that made validation node-dependent - a long-running node
// rejected a too-early stake that a freshly restarted node accepted.

func TestLastStakeHeightSurvivesMarshalRoundTrip(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	addr := [common.AddressLength]byte{}
	copy(addr[:], []byte{9, 8, 7, 6, 5, 4, 3, 2, 1, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10})

	original := StakingAccount{
		StakedBalance:      1000000,
		StakingRewards:     0,
		LockedAmount:       []int64{},
		ReleasePerBlock:    []int64{},
		LockedInitBlock:    []int64{},
		DelegatedAccount:   addr,
		Address:            addr,
		OperationalAccount: true,
		OperationalSince:   4242,
		LastStakeHeight:    777,
		StakingDetails:     make(map[int64][]StakingDetail),
	}

	var restored StakingAccount
	err := restored.Unmarshal(original.Marshal())
	assert.NoError(t, err)

	assert.Equal(t, original.LastStakeHeight, restored.LastStakeHeight,
		"LastStakeHeight must survive the binary round-trip")
	// OperationalSince is written immediately before it; assert it too so a
	// mistake in the field order cannot pass by swapping the two.
	assert.Equal(t, original.OperationalSince, restored.OperationalSince,
		"OperationalSince must not be disturbed by the appended field")
}

// Snapshots written before LastStakeHeight was appended must still decode.
func TestUnmarshalAcceptsSnapshotWithoutLastStakeHeight(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	addr := [common.AddressLength]byte{}
	copy(addr[:], []byte{1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10})

	acc := StakingAccount{
		StakedBalance:    5,
		LockedAmount:     []int64{},
		ReleasePerBlock:  []int64{},
		LockedInitBlock:  []int64{},
		DelegatedAccount: addr,
		Address:          addr,
		OperationalSince: 11,
		LastStakeHeight:  99,
		StakingDetails:   make(map[int64][]StakingDetail),
	}

	// An old snapshot is byte-identical minus the trailing 8 bytes.
	old := acc.Marshal()
	old = old[:len(old)-8]

	var restored StakingAccount
	err := restored.Unmarshal(old)
	assert.NoError(t, err, "an old snapshot must still decode")
	assert.Equal(t, int64(5), restored.StakedBalance)
	assert.Equal(t, int64(11), restored.OperationalSince)
	assert.Equal(t, int64(0), restored.LastStakeHeight,
		"absent field decodes as zero, matching pre-existing behaviour")
}

// The bug as a node operator would meet it: stake, restart (state round-trips
// through the snapshot format), then try to stake again too soon.
func TestStakingDelayStillEnforcedAfterStateReload(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()
	initTestStakingAccounts()

	const delegated = 7
	addr := []byte{31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50}
	stakeHeight := int64(1000)

	err := Stake(addr, common.MinStakingUser, stakeHeight, stakeHeight, delegated, false, 0, 0)
	assert.NoError(t, err)

	// Sanity: while the process keeps the account in memory, the delay holds.
	tooSoon := stakeHeight + common.MinNumberOfBlocksInStake - 1
	err = Stake(addr, common.MinStakingUser, tooSoon, tooSoon, delegated, false, 0, 0)
	assert.Error(t, err, "a second stake inside the delay window must be rejected")

	// Simulate a restart: the account is rebuilt from its snapshot bytes.
	stored := GetStakingAccountByAddressBytes(addr, delegated)
	var reloaded StakingAccount
	assert.NoError(t, reloaded.Unmarshal(stored.Marshal()))
	key := [common.AddressLength]byte{}
	copy(key[:], addr)
	StakingAccounts[delegated].AllStakingAccounts[key] = reloaded

	assert.Equal(t, stakeHeight, reloaded.LastStakeHeight,
		"the reloaded account must remember when it last staked")

	err = Stake(addr, common.MinStakingUser, tooSoon, tooSoon, delegated, false, 0, 0)
	assert.Error(t, err,
		"the delay must survive a reload - otherwise a restarted node accepts "+
			"a transaction a running node rejects, and the two fork")

	// The rule must still let a legitimate stake through afterwards.
	late := stakeHeight + common.MinNumberOfBlocksInStake
	err = Stake(addr, common.MinStakingUser, late, late, delegated, false, 0, 0)
	assert.NoError(t, err, "staking after the delay window must still succeed")
}

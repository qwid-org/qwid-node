package account

import (
	"testing"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
)

// S4-07: a locked stake paid into someone else's account must not restart
// that account's stake/unstake delay - a deposit every 36 blocks used to keep
// the owner from ever unstaking.
func TestThirdPartyLockedStakeDoesNotDelayOwner(t *testing.T) {
	logger.InitLogger()
	initTestStakingAccounts()
	var owner [common.AddressLength]byte
	owner[0] = 0x51
	amount := common.MinStakingUser
	if err := Stake(owner[:], 3*amount, 100, 1, 1, false, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := StakeLockedFor(owner[:], amount, 120, 2, 1, amount, 1); err != nil {
		t.Fatal(err)
	}
	acc := GetStakingAccountByAddressBytes(owner[:], 1)
	if acc.LastStakeHeight != 100 {
		t.Fatalf("a third party moved LastStakeHeight to %d", acc.LastStakeHeight)
	}
	if acc.StakedBalance != 4*amount || len(acc.LockedAmount) != 1 {
		t.Fatalf("the locked deposit was not applied: %+v", acc)
	}
	if err := Unstake(owner[:], -amount, 100+common.MinNumberOfBlocksInStake, 3, 1); err != nil {
		t.Fatalf("the owner could not unstake its free stake: %v", err)
	}
}

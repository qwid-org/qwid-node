package blocks

import (
	"bytes"
	"testing"

	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
)

// Un-pausing a scheme makes it the one every block and every transaction must
// be signed with from the next block on. If the operators holding most of the
// stake have no key of it yet, nobody can sign the following blocks and the
// chain halts - and, with the other scheme now paused, can never register
// those keys either. So un-pausing needs two thirds of the stake to be held
// by operators that already registered a key of the scheme.

type gateValidator struct {
	stake  int64
	op     common.Address
	hasKey bool
}

func gateFakes(vs map[int]gateValidator) (func(int) (int64, common.Address), func(common.Address, bool, int) bool, int64) {
	total := int64(0)
	for _, v := range vs {
		total += v.stake
	}
	stakeAndOperator := func(id int) (int64, common.Address) {
		v := vs[id]
		return v.stake, v.op
	}
	hasKey := func(op common.Address, primary bool, keyLen int) bool {
		if !primary || keyLen != 1793 { // the un-paused scheme is Falcon-1024
			return false
		}
		for _, v := range vs {
			if v.op == op {
				return v.hasKey
			}
		}
		return false
	}
	return stakeAndOperator, hasKey, total
}

func TestUnpauseNeedsTwoThirdsOfStakeWithKeys(t *testing.T) {
	logger.InitLogger()
	parent := blockWithEnc(99, falcon1024(t, true), mayo5(t))
	unpause := falcon1024(t, false)

	cases := []struct {
		name string
		keys [3]bool // validators 1, 2, 3 hold 10, 20, 70 of 100
		ok   bool
	}{
		{"only a third has keys", [3]bool{true, true, false}, false},
		{"exactly the big validator", [3]bool{false, false, true}, true},
		{"80 of 100", [3]bool{true, false, true}, true},
		{"nobody", [3]bool{}, false},
	}
	for _, c := range cases {
		vs := map[int]gateValidator{
			1: {10, testAddress(1), c.keys[0]},
			2: {20, testAddress(2), c.keys[1]},
			3: {70, testAddress(3), c.keys[2]},
		}
		so, hk, total := gateFakes(vs)
		err := checkUnpauseKeyQuorum(unpause, parent, true, total, so, hk)
		if (err == nil) != c.ok {
			t.Errorf("%s: err=%v, want ok=%v", c.name, err, c.ok)
		}
	}
}

func TestUnpauseGateIgnoresOtherChanges(t *testing.T) {
	logger.InitLogger()
	so, hk, total := gateFakes(map[int]gateValidator{1: {100, testAddress(1), false}})
	live := blockWithEnc(99, falcon512(t, false), mayo5(t))
	paused := blockWithEnc(99, falcon512(t, true), mayo5(t))
	// Pausing and replacing make nothing active that lacks keys here.
	if err := checkUnpauseKeyQuorum(falcon512(t, true), live, true, total, so, hk); err != nil {
		t.Fatalf("a pause was gated: %v", err)
	}
	if err := checkUnpauseKeyQuorum(falcon1024(t, true), paused, true, total, so, hk); err != nil {
		t.Fatalf("a paused replacement was gated: %v", err)
	}
}

func TestUnpauseWithoutStakeIsRefused(t *testing.T) {
	logger.InitLogger()
	parent := blockWithEnc(99, falcon1024(t, true), mayo5(t))
	so, hk, _ := gateFakes(map[int]gateValidator{})
	if err := checkUnpauseKeyQuorum(falcon1024(t, false), parent, true, 0, so, hk); err == nil {
		t.Fatal("an un-pause with no stake at all was accepted")
	}
}

// The producer of the un-pausing block signs the next blocks with the
// un-paused scheme, so it must hold a key of it - registered by the parent.
func TestUnpauseProducerMustHoldAKeyOfTheScheme(t *testing.T) {
	k := registeredStageBKey(t) // registers a key of the current primary scheme
	cfg := func(paused bool) []byte {
		return encCfg(t, common.SigName(), common.PubKeyLength(false), common.PrivateKeyLength(), common.SignatureLength(false), paused)
	}
	parent := blockWithEnc(99, cfg(true), mayo5(t))
	newBlock := blockWithEnc(100, cfg(false), mayo5(t))

	newBlock.BaseBlock.BaseHeader.OperatorAccount = k.addr
	if err := checkPauseLeavesRegisteredKey(newBlock, parent, cfg(false), true); err != nil {
		t.Fatalf("a producer holding the key was refused: %v", err)
	}
	newBlock.BaseBlock.BaseHeader.OperatorAccount = testAddress(0x66)
	if err := checkPauseLeavesRegisteredKey(newBlock, parent, cfg(false), true); err == nil {
		t.Fatal("a producer without a key of the un-paused scheme was accepted")
	}
}

// The key quorum is weighed against the stake that can vote, so it must also
// count only that stake: a delegated account below the node minimum signs no
// nonces and must not lift an un-pause past two thirds.
func TestUnpauseQuorumCountsOnlyEligibleAccounts(t *testing.T) {
	logger.InitLogger()
	saved := account.StakingAccounts
	t.Cleanup(func() { account.StakingAccounts = saved })
	for i := range account.StakingAccounts {
		account.StakingAccounts[i] = account.StakingAccountsType{AllStakingAccounts: map[[20]byte]account.StakingAccount{}}
	}
	min := common.MinStakingForNode
	stake := func(id int, op common.Address, amount int64) {
		var a [20]byte
		copy(a[:], op.GetBytes())
		account.StakingAccounts[id].AllStakingAccounts[a] = account.StakingAccount{
			StakedBalance: amount, Address: a, OperationalAccount: true, OperationalSince: int64(id)}
	}
	stake(1, testAddress(1), min)   // eligible, no key of the scheme
	stake(2, testAddress(2), min-1) // below the node minimum, holds a key

	parent := blockWithEnc(99, falcon1024(t, true), mayo5(t))
	hasKey := func(op common.Address, primary bool, keyLen int) bool {
		want := testAddress(2)
		return bytes.Equal(op.GetBytes(), want.GetBytes())
	}
	total := account.GetStakedInEligibleDelegatedAccounts()
	if total != min {
		t.Fatalf("eligible stake %d, want %d", total, min)
	}
	if err := checkUnpauseKeyQuorum(falcon1024(t, false), parent, true, total, stakeAndOperatorOfDelegated, hasKey); err == nil {
		t.Fatal("stake of an account that cannot vote carried the un-pause key quorum")
	}
}

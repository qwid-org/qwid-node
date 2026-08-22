package account

import (
	"testing"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
)

// TestPruneStakingDetails: reward entries land every block, so the details map
// must stay bounded - entries older than the retention window fold into one
// aggregate at key 0 with amounts and rewards summed exactly.
func TestPruneStakingDetails(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	retention := common.StakingDetailsRetentionBlocks
	height := retention + 100

	acc := StakingAccount{StakingDetails: map[int64][]StakingDetail{}}
	totalAmount, totalReward := int64(0), int64(0)
	// Old entries (below cutoff = height - retention = 100): heights 1..99.
	for h := int64(1); h < 100; h++ {
		acc.StakingDetails[h] = []StakingDetail{{Amount: h, Reward: 2 * h, LastUpdated: h}}
		totalAmount += h
		totalReward += 2 * h
	}
	// Recent entries: inside the window, must survive untouched.
	acc.StakingDetails[height-1] = []StakingDetail{{Amount: 7, Reward: 8, LastUpdated: 123}}
	acc.StakingDetails[height] = []StakingDetail{{Amount: 0, Reward: 5, LastUpdated: 124}}

	pruneStakingDetails(&acc, height)

	if len(acc.StakingDetails) != 3 { // aggregate + two recent heights
		t.Fatalf("after pruning the map has %d entries, expected 3", len(acc.StakingDetails))
	}
	agg, ok := acc.StakingDetails[0]
	if !ok || len(agg) != 1 {
		t.Fatalf("no single aggregate under key 0: %v", agg)
	}
	if agg[0].Amount != totalAmount || agg[0].Reward != totalReward {
		t.Fatalf("aggregate = %d/%d, expected %d/%d - the total must not be lost",
			agg[0].Amount, agg[0].Reward, totalAmount, totalReward)
	}
	if agg[0].LastUpdated != 99 {
		t.Fatalf("aggregate LastUpdated = %d, expected 99 (the newest folded entry)", agg[0].LastUpdated)
	}
	if _, ok := acc.StakingDetails[height-1]; !ok {
		t.Fatal("an entry inside the retention window was deleted")
	}

	// Second prune folds a previous aggregate together with newly-aged entries.
	acc.StakingDetails[150] = []StakingDetail{{Amount: 10, Reward: 20, LastUpdated: 150}}
	pruneStakingDetails(&acc, height+150)
	agg = acc.StakingDetails[0]
	if len(agg) != 1 || agg[0].Amount != totalAmount+10 || agg[0].Reward != totalReward+20 {
		t.Fatalf("aggregate after the second prune = %v, expected %d/%d",
			agg, totalAmount+10, totalReward+20)
	}
}

// TestPruneStakingDetailsEarlyChain: nothing may fold while the chain is still
// inside the first retention window - genesis-era details stay as they are.
func TestPruneStakingDetailsEarlyChain(t *testing.T) {
	acc := StakingAccount{StakingDetails: map[int64][]StakingDetail{
		5: {{Amount: 3, Reward: 1, LastUpdated: 5}},
	}}
	pruneStakingDetails(&acc, common.StakingDetailsRetentionBlocks-1)
	if len(acc.StakingDetails) != 1 || len(acc.StakingDetails[5]) != 1 {
		t.Fatalf("pruning happened before the retention window elapsed: %v", acc.StakingDetails)
	}
}

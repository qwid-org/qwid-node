package genesis

import "testing"

// S9-01: the genesis block must commit to the whole genesis configuration,
// so two nodes started from different genesis.json files never share a
// genesis hash (GB) and never sync.
func TestGenesisConfigDigestCoversConsensusParamsAndStaking(t *testing.T) {
	base := Genesis{
		ChainID:           23,
		MinStakingForNode: 100,
		MaxGasUsage:       13_700_000,
		StakedBalances:    []GenesisStaking{{Account: "aa", Amount: 5, DelegatedAccount: 1}},
		Signature:         "sig-a",
	}
	d0, err := GenesisConfigDigest(base)
	if err != nil {
		t.Fatal(err)
	}

	again, _ := GenesisConfigDigest(base)
	if again != d0 {
		t.Fatal("digest must be deterministic")
	}

	resigned := base
	resigned.Signature = "sig-b"
	if d, _ := GenesisConfigDigest(resigned); d != d0 {
		t.Fatal("the header signature covers the digest, so it cannot be part of it")
	}

	changes := map[string]func(g *Genesis){
		"min staking": func(g *Genesis) { g.MinStakingForNode = 101 },
		"gas limit":   func(g *Genesis) { g.MaxGasUsage = 1 },
		"stake":       func(g *Genesis) { g.StakedBalances = []GenesisStaking{{Account: "aa", Amount: 6, DelegatedAccount: 1}} },
		"validator": func(g *Genesis) {
			g.StakedBalances = append(g.StakedBalances, GenesisStaking{Account: "bb", Amount: 5, DelegatedAccount: 2})
		},
	}
	for name, change := range changes {
		g := base
		g.StakedBalances = append([]GenesisStaking(nil), base.StakedBalances...)
		change(&g)
		if d, _ := GenesisConfigDigest(g); d == d0 {
			t.Errorf("%s: a different config produced the same digest", name)
		}
	}
}

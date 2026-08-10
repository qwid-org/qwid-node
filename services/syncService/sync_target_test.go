package syncServices

import (
	"testing"
	"time"

	"github.com/wonabru/qwid-node/common"
)

// withClaims installs a fresh peerHeightClaims map for the duration of fn.
func withClaims(t *testing.T, claims map[[4]byte]peerHeightClaim, fn func()) {
	t.Helper()
	peerHeightClaimsMutex.Lock()
	saved := peerHeightClaims
	peerHeightClaims = claims
	peerHeightClaimsMutex.Unlock()
	defer func() {
		peerHeightClaimsMutex.Lock()
		peerHeightClaims = saved
		peerHeightClaimsMutex.Unlock()
	}()
	fn()
}

func claim(height int64, age time.Duration) peerHeightClaim {
	return peerHeightClaim{height: height, timestamp: time.Now().Add(-age)}
}

func TestNetworkHeight(t *testing.T) {
	savedHint := common.CurrentHeightOfNetwork
	common.CurrentHeightOfNetwork = 23
	defer func() { common.CurrentHeightOfNetwork = savedHint }()

	tests := []struct {
		name   string
		claims map[[4]byte]peerHeightClaim
		want   int64
	}{
		{
			name:   "no claims falls back to the env hint",
			claims: map[[4]byte]peerHeightClaim{},
			want:   23,
		},
		{
			name:   "only expired claims fall back to the env hint",
			claims: map[[4]byte]peerHeightClaim{{1}: claim(105000, 2*ClaimExpiryDuration)},
			want:   23,
		},
		{
			name:   "single live peer is trusted",
			claims: map[[4]byte]peerHeightClaim{{1}: claim(105000, time.Second)},
			want:   105000,
		},
		{
			name: "two peers use the second highest so one liar cannot inflate",
			claims: map[[4]byte]peerHeightClaim{
				{1}: claim(999999, time.Second),
				{2}: claim(105000, time.Second),
			},
			want: 105000,
		},
		{
			name: "three peers use the second highest so one liar cannot deflate",
			claims: map[[4]byte]peerHeightClaim{
				{1}: claim(105000, time.Second),
				{2}: claim(105001, time.Second),
				{3}: claim(0, time.Second),
			},
			want: 105000,
		},
		{
			name: "expired claims are ignored when live ones exist",
			claims: map[[4]byte]peerHeightClaim{
				{1}: claim(105000, time.Second),
				{2}: claim(999999, 2*ClaimExpiryDuration),
			},
			want: 105000,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			withClaims(t, tc.claims, func() {
				if got := networkHeight(); got != tc.want {
					t.Fatalf("networkHeight() = %d, want %d", got, tc.want)
				}
			})
		})
	}
}

// TestBehindNetworkIgnoresHeightHint is the regression test for the reported bug:
// with HEIGHT_OF_NETWORK=0 the node used to declare itself synced after every
// sync batch and start producing its own blocks while 100k blocks behind.
func TestBehindNetworkIgnoresHeightHint(t *testing.T) {
	savedHint := common.CurrentHeightOfNetwork
	savedHeight := common.GetHeight()
	savedTarget := common.GetSyncTarget()
	defer func() {
		common.CurrentHeightOfNetwork = savedHint
		common.SetHeight(savedHeight)
		common.SetSyncTarget(savedTarget)
	}()

	common.CurrentHeightOfNetwork = 0
	common.SetHeight(500)

	withClaims(t, map[[4]byte]peerHeightClaim{{1}: claim(105000, time.Second)}, func() {
		updateSyncTarget()
		if got := common.GetSyncTarget(); got != 105000 {
			t.Fatalf("GetSyncTarget() = %d, want 105000", got)
		}
		if !common.IsBehindNetwork() {
			t.Fatal("node 104500 blocks behind must count as behind the network")
		}
	})
}

// TestNotBehindWithinTolerance guards the other direction: a node that is level
// with the network (or one block behind, which is the steady state) must be
// allowed to produce.
func TestNotBehindWithinTolerance(t *testing.T) {
	savedHint := common.CurrentHeightOfNetwork
	savedHeight := common.GetHeight()
	savedTarget := common.GetSyncTarget()
	defer func() {
		common.CurrentHeightOfNetwork = savedHint
		common.SetHeight(savedHeight)
		common.SetSyncTarget(savedTarget)
	}()

	common.CurrentHeightOfNetwork = 0
	common.SetHeight(105000)

	withClaims(t, map[[4]byte]peerHeightClaim{{1}: claim(105001, time.Second)}, func() {
		updateSyncTarget()
		if common.IsBehindNetwork() {
			t.Fatal("node one block behind the network must not count as behind")
		}
	})
}

// TestHeightHintOverridesPeers pins the configured behaviour: while the local
// height is below HEIGHT_OF_NETWORK the operator's figure wins outright, even
// when peers report a different height.
func TestHeightHintOverridesPeers(t *testing.T) {
	savedHint := common.CurrentHeightOfNetwork
	savedHeight := common.GetHeight()
	savedTarget := common.GetSyncTarget()
	defer func() {
		common.CurrentHeightOfNetwork = savedHint
		common.SetHeight(savedHeight)
		common.SetSyncTarget(savedTarget)
	}()

	common.CurrentHeightOfNetwork = 105000
	common.SetHeight(500)

	withClaims(t, map[[4]byte]peerHeightClaim{
		{1}: claim(200000, time.Second),
		{2}: claim(200000, time.Second),
	}, func() {
		updateSyncTarget()
		if got := common.GetSyncTarget(); got != 105000 {
			t.Fatalf("GetSyncTarget() = %d, want the configured 105000 to override the peer view", got)
		}
	})
}

// TestPeersTakeOverAboveHint is the other half: once the local chain reaches the
// configured height the setting is spent and the live peer view decides, so a
// stale HEIGHT_OF_NETWORK cannot pin the target below the real network height.
func TestPeersTakeOverAboveHint(t *testing.T) {
	savedHint := common.CurrentHeightOfNetwork
	savedHeight := common.GetHeight()
	savedTarget := common.GetSyncTarget()
	defer func() {
		common.CurrentHeightOfNetwork = savedHint
		common.SetHeight(savedHeight)
		common.SetSyncTarget(savedTarget)
	}()

	common.CurrentHeightOfNetwork = 105000
	common.SetHeight(105000)

	withClaims(t, map[[4]byte]peerHeightClaim{{1}: claim(200000, time.Second)}, func() {
		updateSyncTarget()
		if got := common.GetSyncTarget(); got != 200000 {
			t.Fatalf("GetSyncTarget() = %d, want the peer view 200000 once the hint is reached", got)
		}
		if !common.IsBehindNetwork() {
			t.Fatal("node 95000 blocks behind the peer view must count as behind")
		}
	})
}

// TestSyncTargetFloorsAtHint keeps HEIGHT_OF_NETWORK working as a cold-start
// lower bound: a node with no peers still must not consider itself synced below
// the configured height.
func TestSyncTargetFloorsAtHint(t *testing.T) {
	savedHint := common.CurrentHeightOfNetwork
	savedHeight := common.GetHeight()
	savedTarget := common.GetSyncTarget()
	defer func() {
		common.CurrentHeightOfNetwork = savedHint
		common.SetHeight(savedHeight)
		common.SetSyncTarget(savedTarget)
	}()

	common.CurrentHeightOfNetwork = 105000
	common.SetHeight(500)
	common.SetSyncTarget(0)

	if got := common.GetSyncTarget(); got != 105000 {
		t.Fatalf("GetSyncTarget() = %d, want the env hint 105000 as a floor", got)
	}
	if !common.IsBehindNetwork() {
		t.Fatal("node below the configured network height must count as behind")
	}
}

// TestShouldSyncToHeightStepsByBucket documents the throttled step used when not
// enough peers confirm a large height claim and the operator has not confirmed
// it either. The hint is pinned low: the test binary may inherit a real
// HEIGHT_OF_NETWORK from the environment, which would legitimately lift the
// throttle.
func TestShouldSyncToHeightStepsByBucket(t *testing.T) {
	savedHint := common.CurrentHeightOfNetwork
	common.CurrentHeightOfNetwork = 23
	defer func() { common.CurrentHeightOfNetwork = savedHint }()

	withClaims(t, map[[4]byte]peerHeightClaim{{1}: claim(105000, time.Second)}, func() {
		ok, target := shouldSyncToHeight(105000, 500)
		if !ok {
			t.Fatal("shouldSyncToHeight returned false for a higher claim")
		}
		if want := int64(500) + common.NumberOfHashesInBucket; target != want {
			t.Fatalf("throttled target = %d, want %d", target, want)
		}
	})
}

// TestShouldSyncToHeightTrustsOperatorHint: a claim within HEIGHT_OF_NETWORK is
// operator-confirmed and must be approved in full even with a single peer -
// this is what lets a lone-peer node sync at full speed instead of one bucket
// per round. Claims beyond the hint still need multi-peer consensus.
func TestShouldSyncToHeightTrustsOperatorHint(t *testing.T) {
	savedHint := common.CurrentHeightOfNetwork
	common.CurrentHeightOfNetwork = 110000
	defer func() { common.CurrentHeightOfNetwork = savedHint }()

	withClaims(t, map[[4]byte]peerHeightClaim{{1}: claim(105000, time.Second)}, func() {
		ok, target := shouldSyncToHeight(105000, 500)
		if !ok || target != 105000 {
			t.Fatalf("shouldSyncToHeight = %v, %d; oczekiwano pełnej wysokości 105000 "+
				"(deklaracja w granicach HEIGHT_OF_NETWORK)", ok, target)
		}
		// Beyond the operator hint the throttle still applies.
		ok, target = shouldSyncToHeight(120000, 500)
		if !ok || target != 500+common.NumberOfHashesInBucket {
			t.Fatalf("shouldSyncToHeight powyżej HEIGHT_OF_NETWORK = %v, %d; "+
				"oczekiwano dławienia do %d", ok, target, 500+common.NumberOfHashesInBucket)
		}
	})
}

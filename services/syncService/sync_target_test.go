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
// enough peers confirm a large height claim.
func TestShouldSyncToHeightStepsByBucket(t *testing.T) {
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

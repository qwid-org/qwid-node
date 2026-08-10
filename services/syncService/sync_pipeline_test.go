package syncServices

import (
	"testing"
	"time"

	"github.com/qwid-org/qwid-node/common"
)

// TestNextBatchTarget: after applying a batch the node asks the serving peer
// for the next one immediately instead of idling until its next 'hi' - but only
// when that peer still has something for us. A wrong "ask again" here would
// ping-pong empty batches forever; a wrong "don't ask" would put the 1-bucket-
// per-second cap right back.
func TestNextBatchTarget(t *testing.T) {
	savedHint := common.CurrentHeightOfNetwork
	common.CurrentHeightOfNetwork = 110000
	defer func() { common.CurrentHeightOfNetwork = savedHint }()

	peer := [4]byte{1, 2, 3, 4}

	tests := []struct {
		name       string
		claims     map[[4]byte]peerHeightClaim
		height     int64
		wantOK     bool
		wantTarget int64
	}{
		{
			name:   "brak deklaracji od tego peera",
			claims: map[[4]byte]peerHeightClaim{},
			height: 100200,
		},
		{
			name:   "deklaracja wygasła",
			claims: map[[4]byte]peerHeightClaim{peer: claim(105000, 2*ClaimExpiryDuration)},
			height: 100200,
		},
		{
			name:   "peer już nie jest wyżej - koniec pipeline'u",
			claims: map[[4]byte]peerHeightClaim{peer: claim(100200, time.Second)},
			height: 100200,
		},
		{
			name:       "peer wyżej w granicach HEIGHT_OF_NETWORK - pełny cel",
			claims:     map[[4]byte]peerHeightClaim{peer: claim(105000, time.Second)},
			height:     100200,
			wantOK:     true,
			wantTarget: 105000,
		},
		{
			name:       "peer wyżej ponad HEIGHT_OF_NETWORK - cel dławiony do kubełka",
			claims:     map[[4]byte]peerHeightClaim{peer: claim(120000, time.Second)},
			height:     100200,
			wantOK:     true,
			wantTarget: 100200 + common.NumberOfHashesInBucket,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			withClaims(t, tc.claims, func() {
				target, ok := nextBatchTarget(peer, tc.height)
				if ok != tc.wantOK {
					t.Fatalf("nextBatchTarget ok = %v, oczekiwano %v", ok, tc.wantOK)
				}
				if ok && target != tc.wantTarget {
					t.Fatalf("nextBatchTarget = %d, oczekiwano %d", target, tc.wantTarget)
				}
			})
		})
	}
}

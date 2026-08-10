package syncServices

import (
	"testing"
	"time"

	"github.com/qwid-org/qwid-node/common"
)

// TestRequestHeadersFromPeersAheadCountsLiveClaims: the counts this returns are
// what the stall log reports, and they are the only signal that distinguishes
// "we asked and got nothing back" from "we never had anyone to ask".
func TestRequestHeadersFromPeersAheadCountsLiveClaims(t *testing.T) {
	savedHeight := common.GetHeight()
	defer common.SetHeight(savedHeight)
	common.SetHeight(500)

	tests := []struct {
		name     string
		claims   map[[4]byte]peerHeightClaim
		wantSent int
		wantLive int
	}{
		{
			name:     "brak deklaracji",
			claims:   map[[4]byte]peerHeightClaim{},
			wantSent: 0,
			wantLive: 0,
		},
		{
			name:     "same przeterminowane deklaracje",
			claims:   map[[4]byte]peerHeightClaim{{1}: claim(105000, 2*ClaimExpiryDuration)},
			wantSent: 0,
			wantLive: 0,
		},
		{
			name:     "jeden peer wyżej",
			claims:   map[[4]byte]peerHeightClaim{{1}: claim(105000, time.Second)},
			wantSent: 1,
			wantLive: 1,
		},
		{
			name: "dwóch peerów wyżej",
			claims: map[[4]byte]peerHeightClaim{
				{1}: claim(105000, time.Second),
				{2}: claim(105001, time.Second),
			},
			wantSent: 2,
			wantLive: 2,
		},
		{
			name:     "peer żywy, ale nie wyżej od nas",
			claims:   map[[4]byte]peerHeightClaim{{1}: claim(400, time.Second)},
			wantSent: 0,
			wantLive: 1,
		},
		{
			name: "tylko peer wyżej dostaje zapytanie",
			claims: map[[4]byte]peerHeightClaim{
				{1}: claim(400, time.Second),
				{2}: claim(105000, time.Second),
			},
			wantSent: 1,
			wantLive: 2,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			withClaims(t, tc.claims, func() {
				sent, live := requestHeadersFromPeersAhead(common.GetHeight())
				if sent != tc.wantSent {
					t.Fatalf("wysłanych zapytań = %d, oczekiwano %d", sent, tc.wantSent)
				}
				if live != tc.wantLive {
					t.Fatalf("żywych deklaracji = %d, oczekiwano %d", live, tc.wantLive)
				}
			})
		})
	}
}

// TestRequestHeadersFromPeersAheadDoesNotDeadlock: the function reads
// peerHeightClaims under RLock and then calls shouldSyncToHeight, which takes the
// same lock. Holding it across that call would deadlock the sync loop.
func TestRequestHeadersFromPeersAheadDoesNotDeadlock(t *testing.T) {
	savedHeight := common.GetHeight()
	defer common.SetHeight(savedHeight)
	common.SetHeight(500)

	done := make(chan struct{})
	go func() {
		defer close(done)
		withClaims(t, map[[4]byte]peerHeightClaim{
			{1}: claim(105000, time.Second),
			{2}: claim(105000, time.Second),
			{3}: claim(105000, time.Second),
		}, func() {
			requestHeadersFromPeersAhead(common.GetHeight())
		})
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("requestHeadersFromPeersAhead zakleszczyło się na peerHeightClaimsMutex")
	}
}

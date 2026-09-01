package syncServices

import (
	"testing"
	"time"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/tcpip"
)

// withMyIP pins tcpip.MyIP for the duration of a test, so "is this address ours"
// does not depend on the interfaces of the machine running the suite.
func withMyIP(t *testing.T, ip [4]byte) {
	t.Helper()
	saved := tcpip.MyIP
	tcpip.MyIP = ip
	t.Cleanup(func() { tcpip.MyIP = saved })
}

var loopback = [4]byte{127, 0, 0, 1}

// TestRecordPeerHeightClaimIgnoresSelf: a node holds a sync connection to its own
// listener, so its 'hi' comes straight back. Recorded as a claim, that echo is a
// phantom peer sitting at exactly our height - and right after the stall
// watchdog rewinds, above it.
func TestRecordPeerHeightClaimIgnoresSelf(t *testing.T) {
	withMyIP(t, [4]byte{10, 0, 0, 7})

	withClaims(t, map[[4]byte]peerHeightClaim{}, func() {
		recordPeerHeightClaim(loopback, 100180, nil)
		recordPeerHeightClaim(tcpip.MyIP, 100180, nil)
		recordPeerHeightClaim([4]byte{178, 182, 254, 9}, 110000, nil)

		peerHeightClaimsMutex.RLock()
		defer peerHeightClaimsMutex.RUnlock()
		if _, ok := peerHeightClaims[loopback]; ok {
			t.Fatal("a height claim from 127.0.0.1 was recorded as a peer")
		}
		if _, ok := peerHeightClaims[tcpip.MyIP]; ok {
			t.Fatal("a height claim from our own address was recorded as a peer")
		}
		if len(peerHeightClaims) != 1 {
			t.Fatalf("recorded claims = %d, expected 1 (the real peer only)", len(peerHeightClaims))
		}
	})
}

// TestRequestHeadersFromPeersAheadIgnoresSelfClaim reproduces the loop seen in
// production: after a rewind our own pre-rewind height is still on record and
// looks like a peer that is ahead, so the node asks itself for the batch and
// answers itself with blocks it already has.
func TestRequestHeadersFromPeersAheadIgnoresSelfClaim(t *testing.T) {
	withMyIP(t, [4]byte{10, 0, 0, 7})
	savedHeight := common.GetHeight()
	defer common.SetHeight(savedHeight)
	common.SetHeight(100178)

	withClaims(t, map[[4]byte]peerHeightClaim{
		loopback:     claim(100180, time.Second),
		tcpip.MyIP:   claim(100180, time.Second),
		{1, 2, 3, 4}: claim(100177, time.Second),
	}, func() {
		sent, live := requestHeadersFromPeersAhead(common.GetHeight())
		if sent != 0 {
			t.Fatalf("requests sent = %d, expected 0 - the node is querying itself", sent)
		}
		if live != 1 {
			t.Fatalf("live claims = %d, expected 1 (our own addresses do not count)", live)
		}
	})
}

// TestNetworkHeightIgnoresSelfClaim: our own echoed height must not stand in for
// a peer's view of the network, or a node alone on the network would keep
// confirming its own target.
func TestNetworkHeightIgnoresSelfClaim(t *testing.T) {
	withMyIP(t, [4]byte{10, 0, 0, 7})
	savedHint := common.CurrentHeightOfNetwork
	common.CurrentHeightOfNetwork = 23
	defer func() { common.CurrentHeightOfNetwork = savedHint }()

	withClaims(t, map[[4]byte]peerHeightClaim{
		loopback:   claim(100180, time.Second),
		tcpip.MyIP: claim(100180, time.Second),
	}, func() {
		if got := networkHeight(); got != 23 {
			t.Fatalf("networkHeight() = %d, expected 23 - only our own claims means no peers", got)
		}
	})
}

// TestPeersAheadIgnoresOurOwnClaims: the watchdog decides what to do from who
// is genuinely ahead, and our own claim - echoed back by the self-connection -
// must never count as a peer. When it did, the node acted on its own height and
// the stall handling chased itself.
func TestPeersAheadIgnoresOurOwnClaims(t *testing.T) {
	withMyIP(t, [4]byte{10, 0, 0, 7})

	tests := []struct {
		name       string
		claims     map[[4]byte]peerHeightClaim
		wantUseful bool
		wantLive   int
	}{
		{
			name:   "no claims",
			claims: map[[4]byte]peerHeightClaim{},
		},
		{
			name:   "only our own loopback claim",
			claims: map[[4]byte]peerHeightClaim{loopback: claim(100180, time.Second)},
		},
		{
			name:   "only our own claim from NODE_IP",
			claims: map[[4]byte]peerHeightClaim{{10, 0, 0, 7}: claim(100180, time.Second)},
		},
		{
			name:     "peer alive but not ahead",
			claims:   map[[4]byte]peerHeightClaim{{1, 2, 3, 4}: claim(100178, time.Second)},
			wantLive: 1,
		},
		{
			name:   "peer ahead but expired",
			claims: map[[4]byte]peerHeightClaim{{1, 2, 3, 4}: claim(110000, 2*ClaimExpiryDuration)},
		},
		{
			name:       "a real peer ahead",
			claims:     map[[4]byte]peerHeightClaim{{1, 2, 3, 4}: claim(110000, time.Second)},
			wantUseful: true,
			wantLive:   1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			withClaims(t, tc.claims, func() {
				ahead, live := peersAhead(100178)
				if (len(ahead) > 0) != tc.wantUseful {
					t.Fatalf("peersAhead() found %d peers ahead, expected any=%v", len(ahead), tc.wantUseful)
				}
				if live != tc.wantLive {
					t.Fatalf("live claims = %d, expected %d", live, tc.wantLive)
				}
			})
		})
	}
}

// TestStallWatchdogDoesNotRewindWithSelfClaimOnly: the watchdog must never move
// the chain backwards. Rewinding on a stall has been removed outright - it
// destroyed confirmed local state to recover from a lost message, and could not
// tell that case apart from the several others that look identical from here.
// This exercises the whole path and asserts the height is untouched.
func TestStallWatchdogDoesNotRewindWithSelfClaimOnly(t *testing.T) {
	withMyIP(t, [4]byte{10, 0, 0, 7})
	resetProgress(t)
	common.IsSyncing.Store(true)
	common.SetHeight(100178)

	now := time.Now()
	withClaims(t, map[[4]byte]peerHeightClaim{loopback: claim(100180, time.Second)}, func() {
		checkSyncStall(now)
		checkSyncStall(now.Add(2 * SyncStallTimeout))
	})

	if got := common.GetHeight(); got != 100178 {
		t.Fatalf("height = %d, expected 100178 - the chain was rewound with no peer able to send the batch back", got)
	}
	// The clock must be re-armed, or the "nothing to ask" message would repeat on
	// every pass of the send loop instead of once per timeout.
	if !progress.since.Equal(now.Add(2 * SyncStallTimeout)) {
		t.Fatalf("stall clock = %v, expected it to be reset to %v", progress.since, now.Add(2*SyncStallTimeout))
	}
}

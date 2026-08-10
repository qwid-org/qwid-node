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
			t.Fatal("deklaracja wysokości z 127.0.0.1 została zapisana jako peer")
		}
		if _, ok := peerHeightClaims[tcpip.MyIP]; ok {
			t.Fatal("deklaracja wysokości z własnego adresu została zapisana jako peer")
		}
		if len(peerHeightClaims) != 1 {
			t.Fatalf("zapisanych deklaracji = %d, oczekiwano 1 (tylko prawdziwy peer)", len(peerHeightClaims))
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
			t.Fatalf("wysłanych zapytań = %d, oczekiwano 0 - węzeł pyta sam siebie", sent)
		}
		if live != 1 {
			t.Fatalf("żywych deklaracji = %d, oczekiwano 1 (własne adresy się nie liczą)", live)
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
			t.Fatalf("networkHeight() = %d, oczekiwano 23 - same własne deklaracje to brak peerów", got)
		}
	})
}

// TestStallRewindUseful: rewinding is only a way to make a peer re-send a batch.
// With nobody above us to ask, it gives back SyncStallRewind blocks every
// timeout and the chain walks backwards for as long as the node runs - which is
// exactly what a self-connection produced, its claim mirroring our own height
// one rewind behind.
func TestStallRewindUseful(t *testing.T) {
	withMyIP(t, [4]byte{10, 0, 0, 7})

	tests := []struct {
		name       string
		claims     map[[4]byte]peerHeightClaim
		wantUseful bool
		wantLive   int
	}{
		{
			name:   "brak deklaracji",
			claims: map[[4]byte]peerHeightClaim{},
		},
		{
			name:   "tylko własna deklaracja z pętli zwrotnej",
			claims: map[[4]byte]peerHeightClaim{loopback: claim(100180, time.Second)},
		},
		{
			name:   "tylko własna deklaracja z NODE_IP",
			claims: map[[4]byte]peerHeightClaim{{10, 0, 0, 7}: claim(100180, time.Second)},
		},
		{
			name:     "peer żywy, ale nie wyżej",
			claims:   map[[4]byte]peerHeightClaim{{1, 2, 3, 4}: claim(100178, time.Second)},
			wantLive: 1,
		},
		{
			name:   "peer wyżej, ale wygasły",
			claims: map[[4]byte]peerHeightClaim{{1, 2, 3, 4}: claim(110000, 2*ClaimExpiryDuration)},
		},
		{
			name:       "prawdziwy peer wyżej",
			claims:     map[[4]byte]peerHeightClaim{{1, 2, 3, 4}: claim(110000, time.Second)},
			wantUseful: true,
			wantLive:   1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			withClaims(t, tc.claims, func() {
				useful, live := stallRewindUseful(100178)
				if useful != tc.wantUseful {
					t.Fatalf("stallRewindUseful() = %v, oczekiwano %v", useful, tc.wantUseful)
				}
				if live != tc.wantLive {
					t.Fatalf("żywych deklaracji = %d, oczekiwano %d", live, tc.wantLive)
				}
			})
		})
	}
}

// TestStallWatchdogDoesNotRewindWithSelfClaimOnly: the whole watchdog path, from
// the production scenario - syncing, standing still, and the only height claim
// on record is our own from before the last rewind.
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
		t.Fatalf("height = %d, oczekiwano 100178 - cofnięto łańcuch bez peera, który mógłby odesłać batch", got)
	}
	// The clock must be re-armed, or the "nothing to ask" message would repeat on
	// every pass of the send loop instead of once per timeout.
	if !progress.since.Equal(now.Add(2 * SyncStallTimeout)) {
		t.Fatalf("zegar zastoju = %v, oczekiwano przestawienia na %v", progress.since, now.Add(2*SyncStallTimeout))
	}
}

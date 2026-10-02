package syncServices

import (
	"testing"
	"time"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/tcpip"
)

func handleFor(t *testing.T, tag byte, realIP [4]byte) [4]byte {
	t.Helper()
	var id common.Address
	id.ByteValue[0], id.ByteValue[1] = 0xC1, tag
	return tcpip.HandleForPeer(id, realIP)
}

// S2-03: two keys behind one source IP are one witness, not two - they must
// not "corroborate" a height and stop block production.
func TestClaimsFromOneSourceDoNotCorroborate(t *testing.T) {
	src := [4]byte{203, 0, 113, 90}
	h1, h2 := handleFor(t, 1, src), handleFor(t, 2, src)
	now := time.Now()
	withClaims(t, map[[4]byte]peerHeightClaim{
		h1: {height: 1_000_000, timestamp: now},
		h2: {height: 1_000_000, timestamp: now},
	}, func() {
		if got := corroboratedNetworkHeight(); got != 0 {
			t.Fatalf("two handles of one source IP corroborated height %d", got)
		}
	})
}

// Two independent sources still corroborate.
func TestClaimsFromTwoSourcesCorroborate(t *testing.T) {
	h1 := handleFor(t, 3, [4]byte{203, 0, 113, 91})
	h2 := handleFor(t, 4, [4]byte{203, 0, 113, 92})
	now := time.Now()
	withClaims(t, map[[4]byte]peerHeightClaim{
		h1: {height: 500, timestamp: now},
		h2: {height: 400, timestamp: now},
	}, func() {
		if got := corroboratedNetworkHeight(); got != 400 {
			t.Fatalf("corroborated height %d, want the second-highest independent claim 400", got)
		}
	})
}

// The large-sync quorum counts sources too.
func TestLargeSyncQuorumCountsSources(t *testing.T) {
	saved := syncPeerCount
	syncPeerCount = func() int { return 10 }
	t.Cleanup(func() { syncPeerCount = saved })
	savedQ := common.MinPeersForLargeSync
	common.MinPeersForLargeSync = 3
	t.Cleanup(func() { common.MinPeersForLargeSync = savedQ })
	src := [4]byte{203, 0, 113, 93}
	now := time.Now()
	claims := map[[4]byte]peerHeightClaim{}
	for i := byte(10); i < 13; i++ {
		claims[handleFor(t, i, src)] = peerHeightClaim{height: 1_000_000, timestamp: now}
	}
	withClaims(t, claims, func() {
		ok, target := shouldSyncToHeight(1_000_000, 100)
		if ok && target == 1_000_000 {
			t.Fatal("three keys of one source satisfied the three-peer quorum")
		}
	})
}

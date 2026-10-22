package syncServices

import (
	"testing"
	"time"

	"github.com/qwid-org/qwid-node/common"
)

// HeightMax only ever grew: one wrong height claim - a forked or misconfigured
// peer, a stale HEIGHT_OF_NETWORK - pinned the network height shown by the
// stats and the UI, and fed the rewind-depth heuristic, until the node was
// restarted. It now follows the live view and forgets an expired claim.
func TestHeightMaxForgetsAnExpiredClaim(t *testing.T) {
	savedHint, savedHeight, savedMax := common.CurrentHeightOfNetwork, common.GetHeight(), common.GetHeightMax()
	defer func() {
		common.CurrentHeightOfNetwork = savedHint
		common.SetHeight(savedHeight)
		common.SetHeightMax(savedMax)
	}()
	common.CurrentHeightOfNetwork = 0
	common.SetHeight(500)

	withClaims(t, map[[4]byte]peerHeightClaim{{1}: claim(999999, time.Second)}, func() {
		updateSyncTarget()
		if got := common.GetHeightMax(); got != 999999 {
			t.Fatalf("HeightMax = %d, want the live claim 999999", got)
		}
	})
	// The wrong claim is gone; honest peers report 510.
	withClaims(t, map[[4]byte]peerHeightClaim{
		{1}: claim(999999, ClaimExpiryDuration+time.Minute), // expired
		{2}: claim(510, time.Second),
	}, func() {
		updateSyncTarget()
		if got := common.GetHeightMax(); got != 510 {
			t.Fatalf("HeightMax = %d after the wrong claim expired, want 510", got)
		}
	})
}

// HeightMax is the PEERS' height: the node's own height never enters it, even
// when the peers are behind, and neither does the HEIGHT_OF_NETWORK setting.
func TestHeightMaxIsPeersOnly(t *testing.T) {
	savedHint, savedHeight, savedMax := common.CurrentHeightOfNetwork, common.GetHeight(), common.GetHeightMax()
	defer func() {
		common.CurrentHeightOfNetwork = savedHint
		common.SetHeight(savedHeight)
		common.SetHeightMax(savedMax)
	}()
	common.SetHeight(700)
	withClaims(t, map[[4]byte]peerHeightClaim{{1}: claim(650, time.Second)}, func() {
		updateSyncTarget()
		if got := common.GetHeightMax(); got != 650 {
			t.Fatalf("HeightMax = %d, want the peers' 650, not the node's own 700", got)
		}
	})
	common.SetHeightMax(123) // marker: must stay, nothing live to replace it
	common.CurrentHeightOfNetwork = 99999
	withClaims(t, map[[4]byte]peerHeightClaim{{1}: claim(650, ClaimExpiryDuration+time.Minute)}, func() {
		updateSyncTarget()
		if got := common.GetHeightMax(); got != 123 {
			t.Fatalf("HeightMax = %d with no live peer claim; the HEIGHT_OF_NETWORK setting must not enter it", got)
		}
	})
}

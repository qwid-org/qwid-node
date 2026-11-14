package nonceServices

import (
	"testing"

	"github.com/qwid-org/qwid-node/common"
)

// Audit 2026-11-13: every distinct nonce made a node build a block candidate,
// and one validator could sign any number of distinct nonces for one height.
// One nonce per validator and height is acted on; our own nonces are the
// once-a-second trigger of our production and are exempt. A nonce sent from
// a clock far from ours is not acted on.
func TestOneNoncePerValidatorAndHeight(t *testing.T) {
	resetSeenNonces()
	var self, other common.Address
	self.ByteValue[0], other.ByteValue[0] = 1, 2
	now := int64(1_000_000)
	if !acceptNonceFrom(other, self, now, now, 50, 49) {
		t.Fatal("the first nonce of a validator for a height was refused")
	}
	if acceptNonceFrom(other, self, now+1, now+1, 50, 49) {
		t.Fatal("a second nonce of the same validator for the same height was accepted")
	}
	if !acceptNonceFrom(other, self, now+10, now+10, 51, 50) {
		t.Fatal("the validator's nonce for the next height was refused")
	}
	for i := int64(0); i < 3; i++ {
		if !acceptNonceFrom(self, self, now+i, now+i, 51, 50) {
			t.Fatal("our own repeated nonce was refused: it triggers our production every second")
		}
	}
	var third common.Address
	third.ByteValue[0] = 3
	if acceptNonceFrom(third, self, now-common.MaxBlockForwardInTime-1, now, 51, 50) ||
		acceptNonceFrom(third, self, now+common.MaxBlockForwardInTime+1, now, 51, 50) {
		t.Fatal("a nonce sent from a clock outside the tolerance was accepted")
	}
	if !acceptNonceFrom(third, self, now-common.MaxBlockForwardInTime, now, 51, 50) {
		t.Fatal("a nonce within the clock tolerance was refused")
	}
}

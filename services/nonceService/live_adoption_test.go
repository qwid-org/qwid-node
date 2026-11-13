package nonceServices

import (
	"testing"

	"github.com/qwid-org/qwid-node/common"
)

// A block from the near future waits for its second; a stale one is left to
// sync (it was produced long ago and held back).
func TestLiveAdoptionTiming(t *testing.T) {
	now := int64(1_000_000)
	f := common.MaxBlockForwardInTime
	for _, c := range []struct {
		ts    int64
		wait  int64
		adopt bool
	}{
		{now, 0, true},
		{now - f, 0, true},
		{now - f - 1, 0, false},
		{now + 3, 3, true},
		{now + f, f, true},
		{now + f + 1, 0, true}, // invalid: validation refuses it
	} {
		wait, adopt := liveAdoption(c.ts, now)
		if wait != c.wait || adopt != c.adopt {
			t.Errorf("ts=now%+d: wait %d adopt %v, want %d %v", c.ts-now, wait, adopt, c.wait, c.adopt)
		}
	}
}

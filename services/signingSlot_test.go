package services

import "testing"

// A node must never emit a signature peers cannot verify: they treat it as a
// forgery and ban the node, which then cannot even follow the chain (found in
// the recovery-commitment harness: a validator without a key of a freshly
// un-paused scheme kept sending nonces and was cut off at the next block).
func TestSigningSlotNeedsARegisteredKeyOfALiveScheme(t *testing.T) {
	type slots struct{ pausedP, pausedS, regP, regS bool }
	cases := []struct {
		name      string
		preferred bool
		s         slots
		want, ok  bool
	}{
		{"live primary with its key", true, slots{false, true, true, true}, true, true},
		{"live primary without a key, spare paused", true, slots{false, true, false, true}, true, false},
		{"live spare without a key falls back to a live primary", false, slots{false, false, true, false}, true, true},
		{"live spare without a key, primary paused", false, slots{true, false, true, false}, false, false},
		{"live spare with its key", false, slots{true, false, false, true}, false, true},
	}
	for _, c := range cases {
		paused := func(primary bool) bool {
			if primary {
				return c.s.pausedP
			}
			return c.s.pausedS
		}
		registered := func(primary bool) bool {
			if primary {
				return c.s.regP
			}
			return c.s.regS
		}
		got, ok := signingSlot(c.preferred, paused, registered)
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("%s: got (%v, %v), want (%v, %v)", c.name, got, ok, c.want, c.ok)
		}
	}
}

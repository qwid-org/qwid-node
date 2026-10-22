package services

import (
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/pubkeys"
)

// signingSlot picks the slot this node may sign with: the preferred one, else
// the other, provided the slot's scheme is live and the node's key of that
// scheme is registered on-chain. ok=false means no such slot exists - the
// node then must not sign anything peers would verify (nonces, headers):
// such a signature reads as a forgery and gets the node banned, cutting it
// off from the chain it can still follow.
func signingSlot(preferred bool, paused func(primary bool) bool, registered func(primary bool) bool) (primary bool, ok bool) {
	for _, slot := range []bool{preferred, !preferred} {
		if !paused(slot) && registered(slot) {
			return slot, true
		}
	}
	return preferred, false
}

// SigningSlot is signingSlot against the node's current scheme config and the
// live key registry.
func SigningSlot(addr common.Address, preferred bool) (bool, bool) {
	paused := func(primary bool) bool {
		if primary {
			return common.IsPaused()
		}
		return common.IsPaused2()
	}
	registered := func(primary bool) bool {
		n := common.PubKeyLength2(false)
		if primary {
			n = common.PubKeyLength(false)
		}
		_, err := pubkeys.LoadPubKeyWithPrimaryOfLength(addr, primary, n)
		return err == nil
	}
	return signingSlot(preferred, paused, registered)
}

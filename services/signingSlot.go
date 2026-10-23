package services

import (
	"bytes"

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
// live key registry. ownPrimary/ownSecondary are this node's public keys: a
// slot counts as registered only when THAT key is - two schemes can share a
// key length (Falcon-512 and Falcon-padded-512, 897 bytes), so a registered
// key of the right length may be a superseded scheme's, and signing with the
// node's unregistered new key would read as a forgery.
func SigningSlot(addr common.Address, preferred bool, ownPrimary, ownSecondary []byte) (bool, bool) {
	paused := func(primary bool) bool {
		if primary {
			return common.IsPaused()
		}
		return common.IsPaused2()
	}
	registered := func(primary bool) bool {
		n, own := common.PubKeyLength2(false), ownSecondary
		if primary {
			n, own = common.PubKeyLength(false), ownPrimary
		}
		if len(own) == 0 {
			return false
		}
		addrs, err := pubkeys.LoadAddresses(addr)
		if err != nil {
			return false
		}
		for _, a := range addrs {
			pk, err := pubkeys.LoadPubKey(a.GetBytes())
			if err == nil && len(pk.GetBytes()) == n && bytes.Equal(pk.GetBytes(), own) {
				return true
			}
		}
		return false
	}
	return signingSlot(preferred, paused, registered)
}

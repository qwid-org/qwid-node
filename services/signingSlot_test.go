package services

import (
	"bytes"
	"testing"

	"github.com/qwid-org/qwid-node/blocks"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/pubkeys"
)

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

// Two schemes can have keys of the same length (Falcon-512 and
// Falcon-padded-512: 897 bytes). A node whose registered key is the OLD
// scheme's must not take it for a key of the new one: it would sign with its
// unregistered new key, peers would see a forged signature and ban it.
func TestSigningSlotNeedsThisNodesOwnKeyRegistered(t *testing.T) {
	withTempDB(t)
	saved := pubkeys.GlobalMerkleTree
	pubkeys.InitPermanentTrie()
	t.Cleanup(func() { pubkeys.GlobalMerkleTree = saved })

	n := common.PubKeyLength(false)
	oldKey := bytes.Repeat([]byte{1}, n) // registered: the superseded scheme's key
	newKey := bytes.Repeat([]byte{2}, n) // this node's key of the current scheme
	addr, err := common.PubKeyToAddress(oldKey, true)
	if err != nil {
		t.Fatal(err)
	}
	var pk common.PubKey
	if err := pk.Init(oldKey, addr); err != nil {
		t.Skipf("cannot build key: %v", err)
	}
	pk.MainAddress = addr
	if err := blocks.StorePubKey(pk); err != nil {
		t.Fatal(err)
	}
	if err := blocks.StorePubKeyInPatriciaTrie(pk); err != nil {
		t.Fatal(err)
	}

	if _, ok := SigningSlot(addr, true, newKey, nil); ok {
		t.Fatal("a same-length key of another scheme was taken for this node's registered key")
	}
	if slot, ok := SigningSlot(addr, true, oldKey, nil); !ok || !slot {
		t.Fatal("this node's own registered key was not found")
	}
}

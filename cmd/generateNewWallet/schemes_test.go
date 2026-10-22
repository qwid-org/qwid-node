package main

import (
	"testing"

	"github.com/qwid-org/qwid-node/common"
)

func addrOf(b byte) common.Address {
	var a common.Address
	a.ByteValue[0] = b
	return a
}

// Restoring from a phrase must land on the identity the phrase already owns on
// chain - which key its address came from depends on the schemes at creation
// (the defaults, a later primary, or the live spare during a pause) - not on
// whatever key the generator happens to derive first.
func TestRestorePicksTheIdentityKnownOnChain(t *testing.T) {
	cands := []identityCandidate{
		{addrOf(1), "current primary"},
		{addrOf(2), "current spare"},
		{addrOf(3), "default primary"},
	}
	known := func(a common.Address) bool { return a == addrOf(3) }
	got, ok := chooseRestoredIdentity(cands, known)
	if !ok || got.addr != addrOf(3) {
		t.Fatalf("picked %+v (%v), want the on-chain identity 3", got, ok)
	}
	if _, ok := chooseRestoredIdentity(cands, func(common.Address) bool { return false }); ok {
		t.Fatal("reported an on-chain identity although none is known")
	}
}

func TestCandidatesAreDeduplicated(t *testing.T) {
	c := identityCandidates([]identityCandidate{{addrOf(1), "a"}, {addrOf(1), "b"}, {addrOf(2), "c"}})
	if len(c) != 2 {
		t.Fatalf("got %d candidates, want 2", len(c))
	}
}

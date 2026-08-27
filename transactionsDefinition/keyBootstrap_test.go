package transactionsDefinition

import (
	"testing"

	"github.com/qwid-org/qwid-node/common"
)

func addr(t *testing.T, first byte) common.Address {
	t.Helper()
	b := make([]byte, common.AddressLength)
	for i := range b {
		b[i] = first + byte(i)
	}
	a := common.Address{}
	if err := a.Init(b); err != nil {
		t.Fatalf("could not build an address: %v", err)
	}
	return a
}

// The rule that decides whether a key with no on-chain history may open an
// account. Registration is not a prerequisite for holding a balance, so an
// unregistered address can be funded; binding a key to it hands its holder the
// power to sign as it.
func TestBootstrapRequiresTheKeyToDeriveTheIdentity(t *testing.T) {
	victim := addr(t, 0x10)
	attackerKey := addr(t, 0x90)

	// The attack the old rule allowed: a spare key, whose own address is
	// necessarily different from the identity, sent while naming the victim.
	// It used to be accepted on the strength of that claim alone.
	if bootstrapBindsKey(attackerKey, victim) {
		t.Fatal("a key that does not derive the sender address opened its account")
	}

	// The one first-key claim that is self-proving: the address IS the key.
	if !bootstrapBindsKey(victim, victim) {
		t.Fatal("a key that derives the sender address was refused")
	}
}

// Separate from who may register the key: which identity the key claims.
// ProcessBlockPubKey stores that claim verbatim, so it needs checking on every
// path, not only on the bootstrap one.
func TestKeyMustNameItsSender(t *testing.T) {
	sender := addr(t, 0x10)
	other := addr(t, 0x40)

	if keyNamesSender(other, sender) {
		t.Fatal("a key naming a different identity than its sender was accepted")
	}
	if !keyNamesSender(sender, sender) {
		t.Fatal("a key naming its own sender was refused")
	}
	// An unset claim must not pass either: zero is not the sender.
	if keyNamesSender(common.Address{}, sender) {
		t.Fatal("a key with no stated identity was accepted")
	}
}

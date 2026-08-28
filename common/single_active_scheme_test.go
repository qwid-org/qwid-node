package common

import "testing"

// Exactly one signature scheme may be usable at any moment, and there must
// always be one. The secondary is a SPARE: paused while the primary works, and
// unpaused precisely when the primary is paused, so it can take over — that is
// what makes a pause recoverable, since votes and the block that records their
// outcome both need a scheme that verifies.
//
// The two states are therefore not independent, and IsPaused2 is derived rather
// than stored: an independent flag can be set to a combination that has both
// schemes live at once, or neither, and "neither" freezes the chain with no way
// back.
func TestExactlyOneSchemeIsActive(t *testing.T) {
	// Reset to the starting configuration so the assertions below describe a
	// fresh node rather than whatever an earlier test left behind.
	encryptionConfigInstance = newEncryptionConfig()

	if IsPaused() {
		t.Fatal("a fresh node starts with the primary scheme paused")
	}
	if !IsPaused2() {
		t.Fatal("a fresh node starts with the spare scheme live; it must be paused until the primary is")
	}

	// Pause the primary: the spare must take over in the same breath.
	GetEncryptionConfigInstance().SetEncryption(SigName(), PubKeyLength(false), PrivateKeyLength(), SignatureLength(false), true, true)

	if !IsPaused() {
		t.Fatal("pausing the primary did not take effect")
	}
	if IsPaused2() {
		t.Fatal("the primary is paused and the spare is still paused too: nothing can sign, and the pause cannot be undone")
	}

	// Unpause: the spare goes back into reserve.
	GetEncryptionConfigInstance().SetEncryption(SigName(), PubKeyLength(false), PrivateKeyLength(), SignatureLength(false), false, true)

	if IsPaused() {
		t.Fatal("unpausing the primary did not take effect")
	}
	if !IsPaused2() {
		t.Fatal("the primary is live again and the spare stayed live too: two schemes are usable at once")
	}
}

// Whatever is written into the secondary slot, the invariant holds — the slot
// carries WHICH algorithm the spare is, never WHETHER it is live.
func TestSecondarySlotCannotTurnItselfOn(t *testing.T) {
	// Reset to the starting configuration so the assertions below describe a
	// fresh node rather than whatever an earlier test left behind.
	encryptionConfigInstance = newEncryptionConfig()

	GetEncryptionConfigInstance().SetEncryption("Falcon-1024", 1793, 2305, 1280, false, false)

	if IsPaused2() {
		// primary is live, so the spare must be paused
		return
	}
	t.Fatal("writing the secondary slot with isPaused=false made two schemes live at once")
}

package blocks

import (
	"testing"

	"github.com/qwid-org/qwid-node/common"
)

// Empty Encryption1/Encryption2 bytes in a header mean "unchanged — whatever
// the current config is", and headers legitimately carry them (see the "no need
// to change encryption, so leave encryption 2 empty" path). Expanding them must
// therefore always succeed: describing a scheme is not the same question as
// being allowed to sign with it.
//
// Gating the expansion on the scheme being live broke every block carrying an
// empty slot once the spare became paused by default — GetSigNames failed, and
// with it block verification, node startup and oracle-proof checks.
func TestEmptyEncryptionBytesExpandEvenWhenSchemePaused(t *testing.T) {
	// Normal state: primary live, spare paused.
	enc2, err := FromBytesToEncryptionConfig([]byte{}, false)
	if err != nil {
		t.Fatalf("empty secondary bytes failed to expand while the spare is paused: %v", err)
	}
	if enc2.SigName != common.SigName2() {
		t.Fatalf("expanded secondary = %q, expected the current spare %q", enc2.SigName, common.SigName2())
	}
	if enc2.IsPaused != common.IsPaused2() {
		t.Fatalf("expanded secondary IsPaused = %v, expected %v — the flag is data to report, not a precondition",
			enc2.IsPaused, common.IsPaused2())
	}

	enc1, err := FromBytesToEncryptionConfig([]byte{}, true)
	if err != nil {
		t.Fatalf("empty primary bytes failed to expand: %v", err)
	}
	if enc1.SigName != common.SigName() {
		t.Fatalf("expanded primary = %q, expected %q", enc1.SigName, common.SigName())
	}
	if enc1.IsPaused != common.IsPaused() {
		t.Fatalf("expanded primary IsPaused = %v, expected %v", enc1.IsPaused, common.IsPaused())
	}
}

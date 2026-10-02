package blocks

// Fuzz target for the block decoder (AUDIT_PLAN_2026-09-25 Phase 3). Blocks
// arrive from the wire on the sync path; the decoder must never panic on
// hostile bytes (QWID-2026-17 remediation is the lock-in for the known slice
// cases; this target sweeps the whole decoder).

import (
	"testing"
)

func FuzzBlockGetFromBytes(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 0})
	f.Add(make([]byte, 40))
	f.Add(make([]byte, 100))
	f.Add([]byte{0x00, 0x00, 0x00, 0x17, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = (Block{}).GetFromBytes(b)
	})
}

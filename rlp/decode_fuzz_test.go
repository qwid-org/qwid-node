package rlp

// Fuzz target for the RLP decoder (AUDIT_PLAN_2026-09-25 Phase 5). The fork
// is upstream-verbatim per the audit provenance; this target guards the
// decoder against panics on hostile wire bytes that reach EVM transaction
// data decoding.

import (
	"testing"
)

func FuzzDecodeBytes(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x80})
	f.Add([]byte{0x81, 0x01})
	f.Add([]byte{0x84, 0x01, 0x02, 0x03, 0x04})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	f.Add([]byte{0x3f, 0x3f, 0x3f, 0x3f, 0x3f, 0x3f, 0x3f, 0x3f})
	f.Fuzz(func(t *testing.T, b []byte) {
		var out []interface{}
		_ = DecodeBytes(b, &out)
	})
}

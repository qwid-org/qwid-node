package message

// Fuzz targets for the wire-message decoder (AUDIT_PLAN_2026-09-25 Phase 3).
// The decoder is the first untrusted surface an unauthenticated Internet peer
// reaches: hostile frames must decode without a panic or an unbounded
// allocation. These targets reuse the production entry points and assert only
// "no panic" — the decoder already rejects malformed input with errors.

import (
	"testing"
)

// FuzzTransactionsMessageGetFromBytes feeds arbitrary bytes to the wire-message
// decoder. A panic here is a remote crash for every node (the receive loop
// calls this on the first bytes of every inbound frame).
func FuzzTransactionsMessageGetFromBytes(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x74, 0x78, 0x00, 0x17}) // "tx" head, chain id 23
	f.Add([]byte{0x74, 0x78, 0x00, 0x17, 0, 0, 0, 1})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	f.Add([]byte{0x62, 0x7a, 0x00, 0x17, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = (TransactionsMessage{}).GetFromBytes(b)
	})
}

// FuzzCheckValidMessage runs the full message-admission check on arbitrary
// bytes — the path a node applies to decide whether a frame is worth routing.
func FuzzCheckValidMessage(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x74, 0x78, 0x00, 0x17})
	f.Add([]byte{0x00, 0x00, 0x00, 0x00})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = CheckValidMessage(b)
	})
}

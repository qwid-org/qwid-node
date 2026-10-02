package transactionsDefinition

// Fuzz target for the transaction decoder (AUDIT_PLAN_2026-09-25 Phase 3).
// A transaction arrives from the wire on the tx/gossip and sync paths; the
// decoder must never panic on hostile bytes (QWID-2026-03/-17 remediations are
// the lock-in for the known cases; this target sweeps the whole decoder).

import (
	"testing"
)

func FuzzTransactionGetFromBytes(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 0})
	f.Add([]byte{0, 0, 0, 1, 0, 0, 0, 0})
	f.Add([]byte{0x00, 0x00, 0x00, 0x17, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, b []byte) {
		var tx Transaction
		_, _, _ = tx.GetFromBytes(b)
	})
}

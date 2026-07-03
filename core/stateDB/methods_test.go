package stateDB

import (
	"testing"

	"github.com/wonabru/qwid-node/common"
)

func addr(b byte) common.Address {
	var a common.Address
	a.ByteValue[0] = b
	return a
}

func TestRevertToSnapshotRestoresSlots(t *testing.T) {
	sa := CreateStateDB()
	a := addr(0x01)
	key := common.Hash{0xAA}

	sa.SetState(a, key, common.Hash{0x01}) // v1
	snap := sa.Snapshot()
	sa.SetState(a, key, common.Hash{0x02}) // v2
	sa.SetState(a, key, common.Hash{0x03}) // v3

	if sa.GetState(a, key) != (common.Hash{0x03}) {
		t.Fatalf("pre-revert value wrong: %v", sa.GetState(a, key))
	}
	sa.RevertToSnapshot(snap)
	if sa.GetState(a, key) != (common.Hash{0x01}) {
		t.Fatalf("revert did not restore original slot value, got %v", sa.GetState(a, key))
	}
}

func TestRevertDeletesNewlyCreatedSlot(t *testing.T) {
	sa := CreateStateDB()
	a := addr(0x02)
	key := common.Hash{0xBB}
	snap := sa.Snapshot()
	sa.SetState(a, key, common.Hash{0x09})
	sa.RevertToSnapshot(snap)
	if sa.GetState(a, key) != (common.Hash{}) {
		t.Fatalf("newly created slot not removed on revert: %v", sa.GetState(a, key))
	}
}

func TestRevertToSnapshotOutOfRange(t *testing.T) {
	sa := CreateStateDB()
	a := addr(0x03)
	key := common.Hash{0xCC}

	// Set some state changes
	sa.SetState(a, key, common.Hash{0x11})
	snap := sa.Snapshot()
	sa.SetState(a, key, common.Hash{0x22})
	sa.SetState(a, key, common.Hash{0x33})

	// Revert to far-out-of-range value should not panic and should clamp to journal length
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("RevertToSnapshot panicked with out-of-range value: %v", r)
		}
	}()
	sa.RevertToSnapshot(9999)
	// After reverting to 9999 (clamped to len(journal)), state should be at the clamped point
	// which should keep all changes (no revert occurs when sn >= len(journal))
	if sa.GetState(a, key) != (common.Hash{0x33}) {
		t.Fatalf("revert to 9999 should clamp and not panic, got %v", sa.GetState(a, key))
	}

	// Verify revert to snapshot before the out-of-range call still works
	sa.RevertToSnapshot(snap)
	if sa.GetState(a, key) != (common.Hash{0x11}) {
		t.Fatalf("revert to snap did not restore original value, got %v", sa.GetState(a, key))
	}
}

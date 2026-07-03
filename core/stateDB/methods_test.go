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

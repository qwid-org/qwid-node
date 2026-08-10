package vm

import (
	"math"
	"testing"

	"github.com/holiman/uint256"
)

func TestGetCopyNegativeOffset(t *testing.T) {
	m := NewMemory()
	m.Resize(32)
	if got := m.GetCopy(-1, 4); got != nil {
		t.Fatalf("expected nil for negative offset, got %v", got)
	}
}

func TestGetPtrNegativeOffset(t *testing.T) {
	m := NewMemory()
	m.Resize(32)
	if got := m.GetPtr(-1, 4); got != nil {
		t.Fatalf("expected nil for negative offset, got %v", got)
	}
}

func TestSetOnEmptyStoreDoesNotPanic(t *testing.T) {
	m := NewMemory()
	// Previously panicked; must be a safe no-op / bounded write now.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Set panicked: %v", r)
		}
	}()
	m.Set(0, 4, []byte{1, 2, 3, 4})
}

func TestGetCopyInRangeOffsetOutOfRangeSize(t *testing.T) {
	m := NewMemory()
	m.Resize(32)
	if got := m.GetCopy(30, 4); got != nil {
		t.Fatalf("expected nil for offset+size out of range, got %v", got)
	}
}

func TestGetPtrInRangeOffsetOutOfRangeSize(t *testing.T) {
	m := NewMemory()
	m.Resize(32)
	if got := m.GetPtr(30, 4); got != nil {
		t.Fatalf("expected nil for offset+size out of range, got %v", got)
	}
}

func TestGetCopyOverflowOffset(t *testing.T) {
	m := NewMemory()
	m.Resize(32)
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("GetCopy panicked: %v", r)
		}
	}()
	if got := m.GetCopy(math.MaxInt64, 16); got != nil {
		t.Fatalf("expected nil for overflowing offset, got %v", got)
	}
}

func TestGetCopyNegativeSize(t *testing.T) {
	m := NewMemory()
	m.Resize(32)
	if got := m.GetCopy(0, -4); got != nil {
		t.Fatalf("expected nil for negative size, got %v", got)
	}
}

func TestSet32OnEmptyStoreDoesNotPanic(t *testing.T) {
	m := NewMemory()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Set32 panicked: %v", r)
		}
	}()
	m.Set32(0, uint256.NewInt(5))
}

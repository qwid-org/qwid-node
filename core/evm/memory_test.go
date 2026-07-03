package vm

import "testing"

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

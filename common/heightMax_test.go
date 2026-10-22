package common

import (
	"testing"
	"time"
)

// With no peer messages nothing refreshes HeightMax, so a value nobody has
// confirmed for heightMaxTTL falls back to the node's own height.
func TestHeightMaxExpiresWithoutRefresh(t *testing.T) {
	savedH, savedMax, savedAt := GetHeight(), heightMax, heightMaxAt
	defer func() {
		SetHeight(savedH)
		heightMutex.Lock()
		heightMax, heightMaxAt = savedMax, savedAt
		heightMutex.Unlock()
	}()

	SetHeight(100)
	SetHeightMax(5000)
	if got := GetHeightMax(); got != 5000 {
		t.Fatalf("fresh HeightMax = %d, want 5000", got)
	}
	heightMutex.Lock()
	heightMaxAt = time.Now().Add(-heightMaxTTL - time.Second)
	heightMutex.Unlock()
	if got := GetHeightMax(); got != 100 {
		t.Fatalf("stale HeightMax = %d, want the own height 100", got)
	}
}

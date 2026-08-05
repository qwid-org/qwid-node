package common

import (
	"sync"
	"sync/atomic"
)

var height int64
var heightMax int64

// syncTarget is the height the network is believed to be at, derived from live
// peer height claims by the sync service. Unlike heightMax it is the raw
// observed network height, not the throttled per-round sync target, so it is the
// value that answers "am I still behind the network?".
var syncTarget int64
var heightMutex sync.RWMutex
var BlockMutex sync.Mutex
var NonceMutex sync.Mutex
var IsSyncing = atomic.Bool{}

func GetHeight() int64 {
	heightMutex.RLock()
	defer heightMutex.RUnlock()
	return height
}

func SetHeight(h int64) {
	heightMutex.Lock()
	defer heightMutex.Unlock()
	height = h
}

func GetHeightMax() int64 {
	heightMutex.RLock()
	defer heightMutex.RUnlock()
	return heightMax
}

func SetHeightMax(hmax int64) {
	heightMutex.Lock()
	defer heightMutex.Unlock()
	heightMax = hmax
}

// GetSyncTarget returns the height this node must reach to be considered synced.
//
// CurrentHeightOfNetwork (the HEIGHT_OF_NETWORK setting) overrides the height
// derived from peers for as long as this node is below it - the operator's
// explicit figure wins even when peers claim something different. Once the local
// chain reaches that height the setting is spent and the live peer view takes
// over, so a stale value cannot pin the target below the real network height
// forever.
//
// Consequence worth knowing: while the local height is below the setting, a
// HEIGHT_OF_NETWORK that is lower than the real network height lets this node
// declare itself synced early and start producing. Keep the value at or above
// the true network height.
func GetSyncTarget() int64 {
	heightMutex.RLock()
	defer heightMutex.RUnlock()
	if CurrentHeightOfNetwork > height {
		return CurrentHeightOfNetwork
	}
	return syncTarget
}

// SetSyncTarget records the network height observed from peers.
func SetSyncTarget(h int64) {
	heightMutex.Lock()
	defer heightMutex.Unlock()
	syncTarget = h
}

// IsBehindNetwork reports whether this node is too far behind the network to act
// as a block producer. It is the single source of truth for that question; block
// production and the IsSyncing flag must both derive from it.
func IsBehindNetwork() bool {
	heightMutex.RLock()
	defer heightMutex.RUnlock()
	target := syncTarget
	if CurrentHeightOfNetwork > height {
		target = CurrentHeightOfNetwork
	}
	return target-height > SyncedTolerance
}

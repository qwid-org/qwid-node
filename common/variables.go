package common

import (
	"sync"
	"sync/atomic"
	"time"
)

var height int64
var heightMax int64

// heightMaxAt is when heightMax was last refreshed from peer claims. The sync
// service refreshes it on every peer "hi"; a value nobody has confirmed for
// heightMaxTTL (no peers, or none reachable) is stale and is no longer shown.
var heightMaxAt time.Time

const heightMaxTTL = 3 * time.Minute

// syncTarget is the height the network is believed to be at, derived from live
// peer height claims by the sync service. Unlike heightMax it is the raw
// observed network height, not the throttled per-round sync target, so it is the
// value that answers "am I still behind the network?".
var syncTarget int64

// productionTarget is the CORROBORATED network height — a height at least two
// distinct live peers agree on. Unlike syncTarget (which trusts a single peer so
// a two-node network can still catch up) it gates BLOCK PRODUCTION: a single
// uncorroborated claim — a lone peer, a liar, or two nodes behind one NAT that
// collapse to one claim key — must never be able to stop this node from
// producing, only to make it sync (harmless even against a lie, since bogus
// blocks never verify). Set by the sync service; 0 means "no corroboration".
var productionTarget int64
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

// GetHeightMax is the network height last observed from live peer claims,
// never below this node's own height, and only while fresh: a value no peer
// has confirmed for heightMaxTTL falls back to the own height, so a wrong
// claim cannot stay on display (or steer the rewind depth) indefinitely.
func GetHeightMax() int64 {
	heightMutex.RLock()
	defer heightMutex.RUnlock()
	if heightMaxAt.IsZero() || time.Since(heightMaxAt) > heightMaxTTL {
		return height
	}
	return max(heightMax, height)
}

// SetHeightMax records the current network height view (not a running
// maximum: it may go down when a claim expires).
func SetHeightMax(hmax int64) {
	heightMutex.Lock()
	defer heightMutex.Unlock()
	heightMax = hmax
	heightMaxAt = time.Now()
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

// SetProductionTarget records the corroborated network height (see
// productionTarget). Pass 0 when no height is confirmed by enough peers.
func SetProductionTarget(h int64) {
	heightMutex.Lock()
	defer heightMutex.Unlock()
	productionTarget = h
}

// IsBehindNetwork reports whether this node is too far behind the network to act
// as a block producer. It is the single source of truth for that question; block
// production and the IsSyncing flag both derive from it.
//
// It gates on the CORROBORATED height (productionTarget), NOT the single-peer
// syncTarget: a lone/lying/NAT-collapsed peer can make this node SYNC but never
// STOP PRODUCING on an unverified claim (a DoS vector). The operator's explicit
// HEIGHT_OF_NETWORK still gates production below it, so cold start and genesis
// are unaffected.
func IsBehindNetwork() bool {
	heightMutex.RLock()
	defer heightMutex.RUnlock()
	target := productionTarget
	if CurrentHeightOfNetwork > height {
		target = CurrentHeightOfNetwork
	}
	return target-height > SyncedTolerance
}

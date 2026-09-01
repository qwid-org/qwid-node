package handlers

import (
	"sync"
	"time"
)

// syncEtaTracker estimates when the node finishes syncing. It samples
// remaining = heightMax - height on every stats poll and measures how fast
// that DISTANCE shrinks - not how fast the height grows - so the estimate
// automatically accounts for the network producing new blocks while we catch
// up. Kept in the webui backend: the node needs no protocol change, and the
// window survives page reloads.
type syncEtaTracker struct {
	mu      sync.Mutex
	samples []etaSample
}

type etaSample struct {
	at        time.Time
	height    int64
	remaining int64
}

const (
	// etaWindow is the sliding window the rate is averaged over. Long enough
	// to flatten per-batch jitter, short enough to follow real speed changes.
	etaWindow = 2 * time.Minute
	// etaMinSpan is the minimum window span before an estimate is reported -
	// two samples a second apart would swing wildly.
	etaMinSpan = 5 * time.Second
	// etaResetJump is how much remaining may grow between consecutive samples
	// before the window is discarded as poisoned. The target creeps up ~1 per
	// 10s in normal operation; anything bigger means a reset, a fork rewind or
	// a target jump, and averaging across it would
	// yield a nonsense rate for the next two minutes.
	etaResetJump = 64
)

var syncEta = &syncEtaTracker{}

// observe records the current sync distance and returns the blocks-per-second
// import rate, the estimated seconds to finish (-1 when unknown), both over
// the sliding window.
func (t *syncEtaTracker) observe(now time.Time, height, remaining int64) (blocksPerSec float64, etaSeconds int64) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if n := len(t.samples); n > 0 && remaining > t.samples[n-1].remaining+etaResetJump {
		t.samples = t.samples[:0]
	}
	t.samples = append(t.samples, etaSample{at: now, height: height, remaining: remaining})
	// Drop samples that fell out of the window.
	cut := 0
	for cut < len(t.samples)-1 && now.Sub(t.samples[cut].at) > etaWindow {
		cut++
	}
	t.samples = t.samples[cut:]

	oldest := t.samples[0]
	span := now.Sub(oldest.at).Seconds()
	if span < etaMinSpan.Seconds() {
		return 0, -1
	}
	blocksPerSec = float64(height-oldest.height) / span
	closingPerSec := float64(oldest.remaining-remaining) / span
	if closingPerSec <= 0 || remaining <= 0 {
		// Standing still or moving backwards - no honest estimate exists.
		return blocksPerSec, -1
	}
	return blocksPerSec, int64(float64(remaining)/closingPerSec + 0.5)
}

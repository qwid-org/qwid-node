package syncServices

import (
	"sync"
	"time"

	"github.com/qwid-org/qwid-node/tcpip"
)

// Header-serving budget (S2-06). A gh of ~60 bytes makes us read and send up
// to NumberOfHashesInBucket+1 full blocks; the per-message rate limit alone
// left a ~50 000x amplification. Each transport source gets a token bucket of
// blocks: a burst of headerServeBurst, refilled at headerServeRefillPerSec -
// ample for an honest peer syncing from us, a hard ceiling for anyone else.
const (
	headerServeBurst        int64 = 600
	headerServeRefillPerSec int64 = 50
	headerServeMaxSources         = 4096
)

type serveBucket struct {
	tokens int64
	last   time.Time
}

var (
	headerServeMu      sync.Mutex
	headerServeBuckets = map[[4]byte]*serveBucket{}
)

func allowHeaderServe(addr [4]byte, blocks int64, now time.Time) bool {
	src := addr
	if real, ok := tcpip.RealIPForHandle(addr); ok {
		src = real
	}
	headerServeMu.Lock()
	defer headerServeMu.Unlock()
	b, ok := headerServeBuckets[src]
	if !ok {
		if len(headerServeBuckets) >= headerServeMaxSources {
			headerServeBuckets = map[[4]byte]*serveBucket{}
		}
		b = &serveBucket{tokens: headerServeBurst, last: now}
		headerServeBuckets[src] = b
	}
	if el := now.Sub(b.last); el > 0 {
		b.tokens += int64(el/time.Second) * headerServeRefillPerSec
		b.last = b.last.Add(el.Truncate(time.Second))
		if b.tokens > headerServeBurst {
			b.tokens = headerServeBurst
		}
	}
	if b.tokens < blocks {
		return false
	}
	b.tokens -= blocks
	return true
}

func resetHeaderServeBudget() {
	headerServeMu.Lock()
	headerServeBuckets = map[[4]byte]*serveBucket{}
	headerServeMu.Unlock()
}

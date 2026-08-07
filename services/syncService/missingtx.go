package syncServices

import (
	"sync"
	"time"

	"github.com/wonabru/qwid-node/common"
	"github.com/wonabru/qwid-node/logger"
	"github.com/wonabru/qwid-node/services/transactionServices"
)

// Missing-transaction request bookkeeping.
//
// A block whose transaction never arrives used to be re-requested on every
// sync round - twice a second, forever, with no record of WHICH hash was
// missing and no signal that the answer path is broken. This throttles the
// re-requests, names the hash in the log, and escalates: after a while the
// request goes to every live peer ahead (not just the batch sender), and the
// operator gets one loud line with the hash to grep for on the peer.
const (
	// missingTxRetryInterval is the minimum time between two bt requests for
	// the same hash. The peer either answers within a round trip or something
	// is wrong - asking twice a second only floods both logs.
	missingTxRetryInterval = 5 * time.Second
	// missingTxEscalateAfter is how many unanswered requests it takes before
	// the request is broadcast to every live peer ahead and the operator is
	// pointed at the hash. 6 tries * 5s = ~30s of silence.
	missingTxEscalateAfter = 6
	// missingTxForget drops bookkeeping for hashes not asked about for this
	// long, so the map cannot grow without bound across a long sync.
	missingTxForget = 10 * time.Minute
)

type missingTxState struct {
	lastRequest time.Time
	tries       int
}

var (
	missingTxMutex sync.Mutex
	missingTx      = map[[common.HashLength]byte]missingTxState{}
)

// dueMissingTxRequests returns the subset of hashes whose next request is due,
// advancing their counters. It also reports the hashes that just crossed the
// escalation threshold.
func dueMissingTxRequests(hashes [][]byte, now time.Time) (due [][]byte, escalate [][]byte) {
	missingTxMutex.Lock()
	defer missingTxMutex.Unlock()

	for k, st := range missingTx {
		if now.Sub(st.lastRequest) > missingTxForget {
			delete(missingTx, k)
		}
	}

	for _, h := range hashes {
		if len(h) != common.HashLength {
			continue
		}
		var k [common.HashLength]byte
		copy(k[:], h)
		st := missingTx[k]
		if !st.lastRequest.IsZero() && now.Sub(st.lastRequest) < missingTxRetryInterval {
			continue
		}
		st.lastRequest = now
		st.tries++
		missingTx[k] = st
		due = append(due, h)
		if st.tries%missingTxEscalateAfter == 0 {
			escalate = append(escalate, h)
		}
	}
	return due, escalate
}

// clearMissingTx drops all bookkeeping once a sync round finds nothing
// missing, so a later re-miss starts a fresh escalation cycle.
func clearMissingTx() {
	missingTxMutex.Lock()
	defer missingTxMutex.Unlock()
	for k := range missingTx {
		delete(missingTx, k)
	}
}

// requestMissingTxs sends bt requests for the hashes that are due to addr,
// spreading them over MaxNumberTransactionInChunk-sized chunks. Escalated
// hashes additionally go to every live peer ahead of us and are called out in
// the log - by hash - so the operator can grep the serving peer's log for what
// happened to the answer.
func requestMissingTxs(addr [4]byte, hashes [][]byte, height int64) (requested int) {
	due, escalate := dueMissingTxRequests(hashes, time.Now())
	if len(due) == 0 {
		return 0
	}
	logger.GetLogger().Printf("Sync incomplete - requesting %d missing transaction(s) from %v, first: %x",
		len(due), addr, due[0][:8])

	maxChunk := common.MaxNumberTransactionInChunk
	for i := 0; i < len(due); i += maxChunk {
		end := i + maxChunk
		if end > len(due) {
			end = len(due)
		}
		transactionServices.SendGT(addr, due[i:end], "bt")
		if end < len(due) {
			time.Sleep(500 * time.Millisecond)
		}
	}

	if len(escalate) > 0 {
		targets, _ := peersAhead(height)
		for _, h := range escalate {
			logger.GetLogger().Printf("missing tx %x still unanswered after %d requests to %v - "+
				"asking %d other peer(s); grep the peer's log for this hash ('bt'/'bx' lines)",
				h[:8], missingTxEscalateAfter, addr, len(targets))
		}
		for _, t := range targets {
			if t.addr == addr {
				continue
			}
			for i := 0; i < len(escalate); i += maxChunk {
				end := i + maxChunk
				if end > len(escalate) {
					end = len(escalate)
				}
				transactionServices.SendGT(t.addr, escalate[i:end], "bt")
			}
		}
	}
	return len(due)
}

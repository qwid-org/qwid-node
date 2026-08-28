package syncServices

import (
	"sync"
	"time"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
	"github.com/qwid-org/qwid-node/services/transactionServices"
	"github.com/qwid-org/qwid-node/tcpip"
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
	// missingTxRecycleAfter is how many unanswered requests it takes before
	// the transaction-topic connection to the unresponsive peer is torn down
	// and re-dialed. The bt requests demonstrably leave this node while
	// nothing comes back, which is the signature of a half-dead link: OUR
	// receive loop is fine, but the peer's send side points at a stale stream
	// (typically left over from our earlier restart) that no timeout on our
	// side can detect. 12 tries * 5s = ~1 minute of silence.
	missingTxRecycleAfter = 12
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
// escalation threshold, and whether any hash has gone unanswered long enough
// that the link to the serving peer should be recycled.
func dueMissingTxRequests(hashes [][]byte, now time.Time) (due [][]byte, escalate [][]byte, recycle bool) {
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
		if st.tries%missingTxRecycleAfter == 0 {
			recycle = true
		}
	}
	return due, escalate, recycle
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
	due, escalate, recycle := dueMissingTxRequests(hashes, time.Now())
	if len(due) == 0 {
		return 0
	}
	logger.GetLogger().Printf("Sync incomplete - requesting %d missing transaction(s) from %v, first: %x",
		len(due), addr, due[0][:8])

	// Pacing: 5 chunks/s of MaxNumberTransactionInChunk txs each (~2500 tx/s).
	// The ceiling is the peer's per-IP sync-class message budget
	// (MessageRateLimit per MessageRateWindowSeconds = 10 msgs/s), shared with
	// hi/gh/sh - 5 bt requests a second leaves half the budget for those. The
	// previous 100-tx chunks at one per 500ms capped recovery at 200 tx/s,
	// which a network doing 100 TPS could never catch up through.
	maxChunk := common.MaxNumberTransactionInChunk
	for i := 0; i < len(due); i += maxChunk {
		end := i + maxChunk
		if end > len(due) {
			end = len(due)
		}
		transactionServices.SendGT(addr, due[i:end], "bt")
		if end < len(due) {
			time.Sleep(200 * time.Millisecond)
		}
	}

	if len(escalate) > 0 {
		targets, _ := peersAhead(height)
		others := make([]peerTarget, 0, len(targets))
		for _, t := range targets {
			if t.addr != addr {
				others = append(others, t)
			}
		}
		for _, h := range escalate {
			logger.GetLogger().Printf("missing tx %x still unanswered after %d requests to %v - "+
				"asking %d other peer(s); grep the peer's log for this hash ('bt'/'bx' lines)",
				h[:8], missingTxEscalateAfter, addr, len(others))
		}
		for _, t := range others {
			for i := 0; i < len(escalate); i += maxChunk {
				end := i + maxChunk
				if end > len(escalate) {
					end = len(escalate)
				}
				transactionServices.SendGT(t.addr, escalate[i:end], "bt")
			}
		}
	}

	// A minute of one-way silence: our bt requests leave (Send would log
	// otherwise) and no bx ever comes back, while the sync topic to the same
	// peer keeps working. That is a half-dead transaction link - typically the
	// peer's send side holds a stale stream from before our restart - and only
	// a fresh dial can replace it.
	if recycle {
		logger.GetLogger().Printf("no bx answers from %v for ~1 minute - recycling the transaction-topic connection", addr)
		tcpip.RecycleTopicConnection(tcpip.TransactionTopic, addr)
	}
	return len(due)
}

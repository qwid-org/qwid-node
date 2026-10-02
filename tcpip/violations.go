package tcpip

import (
	"sync"
	"time"

	"github.com/qwid-org/qwid-node/common"
)

// Violation ledger (S1-07). Connection trust (validPeersConnected) is reset to
// ConnectionMaxTries on every new connection and its entry deleted at zero,
// so the receive loops' "trust <= 0 -> ban" never fired: a peer reconnecting
// every few violations, or interleaving garbage with valid messages, was
// never banned. Violations are now counted per transport source in a ledger
// that survives reconnects and only decays with time: one point forgiven per
// violationForgiveInterval, a ban at ConnectionMaxTries points.
const (
	violationForgiveInterval = time.Minute
	maxViolationEntries      = 4096
)

func violationCount() int {
	violationsMu.Lock()
	defer violationsMu.Unlock()
	return len(violations)
}

type violationRecord struct {
	score int
	last  time.Time // start of the current, not yet forgiven, interval
}

var (
	violationsMu sync.Mutex
	violations   = map[[4]byte]*violationRecord{}
)

// recordViolation adds one violation for ip and reports whether it is now to
// be banned (the ledger entry is then cleared; the ban itself carries on).
func recordViolation(ip [4]byte, now time.Time) bool {
	if violationCount() > maxViolationEntries {
		pruneViolations(now)
	}
	violationsMu.Lock()
	defer violationsMu.Unlock()
	rec, ok := violations[ip]
	if !ok {
		rec = &violationRecord{last: now}
		violations[ip] = rec
	}
	if forgiven := int(now.Sub(rec.last) / violationForgiveInterval); forgiven > 0 {
		rec.score -= forgiven
		rec.last = rec.last.Add(time.Duration(forgiven) * violationForgiveInterval)
		if rec.score <= 0 {
			rec.score, rec.last = 0, now
		}
	}
	rec.score++
	if rec.score >= common.ConnectionMaxTries {
		delete(violations, ip)
		return true
	}
	return false
}

// pruneViolations drops fully forgiven entries so the ledger stays small.
func pruneViolations(now time.Time) {
	violationsMu.Lock()
	defer violationsMu.Unlock()
	for ip, rec := range violations {
		if int(now.Sub(rec.last)/violationForgiveInterval) >= rec.score {
			delete(violations, ip)
		}
	}
}

func resetViolations() {
	violationsMu.Lock()
	violations = map[[4]byte]*violationRecord{}
	violationsMu.Unlock()
}

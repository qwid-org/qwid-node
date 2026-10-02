package handlers

import (
	"context"
	"sync"
	"time"
)

// QWID-2026-28: the webui LoadWallet endpoint mints an authenticated session on
// a correct password but had no rate limit, so a localhost attacker (malware, or
// a DNS-rebinding page that gained same-origin access) could brute-force the
// wallet password at full speed. This throttle caps load ATTEMPTS in a sliding
// window; a successful load clears the counter so a legitimate single user is
// never locked out by their own use.

const (
	loadWalletMaxAttempts = 10
	loadWalletWindow      = time.Minute
)

var (
	loadWalletMu       sync.Mutex
	loadWalletAttempts []time.Time
)

// loadWalletThrottleAllow records one load attempt and reports whether it is
// within the allowed rate. It prunes attempts older than the window first.
func loadWalletThrottleAllow(now time.Time) bool {
	loadWalletMu.Lock()
	defer loadWalletMu.Unlock()

	cutoff := now.Add(-loadWalletWindow)
	kept := loadWalletAttempts[:0]
	for _, t := range loadWalletAttempts {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	loadWalletAttempts = kept

	if len(loadWalletAttempts) >= loadWalletMaxAttempts {
		return false
	}
	loadWalletAttempts = append(loadWalletAttempts, now)
	return true
}

// loadWalletThrottleReset clears the attempt history after a successful load so
// the legitimate user's subsequent activity is unaffected.
func loadWalletThrottleReset() {
	loadWalletMu.Lock()
	loadWalletAttempts = nil
	loadWalletMu.Unlock()
}

// S8-03: the counter is global - every local process shares 127.0.0.1 - so a
// hard refusal let any of them lock the operator out. Past the cap, attempts
// are instead serialised behind a penalty delay: guessing stays bounded at
// one attempt per loadWalletPenalty, and the operator always gets through.
var (
	loadWalletPenalty   = 6 * time.Second
	loadWalletPenaltyMu sync.Mutex
)

func loadWalletGate(ctx context.Context, now time.Time) bool {
	if ctx.Err() != nil {
		return false
	}
	if loadWalletThrottleAllow(now) {
		return true
	}
	loadWalletPenaltyMu.Lock()
	defer loadWalletPenaltyMu.Unlock()
	t := time.NewTimer(loadWalletPenalty)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

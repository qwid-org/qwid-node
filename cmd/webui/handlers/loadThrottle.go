package handlers

import (
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

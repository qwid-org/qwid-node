package handlers

import (
	"context"
	"net/http"
	"time"
)

// S7-02: /api/stats and /api/details are public and each request costs the
// node RPC calls (an account lookup is 41 DETS calls), so they are limited per
// client address.
const publicReadPerMinute = 60

var publicReadLimiter = &rateLimiter{entries: make(map[string][]time.Time)}

func PublicReadRateLimit(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !publicReadLimiter.allow(getClientIP(r), publicReadPerMinute, time.Minute) {
			JsonError(w, "Too many requests. Please slow down.", http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}

// S7-03: registration, login and password change each run bcrypt and
// Argon2id (64 MiB). Per-IP limits do not bound the total, so parallel
// requests from many addresses could exhaust the process's memory. At most
// maxConcurrentKDF run at once; the rest wait, or give up with the request.
const (
	maxConcurrentKDF = 4
	kdfWaitLimit     = 15 * time.Second
)

var kdfSlots = make(chan struct{}, maxConcurrentKDF)

func acquireKDF(ctx context.Context) bool {
	if ctx.Err() != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, kdfWaitLimit)
	defer cancel()
	select {
	case kdfSlots <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	}
}

func releaseKDF() { <-kdfSlots }

// S7-03: change-password verifies the current password, so it is a guessing
// oracle for whoever holds a session; limit it per user.
const (
	maxPasswordChangeAttempts = 5
	passwordChangeWindow      = 15 * time.Minute
)

var changePasswordLimiter = &rateLimiter{entries: make(map[string][]time.Time)}

// S7-04: a lockout keyed by username alone let anyone keep a chosen account
// locked. Failures now lock out the (account, source) pair; a much higher
// per-account ceiling still stops guessing spread over many addresses.
const maxFailedLoginsGlobal = 50

var loginLockoutGlobal = &rateLimiter{entries: make(map[string][]time.Time)}

func lockoutKey(username, ip string) string { return username + "\x00" + ip }

func loginLockedOut(username, ip string) bool {
	return loginLockout.lockedOutAfter(lockoutKey(username, ip), maxFailedLogins) ||
		loginLockoutGlobal.lockedOutAfter(username, maxFailedLoginsGlobal)
}

func recordLoginFailure(username, ip string) {
	loginLockout.recordFailure(lockoutKey(username, ip))
	loginLockoutGlobal.recordFailure(username)
}

func clearLoginFailures(username, ip string) {
	loginLockout.clearFailures(lockoutKey(username, ip))
	loginLockoutGlobal.clearFailures(username)
}

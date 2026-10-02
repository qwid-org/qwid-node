package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// S7-02: the public, unauthenticated read endpoints are rate limited per IP.
func TestPublicReadRateLimit(t *testing.T) {
	publicReadLimiter = &rateLimiter{entries: make(map[string][]time.Time)}
	h := PublicReadRateLimit(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	call := func(ip string) int {
		r := httptest.NewRequest("GET", "/api/details?hash=1", nil)
		r.RemoteAddr = ip + ":1234"
		w := httptest.NewRecorder()
		h(w, r)
		return w.Code
	}
	for i := 0; i < publicReadPerMinute; i++ {
		if c := call("198.51.100.1"); c != http.StatusOK {
			t.Fatalf("request %d rejected with %d", i, c)
		}
	}
	if c := call("198.51.100.1"); c != http.StatusTooManyRequests {
		t.Fatalf("request over the limit got %d", c)
	}
	if c := call("198.51.100.2"); c != http.StatusOK {
		t.Fatal("another client must not be affected")
	}
}

// S7-03: no more than maxConcurrentKDF password hashings run at once.
func TestKDFSlotsBoundConcurrency(t *testing.T) {
	var running, peak atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 3*maxConcurrentKDF; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !acquireKDF(context.Background()) {
				t.Error("slot not granted")
				return
			}
			defer releaseKDF()
			n := running.Add(1)
			for {
				p := peak.Load()
				if n <= p || peak.CompareAndSwap(p, n) {
					break
				}
			}
			time.Sleep(20 * time.Millisecond)
			running.Add(-1)
		}()
	}
	wg.Wait()
	if peak.Load() > maxConcurrentKDF {
		t.Fatalf("%d KDFs ran concurrently, limit %d", peak.Load(), maxConcurrentKDF)
	}
	ctx, cancel := context.WithCancel(context.Background())
	for i := 0; i < maxConcurrentKDF; i++ {
		acquireKDF(context.Background())
	}
	cancel()
	if acquireKDF(ctx) {
		t.Fatal("a cancelled request must not wait for a slot")
	}
	for i := 0; i < maxConcurrentKDF; i++ {
		releaseKDF()
	}
}

// S7-03: password-change attempts are limited per user.
func TestChangePasswordAttemptsAreLimited(t *testing.T) {
	changePasswordLimiter = &rateLimiter{entries: make(map[string][]time.Time)}
	for i := 0; i < maxPasswordChangeAttempts; i++ {
		if !changePasswordLimiter.allow("alice", maxPasswordChangeAttempts, passwordChangeWindow) {
			t.Fatalf("attempt %d refused", i)
		}
	}
	if changePasswordLimiter.allow("alice", maxPasswordChangeAttempts, passwordChangeWindow) {
		t.Fatal("unbounded password guessing through change-password")
	}
}

// S7-04: failures from one source lock that source out of the account, not
// everyone; a much higher per-account ceiling still stops distributed
// guessing.
func TestLoginLockoutIsPerSourceWithGlobalCeiling(t *testing.T) {
	loginLockout = &rateLimiter{entries: make(map[string][]time.Time)}
	loginLockoutGlobal = &rateLimiter{entries: make(map[string][]time.Time)}
	for i := 0; i < maxFailedLogins; i++ {
		recordLoginFailure("bob", "203.0.113.1")
	}
	if !loginLockedOut("bob", "203.0.113.1") {
		t.Fatal("the guessing source must be locked out")
	}
	if loginLockedOut("bob", "203.0.113.2") {
		t.Fatal("the account owner from another address must still get in")
	}
	for i := 0; i < maxFailedLoginsGlobal; i++ {
		recordLoginFailure("bob", "203.0.113.9")
	}
	if !loginLockedOut("bob", "203.0.113.3") {
		t.Fatal("distributed guessing must hit the per-account ceiling")
	}
	clearLoginFailures("bob", "203.0.113.2")
}

// With TRUST_PROXY the client controls the first X-Forwarded-For entry; the
// proxy appends the address it saw.
func TestGetClientIPUsesProxyAppendedAddress(t *testing.T) {
	t.Setenv("TRUST_PROXY", "true")
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Forwarded-For", "1.2.3.4, 198.51.100.7")
	if got := getClientIP(r); got != "198.51.100.7" {
		t.Fatalf("getClientIP = %q", got)
	}
}

package main

import (
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Per-IP request limiting for the public explorer.
//
// Every /api/* request turns into an RPC round-trip to the node, so an
// unthrottled public endpoint lets one client saturate the node itself rather
// than merely this process. Static assets are served from an embedded
// filesystem and cost almost nothing, so they get a much looser ceiling that
// exists only to bound bandwidth.
//
// The counters are fixed-window rather than the sliding window used by
// cmd/website/handlers/auth.go. That limiter records a timestamp per request,
// which is fine at five attempts per ten minutes but would store hundreds of
// timestamps per IP at the volumes a browsing UI generates — turning the
// defence into its own memory-exhaustion vector under exactly the flood it is
// meant to survive. A fixed window costs O(1) per client.

const (
	// The dashboard issues two API calls every ten seconds while it is open,
	// i.e. twelve per minute. This leaves an order of magnitude of headroom
	// for a visitor clicking through blocks with several tabs open.
	defaultAPILimit = 120

	// Static files are cheap; this only bounds bandwidth abuse.
	defaultStaticLimit = 600

	// The contact form is not an API call — each accepted POST sends a real
	// email through SES. At the API ceiling one address could send two emails
	// a second, which is a mail-bombing channel against support@, a bill, and
	// a threat to the domain's sending reputation all at once. Five per ten
	// minutes matches the registration limiter in
	// cmd/website/handlers/auth.go and is far above what a person submitting a
	// form actually needs.
	defaultContactLimit  = 5
	defaultContactWindow = 10 * time.Minute

	// Upper bound on tracked clients, so the limiter itself cannot be made to
	// exhaust memory by spraying requests from forged or botnet addresses.
	maxTrackedClients = 50000
)

type bucket struct {
	count int
	start time.Time
}

type rateLimiter struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	buckets map[string]*bucket
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{
		limit:   limit,
		window:  window,
		buckets: make(map[string]*bucket),
	}
}

// allow records a request from ip and reports whether it is within the limit.
func (rl *rateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	b, ok := rl.buckets[ip]
	if !ok || now.Sub(b.start) >= rl.window {
		if !ok && len(rl.buckets) >= maxTrackedClients {
			rl.sweepLocked(now)
			if len(rl.buckets) >= maxTrackedClients {
				// Still full of live entries: this is a genuine flood from
				// many addresses. Serve the request rather than locking out
				// the whole internet — the per-IP ceiling on the addresses
				// already tracked still holds, and nginx or the network layer
				// is the right place to answer a distributed flood.
				return true
			}
		}
		rl.buckets[ip] = &bucket{count: 1, start: now}
		return true
	}

	if b.count >= rl.limit {
		return false
	}
	b.count++
	return true
}

// sweepLocked drops windows that have already expired. Caller holds rl.mu.
func (rl *rateLimiter) sweepLocked(now time.Time) {
	for ip, b := range rl.buckets {
		if now.Sub(b.start) >= rl.window {
			delete(rl.buckets, ip)
		}
	}
}

func (rl *rateLimiter) sweep() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.sweepLocked(time.Now())
}

// retryAfter returns the seconds until ip's current window closes.
func (rl *rateLimiter) retryAfter(ip string) int {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	b, ok := rl.buckets[ip]
	if !ok {
		return int(rl.window.Seconds())
	}
	remaining := rl.window - time.Since(b.start)
	if remaining < time.Second {
		return 1
	}
	return int(remaining.Seconds()) + 1
}

// clientIP resolves the address a request is attributed to.
//
// Two paths reach this process with different truths about who the peer is.
// Over HTTPS the peer is nginx on loopback, and the real client address is only
// in X-Real-IP — the header its vhost sets. On WAN port 80, which the router
// forwards straight here, the transport peer IS the client and any such header
// is attacker-supplied.
//
// So proxy headers are honoured only when the connection actually came from
// loopback. Trusting them unconditionally would let anyone reset their own
// counter, or worse, forge another visitor's address and spend that visitor's
// quota. Ignoring them unconditionally would be just as bad in the other
// direction: every HTTPS request would be attributed to 127.0.0.1 and the whole
// internet would share a single bucket, so one busy visitor would lock out
// everyone. TRUST_PROXY=true extends the same trust to a non-loopback proxy,
// matching cmd/website/handlers/auth.go.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}

	trusted := os.Getenv("TRUST_PROXY") == "true"
	if !trusted {
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			trusted = true
		}
	}
	if !trusted {
		return host
	}

	if real := strings.TrimSpace(r.Header.Get("X-Real-IP")); real != "" {
		return real
	}
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		return strings.TrimSpace(strings.Split(fwd, ",")[0])
	}
	return host
}

// envLimit reads a per-minute override, falling back to def.
func envLimit(name string, def int) int {
	if v := os.Getenv(name); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

// rateLimit throttles requests per client IP, with a tighter ceiling on the
// API than on static assets.
func rateLimit(next http.Handler) http.Handler {
	apiLimiter := newRateLimiter(envLimit("RATE_LIMIT_API", defaultAPILimit), time.Minute)
	staticLimiter := newRateLimiter(envLimit("RATE_LIMIT_STATIC", defaultStaticLimit), time.Minute)
	contactLimiter := newRateLimiter(envLimit("RATE_LIMIT_CONTACT", defaultContactLimit), defaultContactWindow)

	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			apiLimiter.sweep()
			staticLimiter.sweep()
			contactLimiter.sweep()
		}
	}()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		limiter := staticLimiter
		if strings.HasPrefix(r.URL.Path, "/api/") {
			limiter = apiLimiter
		}
		// Only the POST is charged to the contact budget. The CORS preflight
		// that precedes it is not an email, and counting it would halve a
		// legitimate visitor's allowance.
		if r.URL.Path == "/api/contact" && r.Method == http.MethodPost {
			limiter = contactLimiter
		}

		ip := clientIP(r)
		if !limiter.allow(ip) {
			w.Header().Set("Retry-After", strconv.Itoa(limiter.retryAfter(ip)))
			// A throttled request never reaches corsMiddleware, so the
			// cross-origin headers it would have set must be repeated here.
			// Without them a rate-limited caller on qwid.org sees an opaque
			// CORS failure instead of the 429 explaining what happened.
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Cross-Origin-Resource-Policy", "cross-origin")
			// Written as JSON because /api/* is the path that realistically
			// trips this, and its callers parse JSON.
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"error":"Too many requests"}`))
			return
		}

		next.ServeHTTP(w, r)
	})
}

package main

import (
	"net/http/httptest"
	"testing"
)

// S8-02: behind a local proxy the client controls the FIRST X-Forwarded-For
// entry; the proxy appends the real address at the end.
func TestClientIPUsesProxyAppendedAddress(t *testing.T) {
	r := httptest.NewRequest("GET", "/api/stats", nil)
	r.RemoteAddr = "127.0.0.1:5555"
	r.Header.Set("X-Forwarded-For", "1.2.3.4, 198.51.100.7")
	if got := clientIP(r); got != "198.51.100.7" {
		t.Fatalf("clientIP = %q, want the proxy-appended 198.51.100.7", got)
	}
	r.Header.Set("X-Real-IP", "198.51.100.8")
	if got := clientIP(r); got != "198.51.100.8" {
		t.Fatalf("X-Real-IP from the proxy must win, got %q", got)
	}
	direct := httptest.NewRequest("GET", "/api/stats", nil)
	direct.RemoteAddr = "203.0.113.5:4444"
	direct.Header.Set("X-Forwarded-For", "1.2.3.4")
	if got := clientIP(direct); got != "203.0.113.5" {
		t.Fatalf("a direct client's headers must be ignored, got %q", got)
	}
}

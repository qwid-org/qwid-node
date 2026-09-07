package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestQWID27_StaticSecurityHeaders verifies the website static handler now sends
// a Content-Security-Policy and the companion hardening headers (QWID-2026-27).
// The policy keeps 'unsafe-inline' only for script/style (the inline SPA needs
// it) but locks down fetch/img/object/frame to blunt XSS exfiltration and
// clickjacking.
func TestQWID27_StaticSecurityHeaders(t *testing.T) {
	handler := staticSecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	csp := rec.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("static handler set no Content-Security-Policy")
	}
	for _, want := range []string{
		"default-src 'self'",
		"connect-src 'self'",
		"img-src 'self' data:",
		"object-src 'none'",
		"base-uri 'none'",
		"frame-ancestors 'none'",
	} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP missing %q; got %q", want, csp)
		}
	}
	// script-src/style-src must allow inline (the SPA is inline), but the fetch
	// surface must not — connect-src stays 'self' with no 'unsafe' token.
	if strings.Contains(csp, "connect-src 'self' 'unsafe") {
		t.Error("connect-src must not be relaxed")
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
	}
	if got := rec.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("X-Frame-Options = %q, want DENY", got)
	}
}

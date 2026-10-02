package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// S10-01: profiling is opt-in.
func TestPprofIsOptIn(t *testing.T) {
	if pprofRequested([]string{"1.2.3.4", "-log"}) {
		t.Fatal("pprof must be off by default")
	}
	if !pprofRequested([]string{"-pprof"}) || !pprofRequested([]string{"--pprof"}) {
		t.Fatal("the -pprof flag must enable it")
	}
}

// S10-01: with no Host check, a DNS-rebinding page could read the profile
// endpoints through the operator's browser.
func TestPprofRejectsForeignHost(t *testing.T) {
	h := loopbackHostOnly(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	for host, want := range map[string]int{
		"127.0.0.1:6060":      http.StatusOK,
		"localhost:6060":      http.StatusOK,
		"attacker.example":    http.StatusForbidden,
		"attacker.example:80": http.StatusForbidden,
	} {
		r := httptest.NewRequest("GET", "/debug/pprof/", nil)
		r.Host = host
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != want {
			t.Errorf("Host %q -> %d, want %d", host, w.Code, want)
		}
	}
}

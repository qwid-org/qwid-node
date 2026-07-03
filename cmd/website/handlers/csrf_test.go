package handlers

import (
	"net/http"
	"testing"
)

// TestIsSameOriginRequest verifies the WH-C4 CSRF check accepts same-origin
// requests and rejects cross-origin or origin-less state-changing requests.
func TestIsSameOriginRequest(t *testing.T) {
	cases := []struct {
		name   string
		host   string
		origin string
		refer  string
		want   bool
	}{
		{"matching origin", "wallet.example:8080", "http://wallet.example:8080", "", true},
		{"cross origin", "wallet.example:8080", "http://evil.example", "", false},
		{"no origin or referer", "wallet.example:8080", "", "", false},
		{"referer fallback match", "wallet.example:8080", "", "http://wallet.example:8080/page", true},
		{"referer cross origin", "wallet.example:8080", "", "http://evil.example/x", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, _ := http.NewRequest("POST", "http://"+c.host+"/api/send", nil)
			r.Host = c.host
			if c.origin != "" {
				r.Header.Set("Origin", c.origin)
			}
			if c.refer != "" {
				r.Header.Set("Referer", c.refer)
			}
			if got := isSameOriginRequest(r); got != c.want {
				t.Fatalf("isSameOriginRequest = %v, want %v", got, c.want)
			}
		})
	}
}

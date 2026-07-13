package clientrpc

import (
	"testing"
	"time"
)

func TestNextBackoff(t *testing.T) {
	got := initialBackoff // 1s
	want := []time.Duration{
		2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second,
		30 * time.Second, 30 * time.Second, // capped at maxBackoff
	}
	for i, w := range want {
		got = nextBackoff(got)
		if got != w {
			t.Fatalf("step %d: got %v, want %v", i, got, w)
		}
	}
}

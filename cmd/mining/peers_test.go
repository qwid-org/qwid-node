package main

import (
	"strings"
	"sync"
	"testing"
	"time"
)

func TestParsePeerIPs(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want [][4]byte
	}{
		{
			name: "no arguments",
			args: nil,
			want: nil,
		},
		{
			name: "pojedynczy adres jak dotychczas",
			args: []string{"1.2.3.4"},
			want: [][4]byte{{1, 2, 3, 4}},
		},
		{
			name: "flags are skipped",
			args: []string{"-log", "1.2.3.4"},
			want: [][4]byte{{1, 2, 3, 4}},
		},
		{
			name: "lista po przecinku",
			args: []string{"1.2.3.4,5.6.7.8"},
			want: [][4]byte{{1, 2, 3, 4}, {5, 6, 7, 8}},
		},
		{
			name: "many arguments",
			args: []string{"1.2.3.4", "5.6.7.8"},
			want: [][4]byte{{1, 2, 3, 4}, {5, 6, 7, 8}},
		},
		{
			name: "duplicates removed, order preserved",
			args: []string{"1.2.3.4", "5.6.7.8", "1.2.3.4"},
			want: [][4]byte{{1, 2, 3, 4}, {5, 6, 7, 8}},
		},
		{
			name: "granice zakresu bajtu",
			args: []string{"0.0.0.0,255.255.255.255"},
			want: [][4]byte{{0, 0, 0, 0}, {255, 255, 255, 255}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parsePeerIPs(tc.args)
			if err != nil {
				t.Fatalf("parsePeerIPs(%v) returned an error: %v", tc.args, err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, expected %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("address %d = %v, expected %v", i, got[i], tc.want[i])
				}
			}
		})
	}
}

// TestParsePeerIPsRejectsGarbage: a typo in the only route back into the network
// must be an error, not a silent skip that looks like success.
func TestParsePeerIPsRejectsGarbage(t *testing.T) {
	bad := []string{"1.2.3", "1.2.3.4.5", "1.2.3.256", "1.2.3.-1", "a.b.c.d", "1.2.3.4,zzz"}
	for _, arg := range bad {
		t.Run(arg, func(t *testing.T) {
			_, err := parsePeerIPs([]string{arg})
			if err == nil {
				t.Fatalf("parsePeerIPs(%q) returned no error", arg)
			}
			if !strings.Contains(err.Error(), "IP address") {
				t.Fatalf("message %q does not point at the address problem", err.Error())
			}
		})
	}
}

// TestDialerSkipsWhileInFlight guards against goroutine pile-up: an unreachable
// peer blocks its StartSubscribing* call, and without this a retry every 15 s
// would leak one goroutine per attempt for the lifetime of the node.
func TestDialerSkipsWhileInFlight(t *testing.T) {
	d := newDialer()
	release := make(chan struct{})
	var started sync.WaitGroup
	started.Add(1)

	if !d.run("peer", func() {
		started.Done()
		<-release
	}) {
		t.Fatal("the first call should have started")
	}
	started.Wait()

	if d.run("peer", func() { t.Error("the second call should not have started") }) {
		t.Fatal("the second call started while the first was still running")
	}

	close(release)

	// After the first call returns, the key frees up again.
	deadline := time.Now().Add(2 * time.Second)
	for {
		if d.run("peer", func() {}) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the key was not released after the first call finished")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestDialerRunsDifferentKeysConcurrently: the three topics of one peer must not
// block each other.
func TestDialerRunsDifferentKeysConcurrently(t *testing.T) {
	d := newDialer()
	release := make(chan struct{})
	defer close(release)

	var wg sync.WaitGroup
	for _, key := range []string{"N", "B", "T"} {
		wg.Add(1)
		if !d.run(key, func() {
			wg.Done()
			<-release
		}) {
			t.Fatalf("the call for key %q did not start", key)
		}
	}
	wg.Wait()
}

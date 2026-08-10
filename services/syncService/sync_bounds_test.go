package syncServices

import (
	"bytes"
	"testing"

	"github.com/qwid-org/qwid-node/common"
)

func TestClampHeaderSpan(t *testing.T) {
	// span within the bucket is unchanged
	if b, e := clampHeaderSpan(100, 110); b != 100 || e != 110 {
		t.Fatalf("small span changed: %d..%d", b, e)
	}
	// oversized span is clamped to NumberOfHashesInBucket
	if b, e := clampHeaderSpan(100, 100000); b != 100 || e != 100+common.NumberOfHashesInBucket {
		t.Fatalf("huge span not clamped: %d..%d (bucket=%d)", b, e, common.NumberOfHashesInBucket)
	}
	// inverted range normalizes eHeight up to bHeight
	if b, e := clampHeaderSpan(200, 100); b != 200 || e != 200 {
		t.Fatalf("inverted not normalized: %d..%d", b, e)
	}
}

func TestSampleIPs(t *testing.T) {
	ips := [][]byte{{1}, {2}, {3}, {4}, {5}}

	got := sampleIPs(ips, 3)
	if len(got) != 3 {
		t.Fatalf("len(sampleIPs(5,3)) = %d, want 3", len(got))
	}
	seen := map[string]bool{}
	for _, g := range got {
		if seen[string(g)] {
			t.Fatalf("duplicate entry in sample: %v", g)
		}
		seen[string(g)] = true
		found := false
		for _, in := range ips {
			if bytes.Equal(in, g) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("sample element %v not from input", g)
		}
	}

	// n >= len(ips) returns all of them
	if all := sampleIPs(ips, 10); len(all) != len(ips) {
		t.Fatalf("n>=len should return all: got %d, want %d", len(all), len(ips))
	}
	// empty input is safe
	if e := sampleIPs(nil, 3); len(e) != 0 {
		t.Fatalf("nil input should return empty, got %d", len(e))
	}
}

package syncServices

import (
	"testing"

	"github.com/wonabru/qwid-node/common"
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

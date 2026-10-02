package genesis

import (
	"testing"

	"github.com/qwid-org/qwid-node/common"
)

func TestRewardRatioToE10(t *testing.T) {
	for in, want := range map[float64]int64{2e-08: 200, 1e-07: 1000} {
		if got, err := rewardRatioToE10(in); err != nil || got != want {
			t.Errorf("%g -> %d, %v; want %d", in, got, err, want)
		}
	}
	for _, bad := range []float64{0, -1e-8, 1.234567891234e-8, 2} {
		if _, err := rewardRatioToE10(bad); err == nil {
			t.Errorf("%g accepted", bad)
		}
	}
}

// S9-02: the frame marker must match the message size it encodes; the
// consistency check used to run before genesis overwrote both.
func TestWireParamsMustAgree(t *testing.T) {
	ok := Genesis{MaxMessageSizeBytes: 151126018, MessageInitialization: common.GetByteInt32(151126018)}
	if err := validateWireParams(ok); err != nil {
		t.Fatal(err)
	}
	bad := ok
	bad.MessageInitialization = []byte{1, 2, 3, 4}
	if err := validateWireParams(bad); err == nil {
		t.Fatal("mismatched marker accepted")
	}
	short := ok
	short.MessageInitialization = []byte{1}
	if err := validateWireParams(short); err == nil {
		t.Fatal("malformed marker accepted")
	}
	if err := validateWireParams(Genesis{}); err != nil {
		t.Fatalf("absent wire params keep the defaults: %v", err)
	}
}

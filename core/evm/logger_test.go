package vm

import (
	"strings"
	"testing"
)

func TestToStringUsesSCCall(t *testing.T) {
	log := &GVMLogger{ResultSCCall: "SCSENTINEL", ResultTxCall: "TXSENTINEL"}
	s := log.ToString()
	if !strings.Contains(s, "Capture SC State and Fault: \n\nSCSENTINEL") {
		t.Fatalf("SC section must render ResultSCCall; got:\n%s", s)
	}
}

func TestAppendCapped(t *testing.T) {
	var dst string
	appendCapped(&dst, strings.Repeat("a", 100))
	if len(dst) != 100 {
		t.Fatalf("under-cap append: len=%d, want 100", len(dst))
	}
	// Overflow the cap in one shot.
	appendCapped(&dst, strings.Repeat("b", maxTraceFieldLen))
	if len(dst) > maxTraceFieldLen+64 {
		t.Fatalf("append not bounded: len=%d, cap=%d", len(dst), maxTraceFieldLen)
	}
	if !strings.Contains(dst, "trace truncated") {
		t.Fatal("expected a truncation marker once the cap is reached")
	}
	// Further appends are no-ops.
	prev := len(dst)
	appendCapped(&dst, "ccc")
	if len(dst) != prev {
		t.Fatalf("append past cap should be a no-op: len went %d -> %d", prev, len(dst))
	}
}

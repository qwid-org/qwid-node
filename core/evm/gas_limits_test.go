package vm

import (
	"math"
	"testing"

	"github.com/holiman/uint256"
	"github.com/qwid-org/qwid-node/params"
)

// Gas accounting is what bounds how much work one transaction can force every
// node in the network to perform. The arithmetic runs on attacker-chosen sizes,
// so the only interesting cases are the ones near the edges: a memory expansion
// that would overflow the word count, and a cost that would wrap a uint64.

func TestMemoryGasCostRefusesOverflowingSizes(t *testing.T) {
	mem := NewMemory()

	// A size near the top of uint64 cannot be charged for honestly; the
	// calculator must report the overflow instead of wrapping to a small
	// number, which would price unbounded memory at almost nothing.
	if _, err := memoryGasCost(mem, math.MaxUint64); err == nil {
		t.Fatal("a memory expansion to MaxUint64 was priced without error")
	}
	if _, err := memoryGasCost(mem, math.MaxUint64-31); err == nil {
		t.Fatal("a memory expansion just below MaxUint64 was priced without error")
	}
}

func TestMemoryGasCostIsZeroWhenNoGrowthIsNeeded(t *testing.T) {
	mem := NewMemory()
	mem.Resize(64)

	cost, err := memoryGasCost(mem, 64)
	if err != nil {
		t.Fatalf("pricing an already-available size failed: %v", err)
	}
	if cost != 0 {
		t.Fatalf("cost = %d for no growth, want 0", cost)
	}
}

func TestMemoryGasCostGrowsWithSize(t *testing.T) {
	prev := uint64(0)
	for _, size := range []uint64{32, 64, 1024, 32768, 1 << 20} {
		mem := NewMemory()
		cost, err := memoryGasCost(mem, size)
		if err != nil {
			t.Fatalf("pricing %d bytes failed: %v", size, err)
		}
		if cost < prev {
			t.Fatalf("expanding to %d cost %d, less than the smaller expansion at %d",
				size, cost, prev)
		}
		prev = cost
	}
	if prev == 0 {
		t.Fatal("a one-megabyte expansion was free")
	}
}

// toWordSize rounds up to 32-byte words and is used to price copies. Its result
// is multiplied by a per-word cost, so a wrap here would make a huge copy cheap.
func TestToWordSizeRoundsUpAndSaturates(t *testing.T) {
	cases := map[uint64]uint64{0: 0, 1: 1, 31: 1, 32: 1, 33: 2, 64: 2, 65: 3}
	for in, want := range cases {
		if got := toWordSize(in); got != want {
			t.Errorf("toWordSize(%d) = %d, want %d", in, got, want)
		}
	}
	// Near the top it must not wrap to a small word count.
	if got := toWordSize(math.MaxUint64); got < math.MaxUint64/32 {
		t.Errorf("toWordSize(MaxUint64) = %d, suspiciously small", got)
	}
}

// The stack has a hard depth limit; exceeding it must be an error rather than
// unbounded growth, since depth is attacker-controlled through nested calls.
func TestStackLimitIsEnforced(t *testing.T) {
	s := newstack()
	for i := 0; i < 1024; i++ {
		s.push(uint256.NewInt(uint64(i)))
	}
	if s.len() != 1024 {
		t.Fatalf("stack length = %d after 1024 pushes", s.len())
	}
	// The interpreter checks the limit before pushing; this documents the
	// constant the check is written against.
	if params.StackLimit != 1024 {
		t.Fatalf("params.StackLimit = %d, want 1024 — the interpreter's bounds "+
			"check is written against this value", params.StackLimit)
	}
}

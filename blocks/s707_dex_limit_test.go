package blocks

import (
	"errors"
	"testing"
)

// S7-07: a buy may not cost more, nor a sell pay less, than its signed limit.
func TestDexLimit(t *testing.T) {
	cases := []struct {
		op           int
		coins, limit int64
		ok           bool
	}{
		{3, -100, 0, true},    // no limit
		{3, -100, 100, true},  // costs exactly the limit
		{3, -101, 100, false}, // costs more
		{4, 100, 100, true},   // pays exactly the limit
		{4, 99, 100, false},   // pays less
		{4, 50, 0, true},
	}
	for _, c := range cases {
		err := checkDexLimit(c.op, c.coins, c.limit)
		if c.ok != (err == nil) {
			t.Fatalf("op %d coins %d limit %d: err=%v", c.op, c.coins, c.limit, err)
		}
		if err != nil && !errors.Is(err, ErrDexLimitExceeded) {
			t.Fatalf("a limit breach must be ErrDexLimitExceeded (skipped, not a block error): %v", err)
		}
	}
}

package transactionsDefinition

import (
	"math"
	"testing"
)

// TestCalcFee verifies AC-C2: fee multiplication detects overflow and negative
// operands instead of silently wrapping to a negative fee.
func TestCalcFee(t *testing.T) {
	cases := []struct {
		name     string
		price    int64
		usage    int64
		wantFee  int64
		wantErr  bool
	}{
		{"normal", 100, 2100, 210000, false},
		{"zero price", 0, 2100, 0, false},
		{"zero usage", 100, 0, 0, false},
		{"overflow", math.MaxInt64, 2, 0, true},
		{"overflow both large", 1 << 40, 1 << 40, 0, true},
		{"negative price", -1, 2100, 0, true},
		{"negative usage", 100, -5, 0, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tx := &Transaction{}
			tx.GasPrice = c.price
			tx.GasUsage = c.usage
			fee, err := tx.CalcFee()
			if c.wantErr {
				if err == nil {
					t.Fatalf("expected error for price=%d usage=%d, got fee=%d", c.price, c.usage, fee)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if fee != c.wantFee {
				t.Fatalf("fee = %d, want %d", fee, c.wantFee)
			}
		})
	}
}

package handlers

import (
	"net/http/httptest"
	"testing"
)

// S8-02: one request may not order hundreds of full block reads.
func TestValidatorBlocksCountIsCapped(t *testing.T) {
	for q, want := range map[string]int{"": 10, "5": 5, "50": 50, "500": 10, "-1": 10, "x": 10} {
		r := httptest.NewRequest("GET", "/api/validators/blocks?count="+q, nil)
		if got := validatorBlocksCount(r); got != want {
			t.Errorf("count=%q -> %d, want %d", q, got, want)
		}
	}
}

package handlers

import (
	"strings"
	"testing"
)

// Audit 2026-11-12 F-SC-01: balances are int64, so transfer and mint must
// refuse a negative amount - transfer(victim, -n) moved the victim's tokens to
// the caller. The behaviour is tested on the compiled contract in
// blocks/audit_2026_11_12_full_test.go; this pins the website's copy.
func TestTokenTemplateRefusesNegativeAmounts(t *testing.T) {
	if n := strings.Count(tokenContractTemplate, `require(amount > 0, "amount must be positive");`); n != 2 {
		t.Fatalf("the token template guards %d of its 2 amount-taking functions against negative amounts", n)
	}
}

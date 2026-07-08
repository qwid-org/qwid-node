# AC-H6 — DEX Constant-Product (`x·y=k`) Fix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make DEX buy/sell pricing exact constant product (`x·y=k`) by removing the `2·amountToken` factor in the swap denominators, eliminating the "denominator approaches zero at half the pool" bug.

**Architecture:** Extract the swap price arithmetic into a pure, unit-testable helper `constantProductPrice(coinPool, tokenPool, amountToken, roundDecimals)` that computes `coinPool/(tokenPool − amountToken)` (signed `amountToken`: >0 buy, <0 sell), and call it from the buy (op 3) and sell (op 4) branches of `GenerateOptDataDEX`. This replaces the two `tokenPool − 2·amountToken` expressions.

**Tech Stack:** Go 1.23.6; `blocks` package; `common.RoundToken`.

## Global Constraints

- Build/test with `GOROOT=/home/wonabru/sdk/go1.24.0`. Example: `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./blocks/`.
- Branch `security-fixes`. Commit `OB-xx (CONSENSUS)` convention. End messages with `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- **Only the buy/sell swap pricing changes.** Do NOT change: add-liquidity (op 2), withdraw (ops 5/6, which use spot `poolPrice`), the sign conventions, the balance-sufficiency checks (`evaluate.go:199-230`), the pool-update lines (`evaluate.go:365-366`), or any sender/handler.
- **No slippage parameter and no swap fee** — both excluded by design decision.
- The helper extraction must be **behavior-preserving** relative to "the current code with `2*` removed" — i.e. same rounding (`common.RoundToken(..., roundDecimals)`), same guard semantics (price 0 when `coinPool ≤ 0` or denominator `≤ 0`).

---

## File Structure

- `blocks/evaluate.go` — add `constantProductPrice`; replace the buy (`:176-184`) and sell (`:185-194`) price computation to call it (removing `2*`); update the op comment.
- `blocks/dex_constant_product_test.go` (new) — pure unit tests of the helper (`k`-invariant, half-pool bounded, full-pool guard, round-trip).

---

## Task 1: Constant-product price helper + wire into buy/sell + tests

**Files:**
- Modify: `blocks/evaluate.go` (`GenerateOptDataDEX`, buy `:176-184` and sell `:185-194`; add helper)
- Test: `blocks/dex_constant_product_test.go` (new)

**Interfaces:**
- Consumes: `common.RoundToken(value float64, decimals int) float64`.
- Produces: `func constantProductPrice(coinPool, tokenPool, amountToken float64, roundDecimals int) float64`.

- [ ] **Step 1: Write the failing tests**

Create `blocks/dex_constant_product_test.go`:

```go
package blocks

import (
	"math"
	"testing"
)

// roundDecimals used by the DEX (common.Decimals=8 + an 8-decimal token).
const rdTest = 16

func TestConstantProductPreservesK(t *testing.T) {
	coinPool, tokenPool := 1000.0, 1000.0
	k := coinPool * tokenPool

	// BUY Δ tokens: price = coin/(token-Δ); coinPaid = price*Δ; pool -> (coin+paid, token-Δ).
	buy := 100.0
	pB := constantProductPrice(coinPool, tokenPool, buy, rdTest)
	if pB <= 0 {
		t.Fatal("buy price must be positive")
	}
	coinPaid := pB * buy
	if kB := (coinPool + coinPaid) * (tokenPool - buy); math.Abs(kB-k)/k > 1e-6 {
		t.Fatalf("BUY broke k: got %v want %v", kB, k)
	}

	// SELL Δ tokens: caller negates amountToken, so pass -Δ; pool -> (coin-recv, token+Δ).
	sell := 100.0
	pS := constantProductPrice(coinPool, tokenPool, -sell, rdTest)
	if pS <= 0 {
		t.Fatal("sell price must be positive")
	}
	coinRecv := pS * sell
	if kS := (coinPool - coinRecv) * (tokenPool + sell); math.Abs(kS-k)/k > 1e-6 {
		t.Fatalf("SELL broke k: got %v want %v", kS, k)
	}
}

func TestConstantProductHalfPoolBoundedAndGuard(t *testing.T) {
	coinPool, tokenPool := 1000.0, 1000.0
	// Half-pool buy: previously the -2*amount guard made this a no-op (denom 0);
	// now it prices at 2*poolPrice (finite), costing ~the whole coin pool.
	pHalf := constantProductPrice(coinPool, tokenPool, 500.0, rdTest)
	if pHalf <= 0 {
		t.Fatal("half-pool buy must now be priced (bounded), not a no-op")
	}
	if math.Abs(pHalf-2.0) > 1e-6 {
		t.Fatalf("half-pool price = %v, want 2.0", pHalf)
	}
	// Full-pool and beyond: rejected by the denom>0 guard (price 0).
	if p := constantProductPrice(coinPool, tokenPool, 1000.0, rdTest); p != 0 {
		t.Fatalf("full-pool buy must be rejected (price 0), got %v", p)
	}
	if p := constantProductPrice(coinPool, tokenPool, 1200.0, rdTest); p != 0 {
		t.Fatalf("over-full buy must be rejected (price 0), got %v", p)
	}
	// Non-positive pool: price 0.
	if p := constantProductPrice(0, tokenPool, 100.0, rdTest); p != 0 {
		t.Fatalf("empty coin pool must yield price 0, got %v", p)
	}
}

func TestConstantProductRoundTripNoValueCreation(t *testing.T) {
	coinPool, tokenPool := 1000.0, 1000.0
	d := 50.0
	// Buy d, then sell d against the resulting pool: coin received must ~equal coin paid
	// (no fee => buy-then-sell of the same amount is a wash).
	pB := constantProductPrice(coinPool, tokenPool, d, rdTest)
	coinPaid := pB * d
	c2, t2 := coinPool+coinPaid, tokenPool-d
	pS := constantProductPrice(c2, t2, -d, rdTest)
	coinRecv := pS * d
	if math.Abs(coinPaid-coinRecv)/coinPaid > 1e-6 {
		t.Fatalf("round-trip leaked value: paid %v received %v", coinPaid, coinRecv)
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./blocks/ -run TestConstantProduct`
Expected: FAIL — `constantProductPrice` undefined.

- [ ] **Step 3: Add the helper**

In `blocks/evaluate.go`, add near `GenerateOptDataDEX` (`common` and `math` are already imported):

```go
// constantProductPrice returns the exact constant-product (x*y=k) average
// execution price coinPool/(tokenPool - amountToken), rounded to roundDecimals,
// or 0 when the pools/denominator are non-positive (e.g. a buy of the whole
// token pool, which is not allowed). amountToken is SIGNED: >0 for a buy (tokens
// leave the pool), <0 for a sell (tokens enter the pool). Using amountToken
// (not the old 2*amountToken) makes swaps exact x*y=k (AC-H6): the price
// diverges only as a trade approaches the full pool, never at half the pool.
func constantProductPrice(coinPool, tokenPool, amountToken float64, roundDecimals int) float64 {
	denom := tokenPool - amountToken
	if coinPool > 0 && denom > 0 {
		return common.RoundToken(coinPool/denom, roundDecimals)
	}
	return 0
}
```

- [ ] **Step 4: Wire it into buy and sell (remove the `2*`)**

In `GenerateOptDataDEX`, replace the buy branch (`blocks/evaluate.go:176-184`):

```go
	case 3: //buy
		price = constantProductPrice(coinPoolAmount, tokenPoolAmount, amountTokenFloat, int(common.Decimals+ti.Decimals))
		if price > 0 {
			amount := common.RoundCoin(-price * amountTokenFloat)
			amountCoinInt64 = int64(amount * math.Pow10(int(common.Decimals)))
			amountTokenInt64 = int64(amountTokenFloat * math.Pow10(int(ti.Decimals)))
		}
```

and the sell branch (`blocks/evaluate.go:185-194`):

```go
	case 4: //sell
		amountTokenFloat *= -1
		price = constantProductPrice(coinPoolAmount, tokenPoolAmount, amountTokenFloat, int(common.Decimals+ti.Decimals))
		if price > 0 {
			amount := common.RoundCoin(-price * amountTokenFloat)
			amountCoinInt64 = int64(amount * math.Pow10(int(common.Decimals)))
			amountTokenInt64 = int64(amountTokenFloat * math.Pow10(int(ti.Decimals)))
		}
```

(The only behavioral change vs today is the denominator: `tokenPool − amountToken` instead of `tokenPool − 2·amountToken`. The `if price > 0` gate, the `-price*amountTokenFloat` coin computation, and the int64 scaling are unchanged.) Update the `// 2 - adding liquidity, 3 - buy trade, ...` comment at `:120` only if it describes the `2·amount` behavior.

- [ ] **Step 5: Run tests + build**

Run: `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./blocks/ -run TestConstantProduct -v && GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go build ./...`
Expected: PASS, build OK.

- [ ] **Step 6: Run the broader blocks suite (no regression)**

Run: `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./blocks/`
Expected: PASS (any pre-existing DB-gated skips remain skips; the known unrelated `core/abi` `ExampleJSON` panic is not in `blocks`).

- [ ] **Step 7: Commit**

```bash
git add blocks/evaluate.go blocks/dex_constant_product_test.go
git commit -m "OB-113 AC-H6 (CONSENSUS): DEX exact constant-product pricing (remove 2*amount denominator)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Final verification

- [ ] `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go build ./...` → exit 0.
- [ ] `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./blocks/` → PASS.
- [ ] Update `SECURITY_AUDIT.md`: mark **AC-H6** fixed — DEX buy/sell now use exact constant-product `x·y=k` pricing (removed the `2·amount` denominator that diverged at half the pool); note that **no slippage parameter and no swap fee** were added, by design decision, and that block-ordering (sandwich) mitigation beyond the honest curve was not pursued.

## Deferred (not in this plan)
- A Uniswap-style swap fee (0.3% LP fee) — separate economics decision.
- Any user slippage/min-output parameter — excluded by decision.

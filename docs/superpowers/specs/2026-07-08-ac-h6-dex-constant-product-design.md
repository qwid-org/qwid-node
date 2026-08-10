# AC-H6 — DEX Constant-Product (`x·y=k`) Price Fix

**Date:** 2026-07-08
**Branch:** `security-fixes`
**Source:** `SECURITY_AUDIT.md` AC-H6 — "DEX price manipulation — Denominator approaches zero. No slippage protection. Sandwich attacks." (`blocks/evaluate.go:93-110`, actual math at `:176-194`).

## Context and decision

This is a Uniswap-style constant-product AMM. Two design decisions were settled:

- **No user slippage parameter.** Price impact with trade size is inherent to the AMM curve (by design), and the DEX stays parameter-free like a bare Uniswap pool — no `OptData` min-output field, no sender changes.
- **Fix the price formula to exact `x·y=k`.** The current swap price uses `tokenPool − 2·amountToken` in the denominator, which diverges when a trade reaches **half** the token pool (and goes negative beyond that) — the "denominator approaches zero" bug. True constant product uses `tokenPool ∓ amountToken`, which diverges only as a trade approaches the **whole** pool (unreachable), so the bug disappears by construction with no artificial guard.

### Ground truth (current math, `blocks/evaluate.go:119-253` `GenerateOptDataDEX`)

Sign convention: positive `amountCoinInt64`/`amountTokenInt64` = the sender **receives**; negative = the sender **pays**; the DEX pool moves opposite.

- **BUY (op 3, `:176-184`):** sender pays coin, receives `amountToken` tokens.
  ```go
  if coinPoolAmount > 0 && tokenPoolAmount-2*amountTokenFloat > 0 {
      price = common.RoundToken(coinPoolAmount/(tokenPoolAmount-2*amountTokenFloat), int(common.Decimals+ti.Decimals))
  }
  if price > 0 {
      amount := common.RoundCoin(-price * amountTokenFloat)   // coin paid (negative below)
      amountCoinInt64 = int64(amount * math.Pow10(int(common.Decimals)))
      amountTokenInt64 = int64(amountTokenFloat * math.Pow10(int(ti.Decimals)))
  }
  ```
- **SELL (op 4, `:185-194`):** `amountTokenFloat *= -1` first, then the identical price block; sender pays token, receives coin.
- Pool state is updated by the caller (`EvaluateSCForBlock`, `evaluate.go:365-366`): `accDex.TokenPool += -tokenAmount; accDex.CoinPool += -coinAmount`, using the computed `amountTokenInt64`/`amountCoinInt64`. These already preserve the invariant given correct amounts and do NOT change.
- `poolPrice = coinPool/tokenPool` (`:150-152`) is the spot price used by withdraw ops 5/6 and is unaffected.

## Goal

Make the buy/sell swap price exact constant product (`x·y=k`), eliminating the half-pool divergence, without adding any slippage parameter, fee, or artificial guard.

## Non-goals (out of scope)

- User slippage / min-output parameter (dropped by decision).
- A Uniswap-style swap fee (0.3% LP fee) — the DEX has none today; adding one is a separate economics decision.
- Add-liquidity (op 2), withdraw (ops 5/6), the balance-sufficiency checks, the sign conventions, and the pool-update lines — all unchanged.
- Rewriting block tx ordering (sandwich mitigation beyond the curve is not pursued; the curve makes large-trade price impact honest, and no slippage param is added by decision).

## Design

### The change — remove the factor of `2` in both swap denominators

**BUY (`blocks/evaluate.go:177-178`):**
```go
if coinPoolAmount > 0 && tokenPoolAmount-amountTokenFloat > 0 {
    price = common.RoundToken(coinPoolAmount/(tokenPoolAmount-amountTokenFloat), int(common.Decimals+ti.Decimals))
}
```

**SELL (`blocks/evaluate.go:187-188`):** identical edit. After the preceding `amountTokenFloat *= -1` (so `amountTokenFloat = −Δ` for a sell of `Δ`), `tokenPoolAmount - amountTokenFloat` evaluates to `tokenPool + Δ` — exactly the constant-product sell denominator.
```go
if coinPoolAmount > 0 && tokenPoolAmount-amountTokenFloat > 0 {
    price = common.RoundToken(coinPoolAmount/(tokenPoolAmount-amountTokenFloat), int(common.Decimals+ti.Decimals))
}
```

Update the operation comment if it references the `2·amount` behavior.

### Why this is exact `x·y=k`

- **BUY Δ:** `price = coinPool/(tokenPool − Δ)`, so `coinPaid = price·Δ = coinPool·Δ/(tokenPool − Δ)`. Pool becomes `(coinPool + coinPaid, tokenPool − Δ)`, and `(coinPool + coinPaid)(tokenPool − Δ) = coinPool·tokenPool = k`.
- **SELL Δ:** `price = coinPool/(tokenPool + Δ)`, so `coinReceived = coinPool·Δ/(tokenPool + Δ)`. Pool becomes `(coinPool − coinReceived, tokenPool + Δ)`, and `(coinPool − coinReceived)(tokenPool + Δ) = coinPool·tokenPool = k`.
- The guard `tokenPool − amountTokenFloat > 0` now means: BUY requires `Δ < tokenPool` (cannot buy the whole pool — the natural Uniswap constraint); SELL's `tokenPool + Δ > 0` is always true. Divergence occurs only as `Δ → tokenPool`, which the guard blocks.

### Behavior change (intended)

- A trade at or beyond **half** the token pool, which previously hit `tokenPool − 2Δ ≤ 0` → `price` stays 0 → the swap silently no-ops, now **executes** at the correct (steep but finite) constant-product price for any `Δ < tokenPool`.
- Trades in the small-positive-denominator zone that previously executed at an inflated price now execute at the correct, lower constant-product price.

### Consensus / error handling

- Consensus-affecting (swap pricing and the executable trade range change). Labeled `(CONSENSUS)`; acceptable under the genesis reset.
- Deterministic: the formula is pure arithmetic over pool state and the tx's `amountToken`; identical across nodes.
- Over-large trades (`Δ ≥ tokenPool`) keep today's behavior: `price` stays 0, amounts stay 0, no error (the DEX effects are a no-op for that tx) — unchanged from the current guard-fails path, just with the correct threshold.

## Testing

`GenerateOptDataDEX` reads a fair amount of state (`account.GetDexAccountByAddressBytes`, `GetBalance`, `State.Tokens`, sender/dex accounts), so a full end-to-end unit test needs that setup (DB-gated skip if needed, as other `blocks` tests do). If that harness is impractical, the plan **may extract the pure swap arithmetic into a helper** — e.g. `constantProductCoinFloat(coinPool, tokenPool, amountToken float64, isBuy bool) (price, coin float64)` — call it from both the buy and sell branches, and unit-test the helper directly for the `k`-invariant (no state needed). Prefer this if it makes the invariant tests clean; it is a small, behavior-preserving extraction. Tests to write either way:

- **`k` preserved on BUY:** for a mid-sized buy, assert `(CoinPool + coinPaid)·(TokenPool − tokensOut)` equals `CoinPool·TokenPool` within an integer-rounding tolerance (state the tolerance; rounding via `RoundCoin`/`RoundToken` makes it approximate, not exact).
- **`k` preserved on SELL:** symmetric.
- **Half-pool buy now succeeds and is bounded:** a buy of ≈half the token pool returns a finite, positive `coinPaid` (≈ the whole coin pool) instead of the previous `price == 0` no-op.
- **Near-full-pool buy is rejected by the guard:** a buy of `Δ ≥ tokenPool` leaves `price == 0`/zero amounts (guard `tokenPool − Δ > 0` false).
- **Buy-then-sell round-trip:** buying Δ then selling Δ returns approximately the starting coin balance (minus rounding), and the pool returns approximately to its start — confirming no value creation.
- **Regression vs old formula:** for a small trade the new `coinPaid` is strictly less than the old `2·amount` formula would have charged (documents the honest-pricing change).

Tests run with `GOROOT=/home/wonabru/sdk/go1.24.0`.

## Files touched

- `blocks/evaluate.go` — the buy (`:177-178`) and sell (`:187-188`) denominators (remove `2*`), plus the operation comment.
- Tests in `blocks/` (new `blocks/dex_constant_product_test.go`).

## Rollout / commit plan

Likely a single `OB-xx (CONSENSUS)` commit (the change is two edits + tests). Split into two only if the test setup warrants its own commit.

Not "done" until `blocks` builds and the DEX tests pass, and `SECURITY_AUDIT.md` marks AC-H6 fixed (constant-product; note no slippage param and no fee were added by decision).

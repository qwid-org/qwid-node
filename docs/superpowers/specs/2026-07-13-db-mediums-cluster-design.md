# EVM/DB Mediums Cluster — DB-M1/M3/M4/M9/M10

**Date:** 2026-07-13
**Branch:** `security-fixes`
**Source:** `SECURITY_AUDIT.md` reconciliation — the five OPEN EVM/DB MEDIUM findings (cluster B of the mediums sweep).

## Context

Five EVM/DB mediums remain. Four are node-local correctness/robustness fixes with **no consensus impact**; one (DB-M10) is a precompile bound that is **consensus-adjacent** and labeled accordingly.

### Ground truth (from exploration)
- **DB-M3** (`core/evm/logger.go` `GVMLogger.ToString`): the "Capture SC State and Fault" section concatenates `log.ResultTxCall` instead of `log.ResultSCCall` — a copy/paste bug. GVMLogger output is the tracer's `OutputLogs`, which is **informational and excluded from the tx-hash preimage** (`GetBytesWithoutSignature`), so this is non-consensus.
- **DB-M4** (same file): every `Capture*` method does unbounded `(*log).ResultXxx += fmt.Sprintf(...)`. For a long/large contract execution the per-frame fields (`ResultRestFrameCall` especially) grow without bound → memory/DB bloat (`OutputLogs` is persisted in `GetBytes`). Non-consensus (tracer output), so bounding/truncating it is safe.
- **DB-M9** (`core/stateDB/methods.go` `ForEachStorage`): `for h, _ := range shs { if value, dirty := shs[h]; dirty { ... } }` — `dirty` is the map-lookup ok-bool for a key just obtained by ranging the same map, so it is **always true**. The check is meaningless but functionally harmless (it already iterates all entries). `ForEachStorage` is only declared in the `StateDB` interface (`core/evm/interface.go:76`); no consensus path depends on the `dirty` semantics.
- **DB-M1** (`core/evm/interpreter.go`): `for i, eip := range cfg.ExtraEips { ... cfg.ExtraEips = append(cfg.ExtraEips[:i], cfg.ExtraEips[i+1:]...) ... }` mutates the slice being ranged over on EIP-activation failure, corrupting subsequent iterations. **Crucially, `ExtraEips` is hardcoded `[]int{}` at all three call sites (`blocks/evaluate.go:511,607,665`), so the loop never executes on this chain** — the bug is **dormant**. The fix is correctness/robustness with zero live consensus impact.
- **DB-M10** (`core/evm/contracts.go` `bigModExp.Run`): `baseLen`/`expLen`/`modLen` are read from attacker-controlled 32-byte fields via `.Uint64()` with **no explicit ceiling**; they then drive `getData(...)` and `base.Exp(base, exp, mod)`. Normally the EIP-2565 gas in `RequiredGas` makes huge operands unaffordable, but **gas is not actually charged on this chain (DB-C4: `GasPrice=0`, refunds/costs not applied)**, so the gas ceiling does not bind — a huge `modLen`/`expLen` is a real OOM/DoS vector. This is an EVM precompile in the execution path → **consensus-adjacent**.

## Decisions (confirmed)
- **DB-M10:** add a generous operand-length ceiling `MaxModExpLen = 1024` bytes (8192-bit operands; RSA-4096 is 512 bytes, so no realistic contract is affected). If any of `baseLen`/`expLen`/`modLen` exceeds it, `Run` returns an error (`ErrModExpOperandTooLarge`). Labeled `(CONSENSUS)` because it changes the precompile's result for above-ceiling inputs (in practice only pathological attack inputs). Chosen over "return zeros above ceiling" and over "defer".
- **DB-M4:** per-field cap `maxTraceFieldLen = 256 * 1024` bytes; once a field reaches the cap, stop appending and add a one-time `…[trace truncated]` marker.

## Design

### DB-M3 — fix the wrong field in `ToString` (non-consensus)
In `core/evm/logger.go` `GVMLogger.ToString`, change the SC-state/fault line from `log.ResultTxCall` to `log.ResultSCCall`:
```go
	restxt += "Capture SC State and Fault: \n\n" + log.ResultSCCall
```

### DB-M4 — bound `GVMLogger` accumulation (non-consensus)
Add a package const and a helper, and route every unbounded `+=` through it:
```go
const maxTraceFieldLen = 256 * 1024 // DB-M4: per-field trace cap to bound OutputLogs memory/DB growth

// appendCapped appends s to *dst unless *dst has reached maxTraceFieldLen, in
// which case it appends a one-time truncation marker and drops further output.
func appendCapped(dst *string, s string) {
	if len(*dst) >= maxTraceFieldLen {
		return
	}
	if len(*dst)+len(s) > maxTraceFieldLen {
		*dst += s[:maxTraceFieldLen-len(*dst)] + "\n…[trace truncated]\n"
		return
	}
	*dst += s
}
```
Replace each `(*log).ResultXxx += fmt.Sprintf(...)` / `log.ResultXxx += ...` site in the `Capture*` methods with `appendCapped(&log.ResultXxx, fmt.Sprintf(...))`. Behavior is unchanged until a field reaches 256 KB, after which output is truncated (the trace is informational; truncation loses only debug detail, never consensus data).

### DB-M9 — simplify the always-true `dirty` check (non-consensus)
In `core/stateDB/methods.go` `ForEachStorage`, replace:
```go
	for h, _ := range shs {
		if value, dirty := shs[h]; dirty {
			if !cb(h, value) {
				return nil
			}
			continue
		}
	}
```
with the equivalent, honest form:
```go
	for h, value := range shs {
		if !cb(h, value) {
			return nil
		}
	}
```
Identical behavior (the old `dirty` was always true); removes the misleading dead conditional.

### DB-M1 — fix mutate-while-range (dormant; non-consensus in practice)
In `core/evm/interpreter.go`, replace the loop:
```go
		for i, eip := range cfg.ExtraEips {
			copy := *cfg.JumpTable
			if err := EnableEIP(eip, &copy); err != nil {
				cfg.ExtraEips = append(cfg.ExtraEips[:i], cfg.ExtraEips[i+1:]...)
				fmt.Printf("EIP activation failed eip %v error %v", eip, err)
			}
			cfg.JumpTable = &copy
		}
```
with a version that builds a filtered list of successfully-enabled EIPs instead of mutating the slice under the range (and drops the `copy`-shadows-builtin name):
```go
		enabled := make([]int, 0, len(cfg.ExtraEips))
		for _, eip := range cfg.ExtraEips {
			jt := *cfg.JumpTable
			if err := EnableEIP(eip, &jt); err != nil {
				fmt.Printf("EIP activation failed eip %v error %v", eip, err)
				continue // skip the failed EIP; do not apply its (partial) table
			}
			cfg.JumpTable = &jt
			enabled = append(enabled, eip)
		}
		cfg.ExtraEips = enabled
```
Now `cfg.ExtraEips` ends with exactly the EIPs that activated, with no iteration corruption. (Behavior is only reachable if `ExtraEips` is ever non-empty; today it is always empty, so there is no live consensus change.)

### DB-M10 — operand-length ceiling in `bigModExp.Run` (CONSENSUS)
In `core/evm/contracts.go`, add:
```go
const MaxModExpLen = 1024 // DB-M10: max bytes per MODEXP operand (8192-bit); above any realistic crypto use

var ErrModExpOperandTooLarge = errors.New("modexp operand length exceeds maximum")
```
In `bigModExp.Run`, immediately after the three `baseLen`/`expLen`/`modLen` are read (before the `getData`/`big.Int` construction), add:
```go
	if baseLen > MaxModExpLen || expLen > MaxModExpLen || modLen > MaxModExpLen {
		return nil, ErrModExpOperandTooLarge // DB-M10: bound operand size (gas does not bind on this chain — DB-C4)
	}
```
This runs before the special-case `baseLen==0 && modLen==0` and operand-load, so an oversized request errors out instead of allocating/exponentiating enormous integers. Legitimate crypto (RSA-4096 ≤ 512 B, and all real curve/field sizes) is far below 1024 B and unaffected. (`errors` may need importing in `contracts.go` — verify.)

## Non-goals
- Real gas economics / charging (DB-C4) — the "proper" MODEXP bound; DB-M10 is defense-in-depth until then.
- Changing the tracer's format or making `OutputLogs` consensus-relevant.
- Any change to EIP semantics for the (always-empty) `ExtraEips`.

## Error handling / determinism
- DB-M3/M4/M9/M1: no consensus/tx/block/wire impact (tracer output, a cosmetic iteration cleanup, and a dormant path). Commits are `OB-125` (not `(CONSENSUS)`).
- **DB-M10: `(CONSENSUS)`** — deterministic (a fixed byte ceiling); every node rejects the same oversized inputs identically. On a pre-launch chain with gas unenforced, this is the intended DoS bound; the ceiling is above any legitimate use so no real contract's result changes.

## Testing
Pure, CGO-free unit tests where the logic is isolable:
- **DB-M3:** set `ResultSCCall` to a sentinel, call `ToString`, assert the "Capture SC State and Fault" section contains the sentinel (and that `ResultTxCall`'s sentinel does NOT appear there).
- **DB-M4:** `appendCapped` — appending under the cap grows the string; appending past the cap stops at `maxTraceFieldLen`-ish and includes the truncation marker; a subsequent append is a no-op.
- **DB-M10:** `bigModExp.Run` with a `modLen`/`expLen`/`baseLen` field > `MaxModExpLen` returns `ErrModExpOperandTooLarge`; a small valid modexp (e.g. 3^2 mod 5 = 4) still computes correctly.
- **DB-M9 / DB-M1:** verified by build + `go vet` + inspection (DB-M9 behavior is provably unchanged; DB-M1's path is dormant). Optionally a light `ForEachStorage` visit-all test if a `StateAccount` is easy to construct — otherwise inspection.

Tests run with `GOROOT=/home/wonabru/sdk/go1.24.0`; build `GOROOT=… go build ./...`.

## Files touched
- `core/evm/logger.go` — DB-M3 (field fix), DB-M4 (`maxTraceFieldLen` + `appendCapped` + routed `+=` sites).
- `core/stateDB/methods.go` — DB-M9 (`ForEachStorage` simplification).
- `core/evm/interpreter.go` — DB-M1 (filtered-EIP loop).
- `core/evm/contracts.go` — DB-M10 (`MaxModExpLen`, `ErrModExpOperandTooLarge`, ceiling check).
- New tests: `core/evm/logger_test.go` (DB-M3 + DB-M4), `core/evm/contracts_modexp_test.go` (DB-M10).

## Rollout / commit plan
`OB-125` commits:
1. DB-M3 + DB-M4 — logger field fix + bounded accumulation (+ tests). *(not consensus)*
2. DB-M9 — `ForEachStorage` simplification. *(not consensus)*
3. DB-M1 — filtered-EIP loop (dormant path). *(not consensus)*
4. **`(CONSENSUS)`** DB-M10 — MODEXP operand-length ceiling (+ test).

Not "done" until the touched packages build and the new tests pass, and `SECURITY_AUDIT.md` reconciliation moves DB-M1/M3/M4/M9/M10 to FIXED (DB-M10 with the `(CONSENSUS)` + gas-deferred note).

## Deferred (follow-ups)
- Real gas economics (DB-C4) — the principled MODEXP/EVM resource bound.
- Wallet mediums (cluster C: CW-M2/M3).
- Remaining deferred-by-design partials.

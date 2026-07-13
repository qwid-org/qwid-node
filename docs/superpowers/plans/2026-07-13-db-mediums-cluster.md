# EVM/DB Mediums Cluster Implementation Plan (DB-M1/M3/M4/M9/M10)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the five OPEN EVM/DB mediums — fix the tracer's wrong field (DB-M3) and bound its growth (DB-M4), simplify a misleading storage-iteration check (DB-M9), fix a dormant mutate-while-range EIP loop (DB-M1), and add a MODEXP operand-length ceiling (DB-M10).

**Architecture:** Four independent tasks across `core/evm/` + `core/stateDB/`. DB-M3/M4/M9/M1 are node-local (tracer output / cosmetic / a dormant path). DB-M10 is a consensus-adjacent precompile bound, committed separately with a `(CONSENSUS)` label.

**Tech Stack:** Go 1.23.6 (build with the `sdk/go1.24.0` toolchain), CGO (RocksDB + liboqs). Test files use `package vm` (the `core/evm` package).

## Global Constraints
- Build/test with `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go`. This repo uses CGO; export before building:
  ```
  export GOROOT=/home/wonabru/sdk/go1.24.0
  export PATH=$GOROOT/bin:$PATH
  export CGO_CFLAGS="-isystem $HOME/local/include"
  export CGO_LDFLAGS="-L$HOME/local/lib -L/usr/local/intelpython3/lib -lrocksdb -lstdc++ -lm -lz -lsnappy -llz4 -lzstd -lbz2 -lpthread -ldl"
  ```
- Branch `security-fixes`. End every commit message with a blank line then `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- Commits are `OB-125`. Tasks 1-3 are node-local (NOT `(CONSENSUS)`). **Task 4 (DB-M10) IS `(CONSENSUS)`** — its commit subject must include the `(CONSENSUS)` label.
- `errors`, `math/big`, `common` are already imported in `contracts.go`; `fmt` in `interpreter.go`; `fmt`/`hex` in `logger.go`. Do not remove imports still in use.
- DB-M10 constant: `MaxModExpLen = 1024` (bytes/operand); error `ErrModExpOperandTooLarge`. DB-M4 constant: `maxTraceFieldLen = 256 * 1024`.

---

## Task 1: DB-M3 + DB-M4 — fix tracer field + bound accumulation

**Files:**
- Modify: `core/evm/logger.go` (`ToString`; add `maxTraceFieldLen` + `appendCapped`; route all `Capture*` `+=` sites through it)
- Test: `core/evm/logger_test.go` (new)

**Interfaces:**
- Produces: `appendCapped(dst *string, s string)`; const `maxTraceFieldLen`.
- Consumes (existing): `GVMLogger` fields `ResultTxCall`, `ResultTopFrameCall`, `ResultRestFrameCall`, `ResultSCCall`; `ToString`; the `Capture*` methods.

- [ ] **Step 1: Write the failing tests** — create `core/evm/logger_test.go`:
```go
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
```

- [ ] **Step 2: Run to verify it fails** — `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./core/evm/ -run 'TestToStringUsesSCCall|TestAppendCapped' -v` → FAIL to compile (`appendCapped`/`maxTraceFieldLen` undefined).

- [ ] **Step 3: DB-M3 — fix the wrong field in `ToString`** — in `core/evm/logger.go`, change the SC-state/fault line:
```go
	restxt += "Capture SC State and Fault: \n\n" + log.ResultSCCall
```
(was `... + log.ResultTxCall`).

- [ ] **Step 4: DB-M4 — add the cap + helper, and route all `+=` sites** — in `core/evm/logger.go`, add near the top (after the imports / above `GVMLogger`):
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
Then convert EVERY accumulation site in the `Capture*` methods from the pattern `(*log).ResultXxx += fmt.Sprintf(...)` to `appendCapped(&log.ResultXxx, fmt.Sprintf(...))`, where `ResultXxx` is one of `ResultTxCall`, `ResultTopFrameCall`, `ResultRestFrameCall`, `ResultSCCall`. Find them all with `grep -n 'Result.*+= fmt.Sprintf' core/evm/logger.go` (there are ~30 across `CaptureTxStart`, `CaptureTxEnd`, `CaptureStart`, `CaptureEnd`, `CaptureEnter`, `CaptureExit`, `CaptureState`, `CaptureFault`). Examples:
```go
// before: (*log).ResultTxCall += fmt.Sprintf("Gas usage limit: %v\n", gasLimit)
appendCapped(&log.ResultTxCall, fmt.Sprintf("Gas usage limit: %v\n", gasLimit))
// before: (*log).ResultSCCall += fmt.Sprintf("Fault Error: %v\n", err)
appendCapped(&log.ResultSCCall, fmt.Sprintf("Fault Error: %v\n", err))
```
Do NOT change `ToString` (already concatenates the fields), the `= ""` reset in the constructor, or any method signature.

- [ ] **Step 5: Run + build** — `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./core/evm/ -run 'TestToStringUsesSCCall|TestAppendCapped' -v && GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go build ./...` → tests PASS, build exit 0. Also confirm no bare `Result.*+= fmt.Sprintf` remains: `grep -n 'Result.*+= fmt.Sprintf' core/evm/logger.go` → no output.

- [ ] **Step 6: Commit**
```bash
git add core/evm/logger.go core/evm/logger_test.go
git commit -m "$(printf 'OB-125 DB-M3/M4: fix ToString SC field + bound GVMLogger accumulation\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Task 2: DB-M9 — simplify the always-true `dirty` check in `ForEachStorage`

**Files:**
- Modify: `core/stateDB/methods.go` (`ForEachStorage`)

**Interfaces:**
- Consumes (existing): `StateAccount.StatesHashes`, the `cb func(key, value common.Hash) bool` callback.
- Note: behavior is provably unchanged (the old `dirty` was always true), so this is verified by build + vet + inspection; no unit test.

- [ ] **Step 1: Simplify the loop** — in `core/stateDB/methods.go` `ForEachStorage`, replace:
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
with:
```go
	for h, value := range shs {
		if !cb(h, value) {
			return nil
		}
	}
```
(Leave the `shs, ok := sa.StatesHashes[a.ByteValue]` lookup and the `if !ok { return nil }` guard above it unchanged.)

- [ ] **Step 2: Build + vet** — `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go build ./... && GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go vet ./core/stateDB/` → build exit 0, vet clean.

- [ ] **Step 3: Commit**
```bash
git add core/stateDB/methods.go
git commit -m "$(printf 'OB-125 DB-M9: simplify ForEachStorage always-true dirty check\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Task 3: DB-M1 — fix the mutate-while-range EIP loop (dormant path)

**Files:**
- Modify: `core/evm/interpreter.go` (the `for i, eip := range cfg.ExtraEips` loop in `NewEVMInterpreter`)

**Interfaces:**
- Consumes (existing): `cfg.ExtraEips []int`, `cfg.JumpTable`, `EnableEIP(eip int, jt *JumpTable) error`.
- Note: `ExtraEips` is always `[]int{}` on this chain (`blocks/evaluate.go`), so the loop never executes — this is a correctness/robustness fix with no live behavior change; verified by build + vet + inspection.

- [ ] **Step 1: Replace the loop** — in `core/evm/interpreter.go`, replace:
```go
		for i, eip := range cfg.ExtraEips {
			copy := *cfg.JumpTable
			if err := EnableEIP(eip, &copy); err != nil {
				// Disable it, so caller can check if it's activated or not
				cfg.ExtraEips = append(cfg.ExtraEips[:i], cfg.ExtraEips[i+1:]...)
				fmt.Printf("EIP activation failed eip %v error %v", eip, err)
			}
			cfg.JumpTable = &copy
		}
```
with (build a filtered list of successfully-enabled EIPs instead of mutating the ranged slice; also drops the `copy`-shadows-builtin name):
```go
		// DB-M1: build the set of successfully-enabled EIPs without mutating the
		// slice being ranged over (the old append(...[:i], ...[i+1:]) corrupted
		// subsequent iterations). Only a successfully-enabled EIP applies its
		// jump-table change and stays in cfg.ExtraEips.
		enabled := make([]int, 0, len(cfg.ExtraEips))
		for _, eip := range cfg.ExtraEips {
			jt := *cfg.JumpTable
			if err := EnableEIP(eip, &jt); err != nil {
				fmt.Printf("EIP activation failed eip %v error %v", eip, err)
				continue
			}
			cfg.JumpTable = &jt
			enabled = append(enabled, eip)
		}
		cfg.ExtraEips = enabled
```

- [ ] **Step 2: Build + vet** — `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go build ./... && GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go vet ./core/evm/` → build exit 0, vet clean.

- [ ] **Step 3: Commit**
```bash
git add core/evm/interpreter.go
git commit -m "$(printf 'OB-125 DB-M1: build filtered EIP list instead of mutating ExtraEips while ranging\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Task 4: DB-M10 — MODEXP operand-length ceiling `(CONSENSUS)`

**Files:**
- Modify: `core/evm/contracts.go` (`bigModExp.Run`; add const + error)
- Test: `core/evm/contracts_modexp_test.go` (new)

**Interfaces:**
- Produces: const `MaxModExpLen = 1024`; `var ErrModExpOperandTooLarge`.
- Consumes (existing): `bigModExp.Run(input []byte) ([]byte, error)`, `getData`, `common.LeftPadBytes`. `errors`/`math/big`/`common` already imported.

- [ ] **Step 1: Write the failing tests** — create `core/evm/contracts_modexp_test.go`:
```go
package vm

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/wonabru/qwid-node/common"
)

// modexpInput builds the MODEXP precompile input: three 32-byte big-endian
// lengths followed by base||exp||mod.
func modexpInput(baseLen, expLen, modLen uint64, base, exp, mod []byte) []byte {
	var b []byte
	b = append(b, common.LeftPadBytes(new(big.Int).SetUint64(baseLen).Bytes(), 32)...)
	b = append(b, common.LeftPadBytes(new(big.Int).SetUint64(expLen).Bytes(), 32)...)
	b = append(b, common.LeftPadBytes(new(big.Int).SetUint64(modLen).Bytes(), 32)...)
	b = append(b, base...)
	b = append(b, exp...)
	b = append(b, mod...)
	return b
}

func TestBigModExpRejectsOversized(t *testing.T) {
	// modLen just over the ceiling; base/exp small. No operands needed — the
	// length check must fire before any operand load.
	in := modexpInput(1, 1, MaxModExpLen+1, nil, nil, nil)
	if _, err := (&bigModExp{}).Run(in); err != ErrModExpOperandTooLarge {
		t.Fatalf("oversized modLen: err = %v, want ErrModExpOperandTooLarge", err)
	}
}

func TestBigModExpSmallStillWorks(t *testing.T) {
	// 3^2 mod 5 = 4
	in := modexpInput(1, 1, 1, []byte{0x03}, []byte{0x02}, []byte{0x05})
	out, err := (&bigModExp{}).Run(in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(out, []byte{0x04}) {
		t.Fatalf("3^2 mod 5: got %v, want [4]", out)
	}
}
```

- [ ] **Step 2: Run to verify it fails** — `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./core/evm/ -run 'TestBigModExp' -v` → FAIL to compile (`MaxModExpLen`/`ErrModExpOperandTooLarge` undefined).

- [ ] **Step 3: Add the const + error** — in `core/evm/contracts.go`, add (package level, e.g. near the other precompile declarations):
```go
// MaxModExpLen bounds each MODEXP operand length. On this chain gas is not
// charged (DB-C4), so the EIP-2565 gas formula does not bound operand size;
// this explicit ceiling prevents an OOM/DoS from attacker-controlled lengths.
// 1024 bytes = 8192-bit operands, far above any realistic crypto (RSA-4096 is
// 512 bytes), so no legitimate contract is affected. DB-M10.
const MaxModExpLen = 1024

var ErrModExpOperandTooLarge = errors.New("modexp operand length exceeds maximum")
```

- [ ] **Step 4: Enforce the ceiling in `Run`** — in `bigModExp.Run`, immediately AFTER the `baseLen`/`expLen`/`modLen` are read and BEFORE the `if len(input) > 96` slicing, insert:
```go
	if baseLen > MaxModExpLen || expLen > MaxModExpLen || modLen > MaxModExpLen {
		return nil, ErrModExpOperandTooLarge // DB-M10: bound operand size (gas does not bind on this chain — DB-C4)
	}
```

- [ ] **Step 5: Run + build** — `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./core/evm/ -run 'TestBigModExp' -v && GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go build ./...` → both tests PASS, build exit 0.

- [ ] **Step 6: Commit** (note the `(CONSENSUS)` label)
```bash
git add core/evm/contracts.go core/evm/contracts_modexp_test.go
git commit -m "$(printf 'OB-125 (CONSENSUS) DB-M10: cap MODEXP operand length (MaxModExpLen=1024)\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Final verification
- [ ] `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go build ./...` → exit 0.
- [ ] `GOROOT=/home/wonabru/sdk/go1.24.0 /home/wonabru/sdk/go1.24.0/bin/go test ./core/evm/ ./core/stateDB/` → PASS (new tests green; pre-existing tests unaffected).
- [ ] Update `SECURITY_AUDIT.md` reconciliation: move **DB-M1, DB-M3, DB-M4, DB-M9, DB-M10** from OPEN to FIXED; Medium FIXED +5, OPEN −5; note DB-M10 is `(CONSENSUS)` with the real bound deferred to gas economics (DB-C4). (Controller handles this doc edit after the final review.)

## Deferred (not in this plan)
- Real gas economics (DB-C4) — the principled MODEXP/EVM resource bound.
- Wallet mediums (cluster C: CW-M2/M3).
- Remaining deferred-by-design partials.

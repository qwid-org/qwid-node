# Security Remediation Design

**Date:** 2026-07-02
**Branch:** `security-fixes`
**Source:** `SECURITY_AUDIT.md` (155 verified findings after re-verification pass)

## Goal

Fix all verified findings from the security audit, in strict audit order (CW → AC → NP → WH → DB), one finding at a time.

## Working method

- All work on branch `security-fixes`; `main` untouched until merge.
- Strict audit order. Per finding: minimal correct fix → build → run/extend package test.
- Build uses `GOROOT=/home/wonabru/sdk/go1.24.0` (avoids the local go1.25.6/go1.24.0 toolchain mismatch). CGO packages (RocksDB/liboqs) cannot build in this environment; pure-Go packages can.
- Commit in section-sized batches (one commit per audit section), messages use `OB-xx` convention.

## Special handling (loud heads-up at each)

1. **Consensus-affecting fixes** (AC-C2, AC-C3, AC-C4, AC-H5, AC-H7, AC-M9): change block validation → nodes running the fix hard-fork from nodes that don't. Implement correct behavior, flag each as fork-inducing, defer activation decision to maintainer.
2. **EVM cluster** (DB-C1..C6, DB-H*): real sub-project. Write a short sub-spec before implementing (StateDB balances, value transfer, ecrecover, logs, refunds, access lists).
3. **Wallet crypto migration** (CW-C1/C2/C3): AES-CTR→GCM, per-encryption IV/nonce, Argon2id KDF. Changes on-disk wallet format → provide backward-compatible read + re-encrypt on load so existing wallets keep working.

## Scope notes

- Audit Section 6 (test-coverage assessment) is not fixable findings; new tests are folded into each section's work.
- Findings removed during re-verification (AC-H4, NP-H1, WH-M7) are out of scope — already correct.

## Progress

Tracked per section in commit history and status updates. Not "done" until the section builds and tests pass.

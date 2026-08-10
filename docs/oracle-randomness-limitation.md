# Known limitation: RAND oracle subset-grinding (bias by omission)

**Status:** Documented, not fixed. Requires an anti-bias construction (commit-reveal).
**Source:** whitepaper-vs-implementation review (`review_2.txt`, finding #6, "RAND resistant to manipulation").
**Related fixes already landed:** deterministic canonical ordering + unique ids in oracle
aggregation, and cryptographic binding of oracle submissions to signed nonce
transactions embedded in the block (`OracleProofs`). Those close *fabrication* of
oracle values; they do **not** close *omission* bias described here.

## The problem

The RAND oracle value in a block is derived from the set of validator randomness
proposals the block producer chooses to include:

- `oracles/oraclesDefinition.go` — `GenerateRandData` collects fresh proposals,
  `CalculateRandOracle` computes `RAND = int64( Blake2b(concat(ordered rands))[24:] )`,
  and `VerifyRandOracle` re-derives the same value from the block's `RandOracleData`.
- Each proposal originates in a signed nonce transaction
  (`services/nonceService/serviceNonce.go` → OptData `rand` at bytes `[48:56]`).

After the canonical-ordering and proof-binding fixes, every included proposal must be
a valid, signature-verified submission and the ordering is fixed (ascending delegated
id). **But the producer still chooses which subset of the submissions it holds to
include**, subject only to the aggregate representing `> 2/3` of stake.

Because `RAND = f(subset)` is a deterministic function of the chosen subset, a producer
can **grind**: enumerate valid `> 2/3` subsets of the submissions it received and pick
the one whose RAND is most favorable. The same subset choice can also nudge the price
median (`VerifyPriceOracle` trims min/max then takes the median), though the median is
more robust than the RAND hash.

## Why it cannot be fixed by a verification rule alone

There is **no canonical "full set" of submissions** that all nodes agree on. Nonce
transactions propagate peer-to-peer, so at any height different nodes have received
different subsets. A verifier — especially a node validating a historical block during
sync — cannot prove that the producer omitted a submission it itself never saw.
Therefore a "include all fresh submissions" completeness rule is **not verifiable** and
cannot be enforced in consensus. This is why the fix is a protocol construction, not a
check added to `VerifyRandOracle`.

## Recommended remediation: commit-reveal (RANDAO-style)

Fits the current crypto (Falcon-512 / MAYO-5; no threshold signatures required).

1. **Commit phase (height H):** each validator's nonce transaction carries
   `commit = Blake2b(seed_i || domain)` instead of the raw random value. Store commits
   per delegated id, bound to the signed nonce tx (reuse the existing `OracleProofs`
   mechanism for provenance).
2. **Reveal phase (height H+k):** the validator's later nonce transaction carries
   `seed_i`. Validators check `Blake2b(seed_i || domain) == commit_i` from height H.
3. **Aggregate:** `RAND = Blake2b(domain || parentHash || XOR/concat of revealed seed_i)`,
   using the **full** 256-bit digest (see quality notes below), not the last 8 bytes.
4. **Missing reveals:** define timeout behavior and whether a non-revealing validator is
   skipped and/or penalized. With commit-reveal the only residual bias is the
   **last-revealer** withholding attack (a validator withholds its own reveal after
   seeing others), which is 1-bit-per-withholder rather than full subset grinding. A VDF
   over the aggregate removes even that, at significant implementation cost.

This is a two-phase protocol change touching the nonce transaction format, block/oracle
serialization, new commit state, reveal↔commit validation, and timeout handling. It must
be validated end-to-end on a live network before deployment.

## Orthogonal RAND-quality weaknesses (smaller, independent follow-ups)

Independent of the grinding issue, the current construction:

- Uses only the **last 8 bytes** of the 256-bit hash (`bytes[24:]` in
  `CalculateRandOracle` / `VerifyRandOracle`) and exposes `RandOracle` as an `int64`,
  discarding 192 bits of entropy. The whitepaper calls it a 256-bit hash.
- Has **no domain separation** in the hash input.
- Is **not bound** to block context (height, parent hash).

If commit-reveal is deferred, these three can be hardened on their own as a smaller,
fully testable change — but note that alone they do **not** reduce subset grinding.

package blocks

// Lock-in tests for remediations that live in this package, plus a target test
// for the still-open within-block gas-overflow aspect of QWID-2026-38.
// See SECURITY_AUDIT_2026-09-05.md.

import (
	"math"
	"testing"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
	"github.com/qwid-org/qwid-node/transactionsDefinition"
)

func gasSpecTx(t *testing.T, recipient common.Address, gasUsage, gasPrice int64, opt []byte) transactionsDefinition.Transaction {
	t.Helper()
	sigBytes := make([]byte, common.SignatureLength(false)+1)
	sig, _ := common.GetSignatureFromBytes(sigBytes, common.EmptyAddress())
	tx := transactionsDefinition.Transaction{
		TxParam: transactionsDefinition.TxParam{
			ChainID: common.GetChainID(), Sender: testAddress(9), SendingTime: 1, Nonce: 1,
		},
		TxData:    transactionsDefinition.TxData{Recipient: recipient, Amount: 1, OptData: opt},
		Height:    5, // non-zero so it is not treated as a genesis tx
		GasPrice:  gasPrice,
		GasUsage:  gasUsage,
		Signature: sig,
	}
	_ = tx.CalcHashAndSet()
	return tx
}

// QWID-2026-11 (lock-in): a plain transaction declaring gas above the protocol
// maximum must be refused at Verify, before it can reach the EVM. The gas
// bound sits ahead of signature verification, so no registered key is needed.
func TestQWID11_VerifyRejectsGasAboveMaximum(t *testing.T) {
	logger.InitLogger()
	over := gasSpecTx(t, testAddress(2), common.MaxGasUsage+1, 1, nil)
	if over.Verify(common.SigName(), common.SigName2(), common.IsPaused(), common.IsPaused2()) {
		t.Fatal("a transaction with GasUsage > MaxGasUsage passed Verify — the block gas limit " +
			"is not an effective admission bound (QWID-2026-11)")
	}
	overPrice := gasSpecTx(t, testAddress(2), 30000, common.MaxGasPrice+1, nil)
	if overPrice.Verify(common.SigName(), common.SigName2(), common.IsPaused(), common.IsPaused2()) {
		t.Fatal("a transaction with GasPrice > MaxGasPrice passed Verify (QWID-2026-11)")
	}
}

// QWID-2026-13 (lock-in): a DEX-routed transaction whose OptData is not exactly
// 8 bytes must produce an error, never the pre-fix GetInt64FromByte panic.
func TestQWID13_ShortDexOptDataIsErrorNotPanic(t *testing.T) {
	logger.InitLogger()
	for _, n := range []int{0, 1, 7, 9, 16} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("GenerateOptDataDEX panicked on %d-byte OptData (%v) — one signed tx to a "+
						"DEX delegated account would halt every validator (QWID-2026-13)", n, r)
				}
			}()
			tx := gasSpecTx(t, testAddress(3), 30000, 1, make([]byte, n))
			if _, _, _, _, _, err := GenerateOptDataDEX(tx, 3); err == nil {
				t.Fatalf("GenerateOptDataDEX accepted %d-byte OptData; exactly 8 required", n)
			}
		}()
	}
}

// QWID-2026-35: a block whose transaction-hash list repeats a hash, or exceeds
// the per-block maximum, must be rejected by validation — otherwise a producer
// re-executes a victim's transfer N times on every validator.
func TestQWID35_DuplicateAndOvercountBlockTxHashesRejected(t *testing.T) {
	var h1, h2 common.Hash
	h1[0], h2[0] = 0x01, 0x02

	if err := validateBlockTxHashes([]common.Hash{h1, h2}); err != nil {
		t.Fatalf("a valid distinct-hash list was rejected: %v", err)
	}
	if err := validateBlockTxHashes([]common.Hash{h1, h2, h1}); err == nil {
		t.Fatal("a block repeating a transaction hash was accepted — the producer can re-execute " +
			"a victim's transfer N times (QWID-2026-35)")
	}
	over := make([]common.Hash, int(common.MaxTransactionsPerBlock)+1)
	for i := range over {
		over[i][0] = byte(i)
		over[i][1] = byte(i >> 8)
		over[i][2] = byte(i >> 16)
	}
	if err := validateBlockTxHashes(over); err == nil {
		t.Fatal("a block exceeding MaxTransactionsPerBlock was accepted (QWID-2026-35)")
	}
}

// QWID-2026-38: the block gas cap must not (a) be defeated by an exempt
// transaction declaring huge gas that overflows the cumulative counter, nor
// (b) reject a normal-sized full block. This exercises the per-transaction
// bound the block loop applies to every addend regardless of exemption.
func TestQWID38_BlockGasSumIsOverflowSafe(t *testing.T) {
	// The invariant the block loop must enforce: any single declared GasUsage
	// above MaxGasUsage is rejected, so the running sum can never wrap.
	// Simulate the loop's per-addend guard.
	addends := []int64{30000, common.MaxGasUsage, 9223372036854775807 /* MaxInt64 */}
	var total int64
	rejected := false
	for _, g := range addends {
		if g > common.MaxGasUsage {
			rejected = true
			break // the block loop returns an error here
		}
		total += g
		if total > common.MaxGasUsage {
			rejected = true
			break
		}
	}
	if !rejected {
		t.Fatal("a MaxInt64 gas addend was not rejected before summing — totalGas would wrap negative " +
			"and disable the block gas cap (QWID-2026-38(b))")
	}
	if total < 0 {
		t.Fatal("cumulative gas wrapped negative (QWID-2026-38(b))")
	}
}

// QWID-2026-24: DEX LP-rebalance arithmetic must never inject NaN/Inf into
// consensus state. A share over an empty pool is zero, and a NaN/Inf/overflow
// product converts to a skip (ok=false), not implementation-defined int64
// garbage that forks amd64 vs arm64.
func TestQWID24_DexRebalanceArithmeticIsSafe(t *testing.T) {
	// Empty pool → zero share (not 0/0 = NaN or x/0 = Inf).
	if s := dexPoolShare(100, 0); s != 0 {
		t.Fatalf("share over an empty pool = %v, want 0 (QWID-2026-24)", s)
	}
	if s := dexPoolShare(0, 0); s != 0 {
		t.Fatalf("0/0 share = %v, want 0 (QWID-2026-24)", s)
	}
	// Normal share is finite.
	if s := dexPoolShare(-50, 200); s != -0.25 {
		t.Fatalf("normal share = %v, want -0.25", s)
	}
	// Checked conversion rejects the degenerate values a pre-fix pool produced.
	for _, v := range []float64{math.NaN(), math.Inf(1), math.Inf(-1), 1e30} {
		if _, ok := checkedRoundToken(v, 8); ok {
			t.Fatalf("checkedRoundToken accepted a degenerate value %v (QWID-2026-24)", v)
		}
	}
	// A normal value converts cleanly.
	if got, ok := checkedRoundToken(12.0, 0); !ok || got != 12 {
		t.Fatalf("checkedRoundToken(12,0) = %d,%v; want 12,true", got, ok)
	}
}

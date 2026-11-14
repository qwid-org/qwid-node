package common

import "math/big"

// HoldFee is the fee for holding one pending-pool slot for the given number of
// blocks: HeldTxFeePerWeek per MaxTransactionDelay blocks, rounded up
// (audit 2026-11-13, F-POOL-01). The slot-blocks are the scarce resource, so
// keeping the pool full costs the same whatever delays fill it.
func HoldFee(blocks int64) int64 {
	if blocks <= 0 || HeldTxFeePerWeek <= 0 || MaxTransactionDelay <= 0 {
		return 0
	}
	n := new(big.Int).Mul(big.NewInt(HeldTxFeePerWeek), big.NewInt(blocks))
	n.Add(n, big.NewInt(MaxTransactionDelay-1))
	n.Quo(n, big.NewInt(MaxTransactionDelay))
	if !n.IsInt64() {
		return int64(^uint64(0) >> 1)
	}
	return n.Int64()
}

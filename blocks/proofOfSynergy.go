package blocks

import (
	"github.com/qwid-org/qwid-node/common"
	"math/big"
)

// validProof reports whether a lottery ticket passes the difficulty: the
// 128-bit AND of its halves, num, satisfies log2(num) <= 128 - (difficulty/10)/10.
// It is decided in integers - num^10 <= 2^(1280 - difficulty/10) - where the
// float log2 it replaces could round differently across architectures at the
// threshold (audit 2026-11-12 F-CONS-04).
func validProof(hash common.Hash, difficulty int32) bool {
	num := lotteryValue(hash)
	if num.Sign() == 0 {
		return true
	}
	e := 1280 - int64(difficulty/10)
	if e < 0 {
		return false
	}
	lhs := new(big.Int).Exp(num, big.NewInt(10), nil)
	return lhs.Cmp(new(big.Int).Lsh(big.NewInt(1), uint(e))) <= 0
}

func minimalHashProof(difficulty int32) float64 {
	hashProof := 128.0 - float64(difficulty/10)/float64(common.DifficultyMultiplier)
	return hashProof
}

// ValidDifficulty reports whether newDifficulty is exactly the value derived
// from the parent difficulty and the two committed block timestamps. Producers
// and validators derive difficulty the same way, so a block that declares any
// other difficulty is rejected. Without this check a producer could declare an
// arbitrarily low difficulty and weaken proof-of-synergy (consensus-security).
func ValidDifficulty(newDifficulty, lastDifficulty int32, lastTimeStamp, newTimeStamp int64) bool {
	return newDifficulty == AdjustDifficulty(lastDifficulty, newTimeStamp-lastTimeStamp)
}

func AdjustDifficulty(lastDifficulty int32, interval int64) int32 {
	if float64(interval) > float64(common.BlockTimeInterval)*1.33 {
		lastDifficulty -= int32(common.DifficultyChange)
	} else if float64(interval) < float64(common.BlockTimeInterval)/1.33 {
		lastDifficulty += int32(common.DifficultyChange)
	}
	if lastDifficulty < 1 {
		lastDifficulty = 1
	}
	if lastDifficulty > 0xff00 {
		lastDifficulty = 0xff00
	}
	return lastDifficulty
}

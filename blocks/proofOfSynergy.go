package blocks

import (
	"github.com/qwid-org/qwid-node/common"
	"math"
	"math/big"
)

func CheckProofOfSynergy(block BaseBlock) bool {
	head := block.BaseHeader
	h := block.BlockHeaderHash
	return validProof(h, head.Difficulty)
}

func validProof(hash common.Hash, difficulty int32) bool {
	hh := hash.GetBytes()
	byteAnd := make([]byte, 16)
	for i := 0; i < 16; i++ {
		byteAnd[i] = hh[i] & hh[i+16]
	}
	num := new(big.Int).SetBytes(byteAnd)
	f, _ := new(big.Float).SetInt(num).Float64()
	proof := math.Log2(f)
	minimalProof := minimalHashProof(difficulty)
	return proof <= minimalProof
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

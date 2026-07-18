package blocks

import (
	"testing"

	"github.com/wonabru/qwid-node/common"
	"github.com/wonabru/qwid-node/logger"
	"github.com/stretchr/testify/assert"
)

func TestMinimalHashProof(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	t.Run("difficulty zero gives max proof", func(t *testing.T) {
		proof := minimalHashProof(0)
		assert.Equal(t, 128.0, proof)
	})

	t.Run("proof decreases as difficulty increases", func(t *testing.T) {
		proof1 := minimalHashProof(10)
		proof2 := minimalHashProof(100)
		assert.Greater(t, proof1, proof2)
	})

	t.Run("proof at max difficulty is less than 128", func(t *testing.T) {
		proof := minimalHashProof(0xff00)
		assert.Less(t, proof, 128.0)
	})

	t.Run("difficulty multiplier affects result", func(t *testing.T) {
		// difficulty/10 / DifficultyMultiplier (10) = difficulty/100
		// hashProof = 128 - difficulty/100
		proof := minimalHashProof(1000)
		expected := 128.0 - float64(1000/10)/float64(common.DifficultyMultiplier)
		assert.Equal(t, expected, proof)
	})
}

func TestAdjustDifficulty(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	t.Run("slow block interval decreases difficulty", func(t *testing.T) {
		// interval > BlockTimeInterval * 1.33 → decrease
		slowInterval := int64(float64(common.BlockTimeInterval)*1.5 + 1)
		result := AdjustDifficulty(100, slowInterval)
		assert.Equal(t, int32(100-int32(common.DifficultyChange)), result)
	})

	t.Run("fast block interval increases difficulty", func(t *testing.T) {
		// interval < BlockTimeInterval / 1.33 → increase
		fastInterval := int64(float64(common.BlockTimeInterval)/2.0 - 1)
		result := AdjustDifficulty(100, fastInterval)
		assert.Equal(t, int32(100+int32(common.DifficultyChange)), result)
	})

	t.Run("normal interval keeps difficulty unchanged", func(t *testing.T) {
		// interval == BlockTimeInterval → no change
		normalInterval := int64(common.BlockTimeInterval)
		result := AdjustDifficulty(100, normalInterval)
		assert.Equal(t, int32(100), result)
	})

	t.Run("difficulty cannot go below 1", func(t *testing.T) {
		result := AdjustDifficulty(1, 999999)
		assert.Equal(t, int32(1), result)
	})

	t.Run("difficulty cannot exceed 0xff00", func(t *testing.T) {
		result := AdjustDifficulty(0xff00, 0)
		assert.Equal(t, int32(0xff00), result)
	})

	t.Run("small difficulty cannot go below 1 after decrease", func(t *testing.T) {
		slowInterval := int64(float64(common.BlockTimeInterval)*2.0 + 1)
		result := AdjustDifficulty(int32(common.DifficultyChange)-1, slowInterval)
		assert.Equal(t, int32(1), result)
	})
}

func TestValidProof(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	t.Run("all-zero hash passes with high difficulty tolerance", func(t *testing.T) {
		// All-zero hash: byteAnd = 0, log2(0) = -Inf, which is <= any threshold
		var h common.Hash
		result := validProof(h, 1)
		assert.True(t, result)
	})

	t.Run("all-ones hash fails with very high difficulty", func(t *testing.T) {
		// All-ones hash gives maximum bit value → high log2 → may fail strict difficulty
		var h common.Hash
		for i := range h {
			h[i] = 0xff
		}
		// With max difficulty, the threshold is very low
		result := validProof(h, 0xff00)
		assert.False(t, result)
	})

	t.Run("higher difficulty is harder to pass", func(t *testing.T) {
		// A hash that passes low difficulty but may fail high difficulty
		var h common.Hash
		h[0] = 0x01
		h[16] = 0x01

		lowDiffResult := validProof(h, 1)
		// difficulty 1 has threshold near 128, almost everything passes
		assert.True(t, lowDiffResult)
	})
}

func TestValidDifficulty(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	const parentDifficulty = int32(1000)
	const parentTime = int64(1_000_000)

	t.Run("declared difficulty matching the expected value is accepted", func(t *testing.T) {
		// normal interval keeps difficulty unchanged
		newTime := parentTime + int64(common.BlockTimeInterval)
		assert.True(t, ValidDifficulty(parentDifficulty, parentDifficulty, parentTime, newTime))
	})

	t.Run("declared difficulty lower than expected is rejected", func(t *testing.T) {
		// The attack the review describes: a producer declares an arbitrarily
		// low difficulty for a normal-interval block to weaken proof-of-work.
		newTime := parentTime + int64(common.BlockTimeInterval)
		forged := parentDifficulty - 10*int32(common.DifficultyChange)
		assert.False(t, ValidDifficulty(forged, parentDifficulty, parentTime, newTime))
	})

	t.Run("correctly decreased difficulty for a slow block is accepted", func(t *testing.T) {
		newTime := parentTime + int64(float64(common.BlockTimeInterval)*1.5+1)
		expected := parentDifficulty - int32(common.DifficultyChange)
		assert.True(t, ValidDifficulty(expected, parentDifficulty, parentTime, newTime))
	})

	t.Run("stale decreased difficulty for a fast block is rejected", func(t *testing.T) {
		// Fast block must increase difficulty; declaring a decreased value fails.
		newTime := parentTime + int64(float64(common.BlockTimeInterval)/2.0-1)
		forged := parentDifficulty - int32(common.DifficultyChange)
		assert.False(t, ValidDifficulty(forged, parentDifficulty, parentTime, newTime))
	})
}

func TestCheckProofOfSynergy(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	t.Run("zero hash with low difficulty passes", func(t *testing.T) {
		bb := BaseBlock{
			BaseHeader: BaseHeader{
				Difficulty: 1,
			},
			BlockHeaderHash: common.Hash{},
		}
		result := CheckProofOfSynergy(bb)
		assert.True(t, result)
	})

	t.Run("all-ones hash with max difficulty fails", func(t *testing.T) {
		var h common.Hash
		for i := range h {
			h[i] = 0xff
		}
		bb := BaseBlock{
			BaseHeader: BaseHeader{
				Difficulty: 0xff00,
			},
			BlockHeaderHash: h,
		}
		result := CheckProofOfSynergy(bb)
		assert.False(t, result)
	})
}

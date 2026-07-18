package blocks

import (
	"testing"

	"github.com/wonabru/qwid-node/common"
	"github.com/wonabru/qwid-node/logger"
	"github.com/stretchr/testify/assert"
)

// buildMinimalBaseHeader creates a BaseHeader with minimal valid data for serialization tests.
func buildMinimalBaseHeader() BaseHeader {
	sig, _ := common.GetSignatureFromBytes([]byte{0, 1, 2, 3}, common.EmptyAddress())
	return BaseHeader{
		PreviousHash:     common.Hash{},
		Difficulty:       100,
		Height:           42,
		DelegatedAccount: common.EmptyAddress(),
		OperatorAccount:  common.EmptyAddress(),
		RootMerkleTree:   common.Hash{},
		Encryption1:      []byte{},
		Encryption2:      []byte{},
		SignatureMessage: []byte{1, 2, 3},
		Signature:        sig,
	}
}

func TestBaseBlockOracleProofsRoundTrip(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	orig := BaseBlock{
		BaseHeader:       buildMinimalBaseHeader(),
		BlockHeaderHash:  common.Hash{},
		BlockTimeStamp:   1000,
		RewardPercentage: 200,
		Supply:           123,
		PriceOracle:      100000000,
		RandOracle:       777,
		PriceOracleData:  []byte{2, 0, 0, 0, 0, 0, 0, 0, 10},
		RandOracleData:   []byte{5, 0, 0, 0, 0, 0, 0, 0, 20},
		OracleProofs:     [][]byte{{1, 2, 3}, {}, {9, 9, 9, 9}},
	}

	// A trailing marker stands in for the bytes Block.GetFromBytes consumes after
	// the BaseBlock, so we can confirm GetFromBytes leaves exactly the remainder.
	encoded := orig.GetBytes()
	trailer := []byte{0xAA, 0xBB}
	encoded = append(encoded, trailer...)

	var decoded BaseBlock
	rest, err := decoded.GetFromBytes(encoded)
	assert.NoError(t, err)
	assert.Equal(t, orig.OracleProofs, decoded.OracleProofs)
	assert.Equal(t, orig.PriceOracleData, decoded.PriceOracleData)
	assert.Equal(t, orig.RandOracleData, decoded.RandOracleData)
	assert.Equal(t, trailer, rest, "GetFromBytes must consume exactly the BaseBlock bytes")
}

func TestBaseHeaderGetBytesWithoutSignature(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	t.Run("returns non-empty bytes", func(t *testing.T) {
		bh := buildMinimalBaseHeader()
		b := bh.GetBytesWithoutSignature()
		assert.NotEmpty(t, b)
	})

	t.Run("bytes start with previous hash", func(t *testing.T) {
		bh := buildMinimalBaseHeader()
		var prevHash common.Hash
		prevHash[0] = 0xAB
		bh.PreviousHash = prevHash
		b := bh.GetBytesWithoutSignature()
		assert.Equal(t, byte(0xAB), b[0])
	})

	t.Run("height is encoded at offset 36", func(t *testing.T) {
		bh := buildMinimalBaseHeader()
		bh.Height = 999
		b := bh.GetBytesWithoutSignature()
		decoded := common.GetInt64FromByte(b[36:44])
		assert.Equal(t, int64(999), decoded)
	})

	t.Run("difficulty is encoded at offset 32", func(t *testing.T) {
		bh := buildMinimalBaseHeader()
		bh.Difficulty = 250
		b := bh.GetBytesWithoutSignature()
		decoded := common.GetInt32FromByte(b[32:36])
		assert.Equal(t, int32(250), decoded)
	})

	t.Run("same header produces same bytes", func(t *testing.T) {
		bh := buildMinimalBaseHeader()
		b1 := bh.GetBytesWithoutSignature()
		b2 := bh.GetBytesWithoutSignature()
		assert.Equal(t, b1, b2)
	})

	t.Run("different height produces different bytes", func(t *testing.T) {
		bh1 := buildMinimalBaseHeader()
		bh2 := buildMinimalBaseHeader()
		bh1.Height = 1
		bh2.Height = 2
		assert.NotEqual(t, bh1.GetBytesWithoutSignature(), bh2.GetBytesWithoutSignature())
	})
}

func TestBaseHeaderGetBytesRoundtrip(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	t.Run("roundtrip with minimal header", func(t *testing.T) {
		original := buildMinimalBaseHeader()
		b := original.GetBytes()
		assert.NotEmpty(t, b)

		var restored BaseHeader
		remaining, err := restored.GetFromBytes(b)
		assert.NoError(t, err)
		assert.Empty(t, remaining)
		assert.Equal(t, original.Difficulty, restored.Difficulty)
		assert.Equal(t, original.Height, restored.Height)
		assert.Equal(t, original.PreviousHash, restored.PreviousHash)
		assert.Equal(t, original.RootMerkleTree, restored.RootMerkleTree)
		assert.Equal(t, original.SignatureMessage, restored.SignatureMessage)
	})

	t.Run("roundtrip preserves encryption fields", func(t *testing.T) {
		original := buildMinimalBaseHeader()
		original.Encryption1 = []byte{0x01, 0x02, 0x03}
		original.Encryption2 = []byte{0x04, 0x05}
		b := original.GetBytes()

		var restored BaseHeader
		_, err := restored.GetFromBytes(b)
		assert.NoError(t, err)
		assert.Equal(t, original.Encryption1, restored.Encryption1)
		assert.Equal(t, original.Encryption2, restored.Encryption2)
	})

	t.Run("roundtrip with extra trailing bytes returns them", func(t *testing.T) {
		original := buildMinimalBaseHeader()
		extra := []byte{0xDE, 0xAD, 0xBE, 0xEF}
		b := append(original.GetBytes(), extra...)

		var restored BaseHeader
		remaining, err := restored.GetFromBytes(b)
		assert.NoError(t, err)
		assert.Equal(t, extra, remaining)
	})

	t.Run("too short data returns error", func(t *testing.T) {
		var bh BaseHeader
		_, err := bh.GetFromBytes([]byte{1, 2, 3})
		assert.Error(t, err)
	})
}

func TestBaseHeaderCalcHash(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	t.Run("returns non-zero hash", func(t *testing.T) {
		bh := buildMinimalBaseHeader()
		h, err := bh.CalcHash()
		assert.NoError(t, err)
		assert.NotEqual(t, common.Hash{}, h)
	})

	t.Run("same header produces same hash", func(t *testing.T) {
		bh := buildMinimalBaseHeader()
		h1, err1 := bh.CalcHash()
		h2, err2 := bh.CalcHash()
		assert.NoError(t, err1)
		assert.NoError(t, err2)
		assert.Equal(t, h1, h2)
	})

	t.Run("different height produces different hash", func(t *testing.T) {
		bh1 := buildMinimalBaseHeader()
		bh2 := buildMinimalBaseHeader()
		bh1.Height = 1
		bh2.Height = 2
		h1, _ := bh1.CalcHash()
		h2, _ := bh2.CalcHash()
		assert.NotEqual(t, h1, h2)
	})
}

func TestBaseHeaderGetString(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	t.Run("returns non-empty string", func(t *testing.T) {
		bh := buildMinimalBaseHeader()
		s := bh.GetString()
		assert.NotEmpty(t, s)
	})

	t.Run("contains height", func(t *testing.T) {
		bh := buildMinimalBaseHeader()
		bh.Height = 42
		s := bh.GetString()
		assert.Contains(t, s, "42")
	})

	t.Run("contains difficulty", func(t *testing.T) {
		bh := buildMinimalBaseHeader()
		bh.Difficulty = 100
		s := bh.GetString()
		assert.Contains(t, s, "100")
	})
}

func TestBaseBlockGetBytesRoundtrip(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	buildBaseBlock := func() BaseBlock {
		return BaseBlock{
			BaseHeader:       buildMinimalBaseHeader(),
			BlockHeaderHash:  common.Hash{},
			BlockTimeStamp:   1700000000,
			RewardPercentage: 200,
			Supply:           1000000000,
			PriceOracle:      500,
			RandOracle:       12345,
			PriceOracleData:  []byte{},
			RandOracleData:   []byte{},
		}
	}

	t.Run("roundtrip basic block", func(t *testing.T) {
		original := buildBaseBlock()
		b := original.GetBytes()
		assert.NotEmpty(t, b)

		var restored BaseBlock
		remaining, err := restored.GetFromBytes(b)
		assert.NoError(t, err)
		assert.Empty(t, remaining)
		assert.Equal(t, original.BlockTimeStamp, restored.BlockTimeStamp)
		assert.Equal(t, original.RewardPercentage, restored.RewardPercentage)
		assert.Equal(t, original.Supply, restored.Supply)
		assert.Equal(t, original.PriceOracle, restored.PriceOracle)
		assert.Equal(t, original.RandOracle, restored.RandOracle)
	})

	t.Run("roundtrip with oracle data", func(t *testing.T) {
		original := buildBaseBlock()
		original.PriceOracleData = []byte{0x01, 0x02, 0x03, 0x04}
		original.RandOracleData = []byte{0x05, 0x06}
		b := original.GetBytes()

		var restored BaseBlock
		_, err := restored.GetFromBytes(b)
		assert.NoError(t, err)
		assert.Equal(t, original.PriceOracleData, restored.PriceOracleData)
		assert.Equal(t, original.RandOracleData, restored.RandOracleData)
	})

	t.Run("too short data returns error", func(t *testing.T) {
		var bb BaseBlock
		_, err := bb.GetFromBytes([]byte{1, 2, 3})
		assert.Error(t, err)
	})

	t.Run("roundtrip preserves header fields", func(t *testing.T) {
		original := buildBaseBlock()
		original.BaseHeader.Height = 777
		original.BaseHeader.Difficulty = 55
		b := original.GetBytes()

		var restored BaseBlock
		_, err := restored.GetFromBytes(b)
		assert.NoError(t, err)
		assert.Equal(t, int64(777), restored.BaseHeader.Height)
		assert.Equal(t, int32(55), restored.BaseHeader.Difficulty)
	})
}

func TestBaseBlockGetString(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	t.Run("returns non-empty string", func(t *testing.T) {
		bb := BaseBlock{
			BaseHeader:       buildMinimalBaseHeader(),
			BlockTimeStamp:   12345,
			RewardPercentage: 100,
			Supply:           500000,
		}
		s := bb.GetString()
		assert.NotEmpty(t, s)
	})

	t.Run("contains supply", func(t *testing.T) {
		bb := BaseBlock{
			BaseHeader: buildMinimalBaseHeader(),
			Supply:     999888777,
		}
		s := bb.GetString()
		assert.Contains(t, s, "999888777")
	})
}

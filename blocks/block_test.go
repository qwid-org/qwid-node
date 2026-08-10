package blocks

import (
	"bytes"
	"testing"

	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/core/stateDB"
	"github.com/qwid-org/qwid-node/logger"
	"github.com/stretchr/testify/assert"
)

func buildMinimalBlock() Block {
	return Block{
		BaseBlock: BaseBlock{
			BaseHeader:       buildMinimalBaseHeader(),
			BlockHeaderHash:  common.Hash{},
			BlockTimeStamp:   1700000000,
			RewardPercentage: 200,
			Supply:           1000000000,
			PriceOracle:      0,
			RandOracle:       0,
			PriceOracleData:  []byte{},
			RandOracleData:   []byte{},
		},
		TransactionsHashes: []common.Hash{},
		BlockHash:          common.Hash{},
		BlockFee:           0,
	}
}

func TestBlockGetters(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	t.Run("GetBaseBlock returns base block", func(t *testing.T) {
		bl := buildMinimalBlock()
		bl.BaseBlock.Supply = 123456
		bb := bl.GetBaseBlock()
		assert.Equal(t, int64(123456), bb.Supply)
	})

	t.Run("GetBlockHeaderHash", func(t *testing.T) {
		bl := buildMinimalBlock()
		var h common.Hash
		h[0] = 0xAB
		bl.BaseBlock.BlockHeaderHash = h
		assert.Equal(t, h, bl.GetBlockHeaderHash())
	})

	t.Run("GetBlockTimeStamp", func(t *testing.T) {
		bl := buildMinimalBlock()
		bl.BaseBlock.BlockTimeStamp = 9999999
		assert.Equal(t, int64(9999999), bl.GetBlockTimeStamp())
	})

	t.Run("GetBlockSupply", func(t *testing.T) {
		bl := buildMinimalBlock()
		bl.BaseBlock.Supply = 5000000
		assert.Equal(t, int64(5000000), bl.GetBlockSupply())
	})

	t.Run("GetRewardPercentage", func(t *testing.T) {
		bl := buildMinimalBlock()
		bl.BaseBlock.RewardPercentage = 300
		assert.Equal(t, int16(300), bl.GetRewardPercentage())
	})

	t.Run("GetHeader returns base header", func(t *testing.T) {
		bl := buildMinimalBlock()
		bl.BaseBlock.BaseHeader.Height = 42
		h := bl.GetHeader()
		assert.Equal(t, int64(42), h.Height)
	})

	t.Run("GetBlockTransactionsHashes returns slice", func(t *testing.T) {
		bl := buildMinimalBlock()
		var h1, h2 common.Hash
		h1[0] = 0x01
		h2[0] = 0x02
		bl.TransactionsHashes = []common.Hash{h1, h2}
		hashes := bl.GetBlockTransactionsHashes()
		assert.Equal(t, 2, len(hashes))
		assert.Equal(t, h1, hashes[0])
		assert.Equal(t, h2, hashes[1])
	})

	t.Run("GetBlockHash", func(t *testing.T) {
		bl := buildMinimalBlock()
		var h common.Hash
		h[0] = 0xFF
		bl.BlockHash = h
		assert.Equal(t, h, bl.GetBlockHash())
	})
}

func TestBlockGetString(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	t.Run("returns non-empty string", func(t *testing.T) {
		bl := buildMinimalBlock()
		s := bl.GetString()
		assert.NotEmpty(t, s)
	})

	t.Run("contains BlockHash", func(t *testing.T) {
		bl := buildMinimalBlock()
		s := bl.GetString()
		assert.Contains(t, s, "BlockHash")
	})

	t.Run("contains transaction hashes", func(t *testing.T) {
		bl := buildMinimalBlock()
		var h common.Hash
		h[0] = 0xAB
		bl.TransactionsHashes = []common.Hash{h}
		s := bl.GetString()
		assert.Contains(t, s, "TransactionsHashes")
	})

	t.Run("empty transaction list shows empty brackets", func(t *testing.T) {
		bl := buildMinimalBlock()
		s := bl.GetString()
		assert.Contains(t, s, "[]")
	})
}

func TestBlockGetBytesRoundtrip(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	t.Run("roundtrip with empty block", func(t *testing.T) {
		original := buildMinimalBlock()
		b := original.GetBytes()
		assert.NotEmpty(t, b)

		restored, err := Block{}.GetFromBytes(b)
		assert.NoError(t, err)
		assert.Equal(t, original.BlockFee, restored.BlockFee)
		assert.Equal(t, 0, len(restored.TransactionsHashes))
		assert.Equal(t, original.BaseBlock.Supply, restored.BaseBlock.Supply)
		assert.Equal(t, original.BaseBlock.BaseHeader.Height, restored.BaseBlock.BaseHeader.Height)
	})

	t.Run("roundtrip with transaction hashes", func(t *testing.T) {
		original := buildMinimalBlock()
		var h1, h2 common.Hash
		h1[0] = 0x01
		h2[0] = 0x02
		original.TransactionsHashes = []common.Hash{h1, h2}
		original.BlockFee = 12345

		b := original.GetBytes()
		restored, err := Block{}.GetFromBytes(b)
		assert.NoError(t, err)
		assert.Equal(t, 2, len(restored.TransactionsHashes))
		assert.Equal(t, h1, restored.TransactionsHashes[0])
		assert.Equal(t, h2, restored.TransactionsHashes[1])
		assert.Equal(t, int64(12345), restored.BlockFee)
	})

	t.Run("roundtrip preserves block hash", func(t *testing.T) {
		original := buildMinimalBlock()
		var bh common.Hash
		bh[0] = 0xCC
		original.BlockHash = bh

		b := original.GetBytes()
		restored, err := Block{}.GetFromBytes(b)
		assert.NoError(t, err)
		assert.Equal(t, bh, restored.BlockHash)
	})
}

func TestBlockCalcBlockHash(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	t.Run("returns non-zero hash for non-empty block", func(t *testing.T) {
		bl := buildMinimalBlock()
		bl.BaseBlock.BaseHeader.Height = 1
		h, err := bl.CalcBlockHash()
		assert.NoError(t, err)
		assert.NotEqual(t, common.Hash{}, h)
	})

	t.Run("same block produces same hash", func(t *testing.T) {
		bl := buildMinimalBlock()
		h1, err1 := bl.CalcBlockHash()
		h2, err2 := bl.CalcBlockHash()
		assert.NoError(t, err1)
		assert.NoError(t, err2)
		assert.Equal(t, h1, h2)
	})

	t.Run("different blocks produce different hashes", func(t *testing.T) {
		bl1 := buildMinimalBlock()
		bl2 := buildMinimalBlock()
		bl1.BaseBlock.BaseHeader.Height = 1
		bl2.BaseBlock.BaseHeader.Height = 2
		h1, _ := bl1.CalcBlockHash()
		h2, _ := bl2.CalcBlockHash()
		assert.NotEqual(t, h1, h2)
	})

	t.Run("GetBytesForHash returns same as BaseBlock.GetBytes", func(t *testing.T) {
		bl := buildMinimalBlock()
		forHash := bl.GetBytesForHash()
		baseBlockBytes := bl.BaseBlock.GetBytes()
		assert.True(t, bytes.Equal(forHash, baseBlockBytes))
	})
}

func TestIsTokenToRegister(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	t.Run("code with all required selectors is a token", func(t *testing.T) {
		// Combine all required ERC20-like function selectors
		code := make([]byte, 0)
		code = append(code, stateDB.NameFunc...)
		code = append(code, stateDB.BalanceOfFunc...)
		code = append(code, stateDB.TransferFunc...)
		code = append(code, stateDB.SymbolFunc...)
		code = append(code, stateDB.DecimalsFunc...)
		assert.True(t, IsTokenToRegister(code))
	})

	t.Run("empty code is not a token", func(t *testing.T) {
		assert.False(t, IsTokenToRegister([]byte{}))
	})

	t.Run("code missing NameFunc is not a token", func(t *testing.T) {
		code := make([]byte, 0)
		code = append(code, stateDB.BalanceOfFunc...)
		code = append(code, stateDB.TransferFunc...)
		code = append(code, stateDB.SymbolFunc...)
		code = append(code, stateDB.DecimalsFunc...)
		assert.False(t, IsTokenToRegister(code))
	})

	t.Run("code missing BalanceOfFunc is not a token", func(t *testing.T) {
		code := make([]byte, 0)
		code = append(code, stateDB.NameFunc...)
		code = append(code, stateDB.TransferFunc...)
		code = append(code, stateDB.SymbolFunc...)
		code = append(code, stateDB.DecimalsFunc...)
		assert.False(t, IsTokenToRegister(code))
	})

	t.Run("code missing TransferFunc is not a token", func(t *testing.T) {
		code := make([]byte, 0)
		code = append(code, stateDB.NameFunc...)
		code = append(code, stateDB.BalanceOfFunc...)
		code = append(code, stateDB.SymbolFunc...)
		code = append(code, stateDB.DecimalsFunc...)
		assert.False(t, IsTokenToRegister(code))
	})

	t.Run("code missing SymbolFunc is not a token", func(t *testing.T) {
		code := make([]byte, 0)
		code = append(code, stateDB.NameFunc...)
		code = append(code, stateDB.BalanceOfFunc...)
		code = append(code, stateDB.TransferFunc...)
		code = append(code, stateDB.DecimalsFunc...)
		assert.False(t, IsTokenToRegister(code))
	})

	t.Run("code missing DecimalsFunc is not a token", func(t *testing.T) {
		code := make([]byte, 0)
		code = append(code, stateDB.NameFunc...)
		code = append(code, stateDB.BalanceOfFunc...)
		code = append(code, stateDB.TransferFunc...)
		code = append(code, stateDB.SymbolFunc...)
		assert.False(t, IsTokenToRegister(code))
	})

	t.Run("random bytes are not a token", func(t *testing.T) {
		code := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
		assert.False(t, IsTokenToRegister(code))
	})
}

package oracles

import (
	"testing"

	"github.com/wonabru/qwid-node/common"
	"github.com/wonabru/qwid-node/logger"
	"github.com/stretchr/testify/assert"
)

// priceEntry / randEntry build the canonical 17-byte on-block encoding of a
// single oracle submission: 1-byte delegated id, 8-byte height, 8-byte value.
func oracleEntry(id uint8, height, value int64) []byte {
	b := []byte{id}
	b = append(b, common.GetByteInt64(height)...)
	b = append(b, common.GetByteInt64(value)...)
	return b
}

func TestParsePriceDataRejectsNonAscendingIDs(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	data := append(oracleEntry(5, 10, 100), oracleEntry(3, 10, 200)...)
	_, _, _, err := ParsePriceData(data)
	assert.Error(t, err, "price data with descending delegated ids must be rejected")
}

func TestParsePriceDataRejectsDuplicateIDs(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	// A producer must not repeat one delegated id to inflate the represented stake.
	data := append(oracleEntry(5, 10, 100), oracleEntry(5, 10, 200)...)
	_, _, _, err := ParsePriceData(data)
	assert.Error(t, err, "price data with duplicate delegated ids must be rejected")
}

func TestParseRandDataRejectsNonAscendingIDs(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	data := append(oracleEntry(9, 10, 100), oracleEntry(2, 10, 200)...)
	_, _, _, err := ParseRandData(data)
	assert.Error(t, err, "rand data with descending delegated ids must be rejected")
}

func TestParseRandDataRejectsDuplicateIDs(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	data := append(oracleEntry(5, 10, 100), oracleEntry(5, 10, 200)...)
	_, _, _, err := ParseRandData(data)
	assert.Error(t, err, "rand data with duplicate delegated ids must be rejected")
}

func TestParseCanonicalDataIsAccepted(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	data := append(oracleEntry(2, 10, 100), oracleEntry(5, 10, 200)...)
	_, prices, _, err := ParsePriceData(data)
	assert.NoError(t, err, "strictly ascending price data must be accepted")
	assert.Equal(t, []int64{100, 200}, prices)

	_, rands, _, err := ParseRandData(data)
	assert.NoError(t, err, "strictly ascending rand data must be accepted")
	assert.Len(t, rands, 16)
}

func TestGenerateRandDataIsAscendingByID(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	RandOraclesRWMutex.Lock()
	RandOracles = map[uint8]RandOracle{
		7: {Rand: 100, Height: 10, Staked: 1},
		3: {Rand: 200, Height: 10, Staked: 1},
		9: {Rand: 300, Height: 10, Staked: 1},
		1: {Rand: 400, Height: 10, Staked: 1},
	}
	RandOraclesRWMutex.Unlock()

	randData, _, _ := GenerateRandData(int64(10) + common.OraclesHeightDistance)

	var prev int
	for i := 0; i < len(randData); i += 17 {
		id := int(randData[i])
		if i > 0 {
			assert.Greater(t, id, prev, "GenerateRandData must emit strictly ascending delegated ids")
		}
		prev = id
	}
}

func TestGeneratePriceDataIsAscendingByID(t *testing.T) {
	logger.InitLogger()
	defer logger.CloseLogger()

	PriceOraclesRWMutex.Lock()
	PriceOracles = map[uint8]PriceOracle{
		7: {Price: 100, Height: 10, Staked: 1},
		3: {Price: 200, Height: 10, Staked: 1},
		9: {Price: 300, Height: 10, Staked: 1},
		1: {Price: 400, Height: 10, Staked: 1},
	}
	PriceOraclesRWMutex.Unlock()

	priceData, _, _ := GeneratePriceData(int64(10) + common.OraclesHeightDistance)

	var prev int
	for i := 0; i < len(priceData); i += 17 {
		id := int(priceData[i])
		if i > 0 {
			assert.Greater(t, id, prev, "GeneratePriceData must emit strictly ascending delegated ids")
		}
		prev = id
	}
}

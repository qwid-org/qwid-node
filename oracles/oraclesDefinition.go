package oracles

import (
	"errors"
	"fmt"
	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
	"sort"
	"sync"
)

type PriceOracle struct {
	Price  int64 `json:"price"`
	Height int64 `json:"height"`
	Staked int64 `json:"staked"`
}

type RandOracle struct {
	Rand   int64 `json:"rand"`
	Height int64 `json:"height"`
	Staked int64 `json:"staked"`
}

var (
	PriceOracles        = make(map[uint8]PriceOracle)
	PriceOraclesRWMutex sync.RWMutex

	RandOracles        = make(map[uint8]RandOracle)
	RandOraclesRWMutex sync.RWMutex

	// oracleProofs retains the raw signed nonce-transaction bytes per delegated
	// id so a block producer can embed them as provenance proofs for the
	// aggregated oracle values.
	oracleProofs        = make(map[uint8]oracleProof)
	oracleProofsRWMutex sync.RWMutex
)

type oracleProof struct {
	height  int64
	txBytes []byte
}

// SaveOracleProof stores the signed nonce transaction backing a delegated
// account's oracle submission, keeping only the most recent height (mirroring
// SavePriceOracle/SaveRandOracle).
func SaveOracleProof(delegatedAccount common.Address, height int64, txBytes []byte) error {
	id, err := common.GetIDFromDelegatedAccountAddress(delegatedAccount)
	if err != nil {
		return err
	}
	if (id <= 0) || (id >= 256) {
		return fmt.Errorf("delegated account is invalid: %d", id)
	}
	oracleProofsRWMutex.Lock()
	defer oracleProofsRWMutex.Unlock()

	p, exists := oracleProofs[uint8(id)]
	if !exists || p.height <= height {
		cp := make([]byte, len(txBytes))
		copy(cp, txBytes)
		oracleProofs[uint8(id)] = oracleProof{height: height, txBytes: cp}
	}
	return nil
}

// GenerateOracleProofs returns the stored proof transactions for delegated
// accounts whose submission is still fresh at height, in strictly ascending id
// order (matching GeneratePriceData/GenerateRandData).
func GenerateOracleProofs(height int64) [][]byte {
	oracleProofsRWMutex.RLock()
	defer oracleProofsRWMutex.RUnlock()
	ids := make([]uint8, 0, len(oracleProofs))
	for id, p := range oracleProofs {
		if height <= p.height+common.OraclesHeightDistance {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(a, b int) bool { return ids[a] < ids[b] })
	out := make([][]byte, 0, len(ids))
	for _, id := range ids {
		out = append(out, oracleProofs[id].txBytes)
	}
	return out
}

func SavePriceOracle(price int64, height int64, delegatedAccount common.Address, staked int64) error {
	id, err := common.GetIDFromDelegatedAccountAddress(delegatedAccount)
	if err != nil {
		return err
	}

	if (id <= 0) || (id >= 256) {
		return fmt.Errorf("delegated account is invalid: %d", id)
	}
	PriceOraclesRWMutex.Lock()
	defer PriceOraclesRWMutex.Unlock()

	po, exists := PriceOracles[uint8(id)]
	if !exists || po.Height <= height {
		PriceOracles[uint8(id)] = PriceOracle{
			Price:  price,
			Height: height,
			Staked: staked,
		}
	} else {
		return errors.New("invalid height in price oracle")
	}

	return nil
}

func SaveRandOracle(rand int64, height int64, delegatedAccount common.Address, staked int64) error {
	id, err := common.GetIDFromDelegatedAccountAddress(delegatedAccount)
	if err != nil {
		return err
	}

	if (id <= 0) || (id >= 256) {
		return fmt.Errorf("delegated account is invalid: %d", id)
	}
	RandOraclesRWMutex.Lock()
	defer RandOraclesRWMutex.Unlock()

	po, exists := RandOracles[uint8(id)]
	if !exists || po.Height <= height {
		RandOracles[uint8(id)] = RandOracle{
			Rand:   rand,
			Height: height,
			Staked: staked,
		}
	} else {
		return errors.New("invalid height in rand oracle")
	}

	return nil
}

func GeneratePriceData(height int64) ([]byte, []int64, int64) {
	priceData := make([]byte, 0)
	prices := []int64{}
	staked := int64(0)
	PriceOraclesRWMutex.RLock()
	defer PriceOraclesRWMutex.RUnlock()
	ids := make([]uint8, 0, len(PriceOracles))
	for i := range PriceOracles {
		ids = append(ids, i)
	}
	sort.Slice(ids, func(a, b int) bool { return ids[a] < ids[b] })
	for _, i := range ids {
		po := PriceOracles[i]
		if height <= po.Height+common.OraclesHeightDistance && po.Price > 0 {
			priceData = append(priceData, i)
			priceData = append(priceData, common.GetByteInt64(po.Height)...)
			priceData = append(priceData, common.GetByteInt64(po.Price)...)
			prices = append(prices, po.Price)
			staked += po.Staked
		}
	}
	return priceData, prices, staked
}

func ParsePriceData(priceData []byte) (map[uint8]PriceOracle, []int64, int64, error) {
	parsedData := make(map[uint8]PriceOracle)
	dataLen := len(priceData)
	prices := []int64{}
	allStaked := int64(0)

	if dataLen%17 != 0 {
		return nil, nil, 0, fmt.Errorf("invalid priceData length: %d", dataLen)
	}

	prevID := -1
	for i := 0; i < dataLen; i += 17 {
		id := priceData[i]
		// Require strictly ascending delegated ids. This makes the aggregation
		// canonical (no producer-controlled ordering) and forbids repeating one
		// id to inflate the represented stake past the 2/3 threshold.
		if int(id) <= prevID {
			return nil, nil, 0, fmt.Errorf("priceData delegated ids must be strictly ascending, got %d after %d", id, prevID)
		}
		prevID = int(id)
		height := common.GetInt64FromByte(priceData[i+1 : i+9])
		price := common.GetInt64FromByte(priceData[i+9 : i+17])
		prices = append(prices, price)
		_, staked, _ := account.GetStakedInDelegatedAccount(int(id))
		allStaked += int64(staked)
		parsedData[id] = PriceOracle{
			Price:  price,
			Height: height,
			Staked: int64(staked),
		}
	}

	return parsedData, prices, allStaked, nil
}

func ParseRandData(randData []byte) (map[uint8]RandOracle, []byte, int64, error) {
	parsedData := make(map[uint8]RandOracle)
	dataLen := len(randData)
	rands := make([]byte, 0)
	allStaked := int64(0)

	if dataLen%17 != 0 {
		return nil, nil, 0, fmt.Errorf("invalid randData length: %d", dataLen)
	}

	prevID := -1
	for i := 0; i < dataLen; i += 17 {
		id := randData[i]
		// Require strictly ascending delegated ids so the hashed proposal order
		// is canonical (removes producer ordering-grinding on the randomness) and
		// no id can be repeated to inflate the represented stake.
		if int(id) <= prevID {
			return nil, nil, 0, fmt.Errorf("randData delegated ids must be strictly ascending, got %d after %d", id, prevID)
		}
		prevID = int(id)
		height := common.GetInt64FromByte(randData[i+1 : i+9])
		rand := common.GetInt64FromByte(randData[i+9 : i+17])
		rands = append(rands, randData[i+9:i+17]...)
		_, staked, _ := account.GetStakedInDelegatedAccount(int(id))
		allStaked += int64(staked)
		parsedData[id] = RandOracle{
			Rand:   rand,
			Height: height,
			Staked: int64(staked),
		}
	}

	return parsedData, rands, allStaked, nil
}

func GenerateRandData(height int64) ([]byte, []byte, int64) {
	randData := make([]byte, 0)
	rands := make([]byte, 0)
	staked := int64(0)
	RandOraclesRWMutex.RLock()
	defer RandOraclesRWMutex.RUnlock()
	ids := make([]uint8, 0, len(RandOracles))
	for i := range RandOracles {
		ids = append(ids, i)
	}
	sort.Slice(ids, func(a, b int) bool { return ids[a] < ids[b] })
	for _, i := range ids {
		po := RandOracles[i]
		if height <= po.Height+common.OraclesHeightDistance && po.Rand > 0 {
			randData = append(randData, i)
			randData = append(randData, common.GetByteInt64(po.Height)...)
			randData = append(randData, common.GetByteInt64(po.Rand)...)
			rands = append(rands, common.GetByteInt64(po.Rand)...)
			staked += po.Staked
		}
	}
	return randData, rands, staked
}

func CalculateRandOracle(height int64, totalStaked int64) (int64, []byte, error) {
	var rand int64
	randData, rands, staked := GenerateRandData(height)

	if staked <= 2*totalStaked/3 {
		return 0, randData, errors.New("in rand, there is not enough staked value for 2/3")
	}

	if len(rands) == 0 {
		return 0, randData, errors.New("not enough rands propositions")
	}

	// Calculate hash from all rand numbers propositions
	bytes, err := common.CalcHashFromBytes(rands)
	if err != nil {
		return 0, nil, err
	}
	rand = common.GetInt64FromByte(bytes[24:])
	return rand, randData, nil
}

func VerifyRandOracle(height int64, totalStaked int64, randBlock int64, randData []byte) bool {

	_, rands, staked, err := ParseRandData(randData)
	if err != nil {
		return false
	}

	if staked <= 2*totalStaked/3 {
		if randBlock == 0 {
			logger.GetLogger().Println("rand oracle is 0 , cannot be established")
			return true
		}
		return false
	}

	if len(rands) == 0 {
		return false
	}

	// Calculate hash from all rand numbers propositions
	bytes, err := common.CalcHashFromBytes(rands)
	if err != nil {
		return false
	}
	rand := common.GetInt64FromByte(bytes[24:])
	return rand == randBlock
}

// one has to think what happens when verification is not on current block than GetStakedInDelegatedAccount should depend on height
func VerifyPriceOracle(height int64, totalStaked int64, priceBlock int64, priceData []byte) bool {

	_, prices, staked, err := ParsePriceData(priceData)
	if err != nil {
		return false
	}

	if staked <= 2*totalStaked/3 {
		if priceBlock == 0 {
			logger.GetLogger().Println("price oracle is 0 , cannot be established")
			return true
		}
		return false
	}

	if len(prices) > 2 {
		sort.Slice(prices, func(i, j int) bool { return prices[i] < prices[j] })
		prices = prices[1 : len(prices)-1] // Remove min and max
	}

	if len(prices) == 0 {
		return false
	}

	// Calculate median price
	price := Median(prices)

	return price == priceBlock
}

func CalculatePriceOracle(height int64, totalStaked int64) (int64, []byte, error) {
	priceData, prices, staked := GeneratePriceData(height)

	if staked <= 2*totalStaked/3 {
		return 0, priceData, errors.New("in price, there is not enough staked value for 2/3")
	}

	if len(prices) > 2 {
		sort.Slice(prices, func(i, j int) bool { return prices[i] < prices[j] })
		prices = prices[1 : len(prices)-1] // Remove min and max
	}

	if len(prices) == 0 {
		return 0, priceData, errors.New("not enough prices propositions after removing min and max")
	}

	// Directly calculate median from (possibly) filtered prices
	return Median(prices), priceData, nil
}

func Median(prices []int64) int64 {
	mid := len(prices) / 2
	if len(prices)%2 == 0 {
		return (prices[mid-1] + prices[mid]) / 2
	}
	return prices[mid]
}

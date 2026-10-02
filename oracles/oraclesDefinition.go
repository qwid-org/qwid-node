package oracles

import (
	"errors"
	"fmt"
	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/common"
	"sort"
	"sync"
)

type PriceOracle struct {
	Price  int64 `json:"price"`
	Height int64 `json:"height"`
	Staked int64 `json:"staked"`
}

var (
	PriceOracles        = make(map[uint8]PriceOracle)
	PriceOraclesRWMutex sync.RWMutex

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
// SavePriceOracle).
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

	// See SavePriceOracle: the proof must back the submission that was
	// actually retained, so it follows the same strictly-newer rule.
	p, exists := oracleProofs[uint8(id)]
	if !exists || p.height < height {
		cp := make([]byte, len(txBytes))
		copy(cp, txBytes)
		oracleProofs[uint8(id)] = oracleProof{height: height, txBytes: cp}
	}
	return nil
}

// GenerateOracleProofs returns the stored proof transactions for delegated
// accounts whose submission is still fresh at height, in strictly ascending id
// order (matching GeneratePriceData).
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

	// Strictly newer only: accepting a resubmission at the same height let a
	// delegated account replace its submission after seeing the others'.
	// SaveOracleProof follows the same rule - blocks.matchOracleData requires
	// the (id, height, value) triple in a block to equal the one inside the
	// signed proof, so the two stores must keep the same submission.
	po, exists := PriceOracles[uint8(id)]
	if !exists || po.Height < height {
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
		// S4-09: generation only ever proposes positive prices; so must data.
		if price <= 0 {
			return nil, nil, 0, fmt.Errorf("priceData entry for delegated id %d has non-positive price %d", id, price)
		}
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

// VerifyPriceOracle checks a block's price against its oracle data. When the
// data does not carry more than 2/3 of the stake the price cannot be
// established and the block must carry fallback - the parent's price (S4-06).
// Accepting 0 there let any producer zero the price by embedding too few
// proofs; carried forward, it can at most hold the price for one block.
// Stake comes from the current snapshot, which block application keeps at the
// parent's.
func VerifyPriceOracle(height int64, totalStaked int64, priceBlock int64, priceData []byte, fallback int64) bool {

	_, prices, staked, err := ParsePriceData(priceData)
	if err != nil {
		return false
	}

	if staked <= 2*totalStaked/3 {
		return priceBlock == fallback
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
		// a + (b-a)/2: (a+b)/2 overflowed for large prices (S4-09). Prices are
		// positive (ParsePriceData), so b-a cannot overflow.
		a, b := prices[mid-1], prices[mid]
		return a + (b-a)/2
	}
	return prices[mid]
}

// PriceFromData computes a block's price from its oracle data exactly as
// VerifyPriceOracle checks it: stake from the current (parent) snapshot,
// min and max dropped, median of the rest. An error means the price cannot
// be established and the block carries 0.
func PriceFromData(priceData []byte, totalStaked int64) (int64, error) {
	_, prices, staked, err := ParsePriceData(priceData)
	if err != nil {
		return 0, err
	}
	if staked <= 2*totalStaked/3 {
		return 0, errors.New("in price, there is not enough staked value for 2/3")
	}
	if len(prices) > 2 {
		sort.Slice(prices, func(i, j int) bool { return prices[i] < prices[j] })
		prices = prices[1 : len(prices)-1]
	}
	if len(prices) == 0 {
		return 0, errors.New("not enough prices propositions after removing min and max")
	}
	return Median(prices), nil
}

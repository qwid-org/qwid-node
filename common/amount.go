package common

import "math"

// CoinToBaseUnits converts a decimal coin amount (e.g. 1.5 QWD) to integer base
// units, rounding to the nearest unit. WH-M4: the previous int64(amount*1e8)
// truncated toward zero, losing a base unit for values whose float
// representation fell just below the integer (e.g. 0.29 -> 28999999). Rounding
// removes that off-by-one for typical amounts. (Amounts above 2^53 base units
// still exceed float64 precision; a string-based amount API would be needed for
// exactness at that scale.)
func CoinToBaseUnits(amount float64) int64 {
	return int64(math.Round(amount * math.Pow10(int(Decimals))))
}

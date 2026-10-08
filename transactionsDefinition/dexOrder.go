package transactionsDefinition

import (
	"fmt"

	"github.com/qwid-org/qwid-node/common"
)

// DEX order data (OptData of a transaction to delegated account 512+op):
//
//	token amount (8 bytes) [ || coin limit (8 bytes) ]
//
// The coin limit (S7-07) is in base units and bounds the coins of a trade:
// at most this much paid for a buy (op 3), at least this much received for a
// sell (op 4). 0 or absent means no limit, which is what orders carried before
// the field existed. Being part of OptData it is covered by the signature, so
// a producer cannot loosen it.

// DexOrderOptData encodes a DEX order; coinLimit 0 omits the limit.
func DexOrderOptData(amountToken, coinLimit int64) []byte {
	b := common.GetByteInt64(amountToken)
	if coinLimit > 0 {
		b = append(b, common.GetByteInt64(coinLimit)...)
	}
	return b
}

// ParseDexOptData decodes and checks the order data of DEX operation op.
func ParseDexOptData(optData []byte, op int) (amountToken, coinLimit int64, err error) {
	switch len(optData) {
	case 8:
	case 16:
		coinLimit = common.GetInt64FromByte(optData[8:16])
		if coinLimit < 0 {
			return 0, 0, fmt.Errorf("DEX price limit must not be negative, got %d", coinLimit)
		}
		if coinLimit > 0 && op != 3 && op != 4 {
			return 0, 0, fmt.Errorf("a DEX price limit applies to buy and sell orders only, not operation %d", op)
		}
	default:
		return 0, 0, fmt.Errorf("DEX transaction opt data must be 8 bytes (token amount) or 16 (with a coin limit), got %d", len(optData))
	}
	return common.GetInt64FromByte(optData[:8]), coinLimit, nil
}

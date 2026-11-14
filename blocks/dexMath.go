package blocks

import (
	"fmt"
	"math/big"

	"github.com/qwid-org/qwid-node/common"
)

// DEX arithmetic, in whole base units (audit 2026-11-12).
//
// Orders used to be priced in float64 - pools and amounts converted to whole
// units, a price rounded to coin+token decimals, amounts converted back - and
// the price stored as price * 10^(coinDecimals + tokenDecimals) in an int64.
// That representation overflowed at ~922 QWD per token for an 8-decimal token
// and held no realistic price at all for an 18-decimal one, amounts above 2^53
// base units lost precision, and every step depended on float rounding staying
// identical on every architecture. Nothing here touches a float: products are
// taken in big.Int and every result is checked to fit in int64.

// MaxTokenDecimals is the most decimals a token may declare to be registered
// for the DEX: 10^18 base units per token is the largest power of ten an
// int64 amount can hold.
const MaxTokenDecimals = 18

// dexMulDiv returns a*b/c, rounded towards zero, or up in magnitude with
// roundUp. ok is false when c is zero or the result does not fit in int64.
func dexMulDiv(a, b, c int64, roundUp bool) (int64, bool) {
	if c == 0 {
		return 0, false
	}
	num := new(big.Int).Mul(big.NewInt(a), big.NewInt(b))
	q, r := new(big.Int).QuoRem(num, big.NewInt(c), new(big.Int))
	if roundUp && r.Sign() != 0 {
		if (num.Sign() < 0) != (c < 0) {
			q.Sub(q, big.NewInt(1))
		} else {
			q.Add(q, big.NewInt(1))
		}
	}
	if !q.IsInt64() {
		return 0, false
	}
	return q.Int64(), true
}

// dexTokenPrice is the price the DEX account stores: coin base units per ONE
// WHOLE token, i.e. price * 10^common.Decimals, for coin base units exchanged
// against token base units of a token with tokenDecimals. It does not depend
// on the token's decimals beyond that, so it ranges up to ~9.2e10 QWD per
// token for every token. A price that does not fit is stored as MaxInt64, an
// undefined one (no tokens) as 0. The value is informational: trades are
// computed from the pools, never from it.
func dexTokenPrice(coin, token int64, tokenDecimals uint8) int64 {
	if coin <= 0 || token <= 0 {
		return 0
	}
	num := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(tokenDecimals)), nil)
	num.Mul(num, big.NewInt(coin))
	num.Quo(num, big.NewInt(token))
	if !num.IsInt64() {
		return int64(^uint64(0) >> 1)
	}
	return num.Int64()
}

// dexShareDelta is balance*amount/pool, towards zero: what a liquidity
// provider's balance moves by when amount enters (or leaves) a pool side
// holding pool. An empty pool side moves nothing.
func dexShareDelta(balance, amount, pool int64) (int64, bool) {
	if pool <= 0 {
		return 0, true
	}
	return dexMulDiv(balance, amount, pool, false)
}

// tokenDecimalsFromWord reads a token's decimals() return word. ok is false
// when it is not a number in 0..MaxTokenDecimals.
func tokenDecimalsFromWord(word []byte) (uint8, bool) {
	v, ok := common.Int64FromSCWord(word)
	if !ok || v < 0 || v > MaxTokenDecimals {
		return 0, false
	}
	return uint8(v), true
}

// dexOrderAmounts prices one DEX order against a pool. coins is the
// transaction's Amount and tokens the token amount of its data, both in base
// units. amountCoin and amountToken are what the SENDER receives (negative:
// pays). Operations: 2 add liquidity, 3 buy, 4 sell, 5 withdraw tokens,
// 6 withdraw coins.
//
// Trades are exact constant product (x*y=k), rounded in the pool's favour:
//
//	buy  d tokens: pays     ceil (coinPool*d / (tokenPool-d))
//	sell d tokens: receives floor(coinPool*d / (tokenPool+d))
//
// so coinPool*tokenPool never decreases. A trade the pool cannot price - an
// empty side, a buy of the whole token pool, a result beyond int64 - is an
// error, and the caller skips the order.
func dexOrderAmounts(operation int, coins, tokens, coinPool, tokenPool int64, tokenDecimals uint8) (amountCoin, amountToken, price int64, err error) {
	switch operation {
	case 2:
		if tokens == 0 {
			return 0, 0, 0, fmt.Errorf("dex add liquidity: no tokens")
		}
		return -coins, -tokens, dexTokenPrice(coins, tokens, tokenDecimals), nil
	case 5:
		if coinPool <= 0 || tokenPool <= 0 {
			return 0, 0, 0, nil
		}
		c, ok := dexMulDiv(coinPool, tokens, tokenPool, false)
		if !ok {
			return 0, 0, 0, fmt.Errorf("dex withdraw token: amount does not fit in int64")
		}
		return c, tokens, dexTokenPrice(coinPool, tokenPool, tokenDecimals), nil
	case 6:
		if coinPool <= 0 || tokenPool <= 0 {
			return 0, 0, 0, nil
		}
		t, ok := dexMulDiv(tokenPool, coins, coinPool, false)
		if !ok {
			return 0, 0, 0, fmt.Errorf("dex withdraw coin: amount does not fit in int64")
		}
		return coins, t, dexTokenPrice(coinPool, tokenPool, tokenDecimals), nil
	case 3, 4:
		// A negative amount turns the order round, as it always did: a buy
		// of -d is a sell of d.
		if operation == 4 {
			if tokens == -tokens && tokens != 0 {
				return 0, 0, 0, fmt.Errorf("dex trade: amount does not fit in int64")
			}
			tokens = -tokens
		}
		if coinPool <= 0 || tokenPool <= 0 {
			return 0, 0, 0, fmt.Errorf("dex trade: the pool is empty")
		}
		if tokens > 0 { // tokens leave the pool
			if tokens >= tokenPool {
				return 0, 0, 0, fmt.Errorf("dex trade: cannot buy %d of the pool's %d tokens", tokens, tokenPool)
			}
			cost, ok := dexMulDiv(coinPool, tokens, tokenPool-tokens, true)
			if !ok {
				return 0, 0, 0, fmt.Errorf("dex trade: amount does not fit in int64")
			}
			return -cost, tokens, dexTokenPrice(cost, tokens, tokenDecimals), nil
		}
		if tokens == 0 {
			return 0, 0, 0, fmt.Errorf("dex trade: no tokens")
		}
		sold := new(big.Int).Neg(big.NewInt(tokens)) // tokens enter the pool
		den := new(big.Int).Add(big.NewInt(tokenPool), sold)
		payout := new(big.Int).Mul(big.NewInt(coinPool), sold)
		payout.Quo(payout, den)
		if !payout.IsInt64() || !sold.IsInt64() {
			return 0, 0, 0, fmt.Errorf("dex trade: amount does not fit in int64")
		}
		return payout.Int64(), tokens, dexTokenPrice(payout.Int64(), sold.Int64(), tokenDecimals), nil
	}
	return 0, 0, 0, fmt.Errorf("wrong operation on dex")
}

// dexCoversReserved reports whether a sender holding balance can take a DEX
// order moving amountCoin (negative: pays) and still cover reserved - what its
// other transactions of the same block will debit when the block's transfers
// are applied (audit 2026-11-12 F-TX-04). An order that pays the sender is
// always covered.
func dexCoversReserved(balance, amountCoin, reserved int64) bool {
	if amountCoin >= 0 {
		return true
	}
	return balance+amountCoin >= reserved
}

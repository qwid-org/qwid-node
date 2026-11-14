package blocks

import (
	"math"
	"math/big"
	"math/rand"
	"testing"

	"github.com/qwid-org/qwid-node/common"
)

// DEX arithmetic in whole base units (audit 2026-11-12, DEX price). Orders
// used to be priced in float64 and the price stored as price * 10^(8 + token
// decimals) in an int64: a price of ~922 QWD overflowed for an 8-decimal
// token, no realistic price fitted for an 18-decimal one, and amounts above
// 2^53 base units lost precision. Everything below is exact.

func k(coin, token int64) *big.Int {
	return new(big.Int).Mul(big.NewInt(coin), big.NewInt(token))
}

// order runs dexOrderAmounts and fails the test on an error.
func order(t *testing.T, op int, coins, tokens, coinPool, tokenPool int64, dec uint8) (coin, token, price int64) {
	t.Helper()
	coin, token, price, err := dexOrderAmounts(op, coins, tokens, coinPool, tokenPool, dec)
	if err != nil {
		t.Fatalf("operation %d refused: %v", op, err)
	}
	return coin, token, price
}

// A trade never lowers coinPool*tokenPool: rounding always favours the pool.
func TestIntegerTradesNeverLowerK(t *testing.T) {
	rnd := rand.New(rand.NewSource(1))
	for i := 0; i < 20000; i++ {
		coinPool := rnd.Int63n(1<<50) + 1
		tokenPool := rnd.Int63n(1<<50) + 2
		amount := rnd.Int63n(tokenPool-1) + 1
		before := k(coinPool, tokenPool)

		coin, token, _, err := dexOrderAmounts(3, 0, amount, coinPool, tokenPool, 8)
		if err == nil {
			if coin > 0 || token != amount {
				t.Fatalf("buy of %d: sender gets coin %d token %d", amount, coin, token)
			}
			if k(coinPool-coin, tokenPool-token).Cmp(before) < 0 {
				t.Fatalf("buy of %d from (%d, %d) lowered k", amount, coinPool, tokenPool)
			}
		}
		coin, token, _, err = dexOrderAmounts(4, 0, amount, coinPool, tokenPool, 8)
		if err == nil {
			if coin < 0 || token != -amount {
				t.Fatalf("sell of %d: sender gets coin %d token %d", amount, coin, token)
			}
			if k(coinPool-coin, tokenPool-token).Cmp(before) < 0 {
				t.Fatalf("sell of %d into (%d, %d) lowered k", amount, coinPool, tokenPool)
			}
		}
	}
}

func TestBuyThenSellBackNeverProfits(t *testing.T) {
	rnd := rand.New(rand.NewSource(2))
	for i := 0; i < 20000; i++ {
		coinPool := rnd.Int63n(1<<45) + 1
		tokenPool := rnd.Int63n(1<<45) + 2
		amount := rnd.Int63n(tokenPool-1) + 1
		paid, _, _, err := dexOrderAmounts(3, 0, amount, coinPool, tokenPool, 8)
		if err != nil {
			continue
		}
		got, _, _, err := dexOrderAmounts(4, 0, amount, coinPool-paid, tokenPool-amount, 8)
		if err != nil {
			continue
		}
		if got > -paid {
			t.Fatalf("round trip of %d on (%d, %d) paid %d and returned %d", amount, coinPool, tokenPool, -paid, got)
		}
	}
}

// A larger buy never gets a better price per token, and splitting a buy in two
// never costs less than doing it at once - the classic ways to milk a badly
// specified curve.
func TestLargerOrSplitBuysNeverPayLess(t *testing.T) {
	const coinPool, tokenPool = int64(1_000_000_00000000), int64(1_000_000_00000000)
	prev := new(big.Rat)
	// Sizes where the one-unit rounding in the pool's favour is far below
	// the price step between them.
	for _, size := range []int64{1_00000000, 1000_00000000, 500_000_00000000, 900_000_00000000} {
		paid, _, _ := order(t, 3, 0, size, coinPool, tokenPool, 8)
		perToken := big.NewRat(-paid, size)
		if perToken.Cmp(prev) < 0 {
			t.Fatalf("a buy of %d paid %s per token, less than a smaller buy (%s)", size, perToken, prev)
		}
		prev = perToken
	}
	const total = int64(100_000_00000000)
	oneShot, _, _ := order(t, 3, 0, total, coinPool, tokenPool, 8)
	half1, _, _ := order(t, 3, 0, total/2, coinPool, tokenPool, 8)
	half2, _, _ := order(t, 3, 0, total/2, coinPool-half1, tokenPool-total/2, 8)
	if -(half1 + half2) < -oneShot {
		t.Fatalf("two halves cost %d, the single trade %d", -(half1 + half2), -oneShot)
	}
}

func TestBuyOfTheWholePoolIsRefused(t *testing.T) {
	for _, amount := range []int64{1000, 1001, math.MaxInt64} {
		if _, _, _, err := dexOrderAmounts(3, 0, amount, 5000, 1000, 8); err == nil {
			t.Fatalf("a buy of %d from a pool of 1000 was priced", amount)
		}
	}
	for _, pools := range [][2]int64{{0, 1000}, {1000, 0}, {-1, 1000}} {
		if _, _, _, err := dexOrderAmounts(3, 0, 1, pools[0], pools[1], 8); err == nil {
			t.Fatalf("a buy from the degenerate pool %v was priced", pools)
		}
		if _, _, _, err := dexOrderAmounts(4, 0, 1, pools[0], pools[1], 8); err == nil {
			t.Fatalf("a sell into the degenerate pool %v was priced", pools)
		}
	}
}

// Exact values: buy 100 tokens from (1000 coin, 1000 token) costs
// ceil(1000*100/900) = 112; selling 100 pays floor(1000*100/1100) = 90.
func TestTradeAmountsAreExact(t *testing.T) {
	if coin, token, _ := order(t, 3, 0, 100, 1000, 1000, 0); coin != -112 || token != 100 {
		t.Fatalf("buy: coin %d token %d, want -112 and 100", coin, token)
	}
	if coin, token, _ := order(t, 4, 0, 100, 1000, 1000, 0); coin != 90 || token != -100 {
		t.Fatalf("sell: coin %d token %d, want 90 and -100", coin, token)
	}
}

// Amounts beyond float64's 53 bits stay exact.
func TestTradeAmountsAbove2Pow53AreExact(t *testing.T) {
	coinPool, tokenPool := int64(1)<<61, int64(1)<<61
	amount := int64(1)<<60 + 1
	want := new(big.Int).Mul(big.NewInt(coinPool), big.NewInt(amount))
	want.Quo(want, big.NewInt(tokenPool+amount))
	coin, _, _ := order(t, 4, 0, amount, coinPool, tokenPool, 8)
	if coin != want.Int64() {
		t.Fatalf("sell paid %d, exact value is %d", coin, want.Int64())
	}
}

// The stored price is coin base units per whole token (price * 10^8),
// whatever the token's decimals: prices that used to overflow now fit.
func TestStoredPriceFitsRealisticPrices(t *testing.T) {
	const qwd = 100_000_000
	// 1000 QWD per token, 8 decimals (the old ceiling was ~922).
	if p := dexTokenPrice(1000*qwd, 1*100_000_000, 8); p != 1000*qwd {
		t.Fatalf("price of 1000 QWD per 8-decimal token stored as %d", p)
	}
	// 1 QWD per token, 18 decimals (the old multiplier 10^26 never fitted).
	if p := dexTokenPrice(1*qwd, 1_000_000_000_000_000_000, 18); p != 1*qwd {
		t.Fatalf("price of 1 QWD per 18-decimal token stored as %d", p)
	}
	// 0.5 QWD per token, 0 decimals.
	if p := dexTokenPrice(qwd, 2, 0); p != qwd/2 {
		t.Fatalf("price of 0.5 QWD per 0-decimal token stored as %d", p)
	}
	if p := dexTokenPrice(math.MaxInt64, 1, 18); p != math.MaxInt64 {
		t.Fatalf("a price beyond int64 stored as %d, want it saturated", p)
	}
	for _, token := range []int64{0, -5} {
		if p := dexTokenPrice(qwd, token, 8); p != 0 {
			t.Fatalf("price against %d tokens stored as %d, want 0", token, p)
		}
	}
}

func TestLiquidityAndWithdrawalAmounts(t *testing.T) {
	// Add liquidity: both amounts leave the sender exactly as given.
	// 5000 coin units for 2000 units of an 8-decimal token: 2.5 QWD a token.
	coin, token, price := order(t, 2, 5_000, 2_000, 0, 0, 8)
	if coin != -5_000 || token != -2_000 || price != 250_000_000 {
		t.Fatalf("add liquidity: coin %d token %d price %d", coin, token, price)
	}
	if _, _, _, err := dexOrderAmounts(2, 5_000, 0, 0, 0, 0); err == nil {
		t.Fatal("liquidity without tokens was priced")
	}
	// Withdraw 100 tokens from (1000 coin, 400 token): 250 coins come along.
	if coin, token, _ := order(t, 5, 0, 100, 1000, 400, 0); coin != 250 || token != 100 {
		t.Fatalf("withdraw token: coin %d token %d, want 250 and 100", coin, token)
	}
	// Withdraw 250 coins: 100 tokens come along.
	if coin, token, _ := order(t, 6, 250, 0, 1000, 400, 0); coin != 250 || token != 100 {
		t.Fatalf("withdraw coin: coin %d token %d, want 250 and 100", coin, token)
	}
	// An empty pool gives nothing, as before.
	if coin, token, price := order(t, 5, 0, 100, 0, 0, 0); coin != 0 || token != 0 || price != 0 {
		t.Fatalf("withdraw from an empty pool: coin %d token %d price %d", coin, token, price)
	}
}

func TestShareDeltaIsExactAndTruncates(t *testing.T) {
	cases := []struct{ balance, amount, pool, want int64 }{
		{1000, 50, 200, 250},
		{1000, -50, 200, -250},
		{10, 1, 3, 3},
		{10, -1, 3, -3},
		{1000, 50, 0, 0},
		{1 << 61, 1 << 61, 1 << 61, 1 << 61},
	}
	for _, c := range cases {
		if got, ok := dexShareDelta(c.balance, c.amount, c.pool); !ok || got != c.want {
			t.Fatalf("share of %d for %d of %d = %d (%v), want %d", c.balance, c.amount, c.pool, got, ok, c.want)
		}
	}
	if _, ok := dexShareDelta(math.MaxInt64, math.MaxInt64, 1); ok {
		t.Fatal("a share that does not fit in int64 was reported as fitting")
	}
}

// A token balance comes back from the contract as a 256-bit word. Only its low
// 8 bytes used to be read, as a signed number: 2^63 became negative and
// anything from 2^64 up silently lost its top bits.
func TestContractWordIsReadInFull(t *testing.T) {
	word := func(v *big.Int) []byte { return common.LeftPadBytes(v.Bytes(), 32) }
	if v, ok := common.Int64FromSCWord(word(big.NewInt(123456789))); !ok || v != 123456789 {
		t.Fatalf("an ordinary balance read as %d (%v)", v, ok)
	}
	if v, ok := common.Int64FromSCWord(word(big.NewInt(math.MaxInt64))); !ok || v != math.MaxInt64 {
		t.Fatalf("the largest int64 read as %d (%v)", v, ok)
	}
	for _, huge := range []*big.Int{
		new(big.Int).Lsh(big.NewInt(1), 63),
		new(big.Int).Lsh(big.NewInt(1), 64),
		new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 200), big.NewInt(7)),
	} {
		if v, ok := common.Int64FromSCWord(word(huge)); ok {
			t.Fatalf("%s read as %d and reported as fitting", huge, v)
		}
	}
	if _, ok := common.Int64FromSCWord(make([]byte, 31)); ok {
		t.Fatal("a short word was accepted")
	}
	// The display helper saturates instead of going negative.
	if v := common.GetInt64FromSCByte(word(new(big.Int).Lsh(big.NewInt(1), 63))); v != math.MaxInt64 {
		t.Fatalf("an oversized balance is shown as %d, want it saturated", v)
	}
}

func TestTokenDecimalsAreCapped(t *testing.T) {
	word := func(v int64) []byte { return common.LeftPadBytes(big.NewInt(v).Bytes(), 32) }
	if d, ok := tokenDecimalsFromWord(word(18)); !ok || d != 18 {
		t.Fatalf("18 decimals read as %d (%v)", d, ok)
	}
	for _, v := range []int64{19, 255, 256 + 8} {
		if d, ok := tokenDecimalsFromWord(word(v)); ok {
			t.Fatalf("%d decimals accepted as %d", v, d)
		}
	}
}

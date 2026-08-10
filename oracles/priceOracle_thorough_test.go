package oracles

import (
	"testing"

	"github.com/qwid-org/qwid-node/account"
	"github.com/qwid-org/qwid-node/common"
	"github.com/qwid-org/qwid-node/logger"
)

// The PRICE oracle turns independent submissions into one number the chain
// commits to, via a trimmed median: drop the lowest and the highest, then take
// the median of the rest. That trimming is the defence against a single
// validator dragging the price, so exactly where it applies — and where it
// stops applying — is what these tests pin.

func resetPrice(t *testing.T) {
	t.Helper()
	logger.InitLogger()
	t.Cleanup(logger.CloseLogger)

	PriceOraclesRWMutex.Lock()
	PriceOracles = make(map[uint8]PriceOracle)
	PriceOraclesRWMutex.Unlock()

	account.StakingRWMutex.Lock()
	for i := 0; i < 256; i++ {
		account.StakingAccounts[i] = account.StakingAccountsType{
			AllStakingAccounts: make(map[[20]byte]account.StakingAccount),
		}
	}
	account.StakingRWMutex.Unlock()

	t.Cleanup(func() {
		PriceOraclesRWMutex.Lock()
		PriceOracles = make(map[uint8]PriceOracle)
		PriceOraclesRWMutex.Unlock()
	})
}

// submitPrices stakes each delegated account equally and records its price, so
// the aggregate clears the 2/3 bar and the only variable is the prices.
func submitPrices(t *testing.T, height int64, prices map[int16]int64) (totalStaked int64) {
	t.Helper()
	const perAccount = int64(1_000)
	for id, p := range prices {
		stakeDelegated(t, int(id), perAccount)
		if err := SavePriceOracle(p, height, delegatedAddr(id), perAccount); err != nil {
			t.Fatalf("SavePriceOracle(%d): %v", id, err)
		}
	}
	// Total below the submitted stake so the 2/3 threshold is comfortably met.
	return int64(len(prices)) * perAccount
}

// ------------------------------------------------------------- submissions

func TestSavePriceOracleRecordsSubmission(t *testing.T) {
	resetPrice(t)

	if err := SavePriceOracle(123_456_789, 100, delegatedAddr(3), 7_000); err != nil {
		t.Fatalf("SavePriceOracle: %v", err)
	}

	PriceOraclesRWMutex.RLock()
	defer PriceOraclesRWMutex.RUnlock()
	got, ok := PriceOracles[3]
	if !ok {
		t.Fatal("submission not stored under the delegated id")
	}
	if got.Price != 123_456_789 || got.Height != 100 || got.Staked != 7_000 {
		t.Errorf("stored %+v", got)
	}
}

func TestSavePriceOracleRejectsInvalidDelegatedID(t *testing.T) {
	resetPrice(t)

	for _, id := range []int16{0, 256, 300, -1} {
		if err := SavePriceOracle(1, 100, delegatedAddr(id), 1_000); err == nil {
			t.Errorf("delegated id %d was accepted", id)
		}
	}
}

func TestSavePriceOracleRejectsOlderAndSameHeight(t *testing.T) {
	resetPrice(t)

	if err := SavePriceOracle(100, 200, delegatedAddr(4), 1_000); err != nil {
		t.Fatalf("first submission: %v", err)
	}
	if err := SavePriceOracle(200, 199, delegatedAddr(4), 1_000); err == nil {
		t.Error("an older height was accepted")
	}
	if err := SavePriceOracle(300, 200, delegatedAddr(4), 1_000); err == nil {
		t.Error("a resubmission at the same height was accepted")
	}

	PriceOraclesRWMutex.RLock()
	defer PriceOraclesRWMutex.RUnlock()
	if got := PriceOracles[4].Price; got != 100 {
		t.Errorf("price = %d, want the first submission 100", got)
	}
}

func TestPriceSubmissionCountsUpToWindowEnd(t *testing.T) {
	resetPrice(t)
	const submittedAt = int64(100)

	if err := SavePriceOracle(500, submittedAt, delegatedAddr(5), 1_000); err != nil {
		t.Fatalf("submission: %v", err)
	}

	last := submittedAt + common.OraclesHeightDistance
	if _, prices, _ := GeneratePriceData(last); len(prices) != 1 {
		t.Errorf("submission dropped at the last height of its window (%d)", last)
	}
	if _, prices, _ := GeneratePriceData(last + 1); len(prices) != 0 {
		t.Errorf("submission still counted one height past its window")
	}
}

// --------------------------------------------------------- trimmed median

// Three submissions: the extremes are both dropped, so the answer is the one in
// the middle — a single outlier cannot move it at all.
func TestOutlierIsTrimmedFromThreeSubmissions(t *testing.T) {
	resetPrice(t)
	total := submitPrices(t, 100, map[int16]int64{10: 100, 11: 105, 12: 999_999})

	price, _, err := CalculatePriceOracle(100, total)
	if err != nil {
		t.Fatalf("CalculatePriceOracle: %v", err)
	}
	if price != 105 {
		t.Fatalf("price = %d, want 105 — min and max must both be dropped", price)
	}
}

// Four submissions: after trimming, two remain and the result is their mean.
func TestFourSubmissionsAverageTheMiddleTwo(t *testing.T) {
	resetPrice(t)
	total := submitPrices(t, 100, map[int16]int64{13: 100, 14: 200, 15: 300, 16: 400})

	price, _, err := CalculatePriceOracle(100, total)
	if err != nil {
		t.Fatalf("CalculatePriceOracle: %v", err)
	}
	if price != 250 { // (200 + 300) / 2
		t.Fatalf("price = %d, want 250", price)
	}
}

// With one or two submissions there is nothing left after trimming, so the code
// does not trim at all. That means a lone validator's number becomes the chain
// price verbatim — the trimming defence simply does not exist at this size.
func TestBelowThreeSubmissionsNothingIsTrimmed(t *testing.T) {
	resetPrice(t)
	total := submitPrices(t, 100, map[int16]int64{17: 999_999})

	price, _, err := CalculatePriceOracle(100, total)
	if err != nil {
		t.Fatalf("CalculatePriceOracle: %v", err)
	}
	if price != 999_999 {
		t.Fatalf("price = %d, want the single submission verbatim", price)
	}

	resetPrice(t)
	total = submitPrices(t, 100, map[int16]int64{18: 100, 19: 999_999})
	price, _, err = CalculatePriceOracle(100, total)
	if err != nil {
		t.Fatalf("CalculatePriceOracle: %v", err)
	}
	if price != 500_049 { // (100 + 999999) / 2, no trimming at two entries
		t.Fatalf("price = %d, want the untrimmed mean of two", price)
	}
}

// Two extreme submissions are enough to defeat the trimming, because only one
// of each end is removed. Worth stating explicitly: the defence holds against
// a single outlier, not against a colluding pair.
func TestTwoColludingOutliersSurviveTrimming(t *testing.T) {
	resetPrice(t)
	total := submitPrices(t, 100, map[int16]int64{
		20: 100, 21: 100, 22: 100, 23: 999_998, 24: 999_999,
	})

	price, _, err := CalculatePriceOracle(100, total)
	if err != nil {
		t.Fatalf("CalculatePriceOracle: %v", err)
	}
	// Sorted: 100 100 100 999998 999999 -> trim -> 100 100 999998 -> median 100.
	if price != 100 {
		t.Fatalf("price = %d, want 100 with three honest of five", price)
	}

	// Flip the balance: three outliers out of five and they carry the result.
	resetPrice(t)
	total = submitPrices(t, 100, map[int16]int64{
		25: 100, 26: 100, 27: 999_997, 28: 999_998, 29: 999_999,
	})
	price, _, err = CalculatePriceOracle(100, total)
	if err != nil {
		t.Fatalf("CalculatePriceOracle: %v", err)
	}
	// Sorted: 100 100 999997 999998 999999 -> trim -> 100 999997 999998,
	// median 999997. Three colluding submissions out of five carry the price.
	if price != 999_997 {
		t.Fatalf("price = %d, want the outliers to carry it at three of five", price)
	}
}

func TestMedianIsExactForOddAndEvenCounts(t *testing.T) {
	if got := Median([]int64{1, 2, 3}); got != 2 {
		t.Errorf("odd median = %d, want 2", got)
	}
	if got := Median([]int64{1, 2, 3, 4}); got != 2 { // (2+3)/2 truncates
		t.Errorf("even median = %d, want 2 after integer division", got)
	}
	if got := Median([]int64{5}); got != 5 {
		t.Errorf("single median = %d, want 5", got)
	}
}

// ---------------------------------------------------------------- threshold

func TestPriceOracleNeedsStrictlyMoreThanTwoThirds(t *testing.T) {
	resetPrice(t)
	const total = int64(9_000)

	stakeDelegated(t, 30, 6_000)
	if err := SavePriceOracle(500, 100, delegatedAddr(30), 6_000); err != nil {
		t.Fatalf("submission: %v", err)
	}
	if _, _, err := CalculatePriceOracle(100, total); err == nil {
		t.Error("exactly two thirds was accepted; the check is strict")
	}

	resetPrice(t)
	stakeDelegated(t, 31, 6_001)
	if err := SavePriceOracle(500, 100, delegatedAddr(31), 6_001); err != nil {
		t.Fatalf("submission: %v", err)
	}
	if _, _, err := CalculatePriceOracle(100, total); err != nil {
		t.Errorf("just above two thirds was rejected: %v", err)
	}
}

func TestPriceOracleRejectsWhenNobodySubmitted(t *testing.T) {
	resetPrice(t)

	if _, _, err := CalculatePriceOracle(100, 9_000); err == nil {
		t.Fatal("a price was produced with no submissions")
	}
}

// ------------------------------------------------------- calculate / verify

func TestVerifyAcceptsWhatCalculatePriceProduced(t *testing.T) {
	resetPrice(t)
	total := submitPrices(t, 100, map[int16]int64{40: 100, 41: 105, 42: 110, 43: 115})

	price, priceData, err := CalculatePriceOracle(100, total)
	if err != nil {
		t.Fatalf("CalculatePriceOracle: %v", err)
	}
	if !VerifyPriceOracle(100, total, price, priceData) {
		t.Fatal("a validator rejected the price its own producer path computed")
	}
}

func TestVerifyRejectsATamperedPrice(t *testing.T) {
	resetPrice(t)
	total := submitPrices(t, 100, map[int16]int64{44: 100, 45: 105, 46: 110, 47: 115})

	price, priceData, err := CalculatePriceOracle(100, total)
	if err != nil {
		t.Fatalf("CalculatePriceOracle: %v", err)
	}
	if VerifyPriceOracle(100, total, price+1, priceData) {
		t.Fatal("a price that does not follow from the submissions was accepted")
	}
}

func TestPriceCalculationIsDeterministic(t *testing.T) {
	resetPrice(t)
	total := submitPrices(t, 100, map[int16]int64{
		50: 101, 51: 102, 52: 103, 53: 104, 54: 105,
	})

	first, _, err := CalculatePriceOracle(100, total)
	if err != nil {
		t.Fatalf("CalculatePriceOracle: %v", err)
	}
	for i := 0; i < 20; i++ {
		again, _, err := CalculatePriceOracle(100, total)
		if err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		if again != first {
			t.Fatalf("run %d gave %d, first gave %d — map iteration order is "+
				"leaking into consensus data", i, again, first)
		}
	}
}

// Prices are 8-decimal fixed point, so a real BTC/USD quote is around 1e13.
// The arithmetic must stay exact at that magnitude rather than drifting.
func TestPriceArithmeticIsExactAtRealBTCMagnitudes(t *testing.T) {
	resetPrice(t)
	// 64188.42 / 64188.43 / 64188.44 USD in 8-decimal fixed point.
	total := submitPrices(t, 100, map[int16]int64{
		60: 6_418_842_000_000, 61: 6_418_843_000_000, 62: 6_418_844_000_000,
	})

	price, _, err := CalculatePriceOracle(100, total)
	if err != nil {
		t.Fatalf("CalculatePriceOracle: %v", err)
	}
	if price != 6_418_843_000_000 {
		t.Fatalf("price = %d, want the exact middle quote", price)
	}
}

package oracles

import (
	"math/rand"
	"sort"
	"testing"

	"github.com/qwid-org/qwid-node/common"
)

// Audit 2026-11-12 F-CONS-02: the chain price is the STAKE-weighted median of
// the embedded submissions. Counting every delegated account once let a few
// minimum-stake accounts outvote the stake.

type sub struct {
	id    uint8
	stake int64
	price int64
}

// priceDataOf stakes each account and encodes the submissions as a block does.
func priceDataOf(t *testing.T, subs []sub) []byte {
	t.Helper()
	sort.Slice(subs, func(i, j int) bool { return subs[i].id < subs[j].id })
	var data []byte
	for _, s := range subs {
		stakeDelegated(t, int(s.id), s.stake)
		data = append(data, s.id)
		data = append(data, common.GetByteInt64(100)...)
		data = append(data, common.GetByteInt64(s.price)...)
	}
	return data
}

func totalOf(subs []sub) (w int64) {
	for _, s := range subs {
		w += s.stake
	}
	return w
}

func TestPriceIsTheStakeWeightedMedian(t *testing.T) {
	resetPrice(t)
	subs := []sub{
		{1, 100_000_000, 60_000}, {2, 100_000_000, 60_000}, {3, 100_000_000, 60_000},
		{4, 1_000_000, 120_000}, {5, 1_000_000, 120_000}, {6, 1_000_000, 120_000}, {7, 1_000_000, 120_000},
	}
	data := priceDataOf(t, subs)
	price, err := PriceFromData(data, totalOf(subs))
	if err != nil {
		t.Fatal(err)
	}
	if price != 60_000 {
		t.Fatalf("price = %d: four accounts holding 1.3%% of the stake set it; want 60000", price)
	}
	if !VerifyPriceOracle(100, totalOf(subs), 60_000, data, 1) || VerifyPriceOracle(100, totalOf(subs), 120_000, data, 1) {
		t.Fatal("block verification does not agree with the weighted median")
	}
}

// A producer may leave out proofs worth up to a third of the stake (it alone
// knows which nonces it received). With the weighted median that can move the
// price only among what the honest stake reported.
func TestOmittingUpToAThirdOfTheStakeKeepsThePriceAmongHonestReports(t *testing.T) {
	honest := []sub{
		{1, 40_000_000, 59_900}, {2, 30_000_000, 59_950}, {3, 25_000_000, 60_000},
		{4, 20_000_000, 60_020}, {5, 15_000_000, 60_050}, {6, 10_000_000, 60_100},
	}
	// more accounts than the honest side, under 5% of the stake
	var attacker []sub
	for id := uint8(7); id <= 13; id++ {
		attacker = append(attacker, sub{id, 1_000_000, 1_000_000})
	}
	total := totalOf(honest) + totalOf(attacker)
	byPrice := append([]sub{}, honest...)
	for _, side := range []string{"low", "high"} {
		sort.Slice(byPrice, func(i, j int) bool {
			if side == "low" {
				return byPrice[i].price < byPrice[j].price
			}
			return byPrice[i].price > byPrice[j].price
		})
		for drop := 0; drop <= len(byPrice); drop++ {
			kept := append(append([]sub{}, byPrice[drop:]...), attacker...)
			if 3*totalOf(kept) <= 2*total { // the block would carry the price forward
				break
			}
			resetPrice(t)
			price, err := PriceFromData(priceDataOf(t, kept), total)
			if err != nil {
				t.Fatal(err)
			}
			if price < 59_900 || price > 60_100 {
				t.Fatalf("leaving out %d honest proofs from the %s side moved the price to %d", drop, side, price)
			}
		}
	}
}

// With equal stakes the weighted median is the ordinary median - which is what
// the former rule (drop the lowest and the highest, then the median) gave too.
func TestEqualStakesGiveTheFormerResult(t *testing.T) {
	r := rand.New(rand.NewSource(7))
	for n := 1; n <= 12; n++ {
		for trial := 0; trial < 50; trial++ {
			resetPrice(t)
			var subs []sub
			var prices []int64
			for i := 0; i < n; i++ {
				p := int64(r.Intn(1000) + 1)
				subs = append(subs, sub{uint8(i + 1), 5_000, p})
				prices = append(prices, p)
			}
			sort.Slice(prices, func(i, j int) bool { return prices[i] < prices[j] })
			old := prices
			if len(old) > 2 {
				old = old[1 : len(old)-1]
			}
			want := Median(old)
			got, err := PriceFromData(priceDataOf(t, subs), totalOf(subs))
			if err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Fatalf("n=%d prices %v: weighted %d, former %d", n, prices, got, want)
			}
		}
	}
}

func TestStakeSplitExactlyInHalfTakesTheMidpoint(t *testing.T) {
	resetPrice(t)
	subs := []sub{{1, 700, 100}, {2, 300, 150}, {3, 1_000, 300}}
	got, err := PriceFromData(priceDataOf(t, subs), totalOf(subs))
	if err != nil {
		t.Fatal(err)
	}
	if got != 225 { // 1000 of 2000 at or below 150, the rest at 300: (150+300)/2
		t.Fatalf("price = %d, want 225", got)
	}
}

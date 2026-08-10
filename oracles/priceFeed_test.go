package oracles

import (
	"errors"
	"testing"
	"time"

	"github.com/qwid-org/qwid-node/logger"
)

// No test here touches the network: the fetcher is injected. The one property
// that matters most is negative — a node whose feed is broken must keep
// producing blocks and must submit nothing, rather than submitting a guess.

func resetFeed(t *testing.T) {
	t.Helper()
	logger.InitLogger()
	t.Cleanup(logger.CloseLogger)

	priceFeedMutex.Lock()
	priceFeedValue, priceFeedAt = 0, time.Time{}
	priceFeedMutex.Unlock()

	savedNow := priceFeedNow
	t.Cleanup(func() {
		priceFeedNow = savedNow
		priceFeedMutex.Lock()
		priceFeedValue, priceFeedAt = 0, time.Time{}
		priceFeedMutex.Unlock()
	})
}

func TestNoQuoteYetMeansNoSubmission(t *testing.T) {
	resetFeed(t)

	if _, ok := CurrentPrice(); ok {
		t.Fatal("a price was offered before any quote was fetched")
	}
}

func TestRefreshPublishesQuote(t *testing.T) {
	resetFeed(t)

	if err := RefreshPrice(func() (int64, error) { return 6_418_842_000_000, nil }); err != nil {
		t.Fatalf("RefreshPrice: %v", err)
	}

	got, ok := CurrentPrice()
	if !ok {
		t.Fatal("a freshly fetched quote is not offered")
	}
	if got != 6_418_842_000_000 {
		t.Fatalf("price = %d", got)
	}
}

// An upstream failure must not clear a usable quote — a brief outage should not
// silence a node that already knows the market.
func TestFailedRefreshKeepsThePreviousQuote(t *testing.T) {
	resetFeed(t)

	if err := RefreshPrice(func() (int64, error) { return 6_418_842_000_000, nil }); err != nil {
		t.Fatalf("first refresh: %v", err)
	}
	if err := RefreshPrice(func() (int64, error) { return 0, errors.New("upstream down") }); err == nil {
		t.Fatal("a failing fetch reported success")
	}

	got, ok := CurrentPrice()
	if !ok || got != 6_418_842_000_000 {
		t.Fatalf("previous quote lost after a failed refresh: %d ok=%t", got, ok)
	}
}

// A quote that is too old is worse than none: submitting it would report a
// market that may have moved. The node goes quiet instead.
func TestStaleQuoteIsNotOffered(t *testing.T) {
	resetFeed(t)

	base := time.Now()
	priceFeedNow = func() time.Time { return base }
	if err := RefreshPrice(func() (int64, error) { return 6_418_842_000_000, nil }); err != nil {
		t.Fatalf("refresh: %v", err)
	}

	priceFeedNow = func() time.Time { return base.Add(PriceFeedMaxAge) }
	if _, ok := CurrentPrice(); !ok {
		t.Error("a quote exactly at the age limit was withheld")
	}

	priceFeedNow = func() time.Time { return base.Add(PriceFeedMaxAge + time.Second) }
	if _, ok := CurrentPrice(); ok {
		t.Error("a quote past the age limit was still offered")
	}
}

// A malformed upstream response must never reach the cache.
func TestNonPositiveQuoteIsRejected(t *testing.T) {
	resetFeed(t)

	for _, v := range []int64{0, -1} {
		if err := RefreshPrice(func() (int64, error) { return v, nil }); err == nil {
			t.Errorf("quote %d was accepted", v)
		}
	}
	if _, ok := CurrentPrice(); ok {
		t.Fatal("a rejected quote still became submittable")
	}
}

// ------------------------------------------------------------------ parsing

func TestParseCoinbaseSpotConvertsToFixedPoint(t *testing.T) {
	got, err := ParseCoinbaseSpot([]byte(`{"data":{"amount":"64188.425","base":"BTC","currency":"USD"}}`))
	if err != nil {
		t.Fatalf("ParseCoinbaseSpot: %v", err)
	}
	if got != 6_418_842_500_000 {
		t.Fatalf("parsed %d, want 6418842500000 (64188.425 in 8 decimals)", got)
	}
}

func TestParseCoinbaseSpotRoundsRatherThanTruncates(t *testing.T) {
	// 0.000000005 sits half a unit above the last representable digit.
	got, err := ParseCoinbaseSpot([]byte(`{"data":{"amount":"1.000000005","currency":"USD"}}`))
	if err != nil {
		t.Fatalf("ParseCoinbaseSpot: %v", err)
	}
	if got != 100_000_001 {
		t.Fatalf("parsed %d, want 100000001 — the last digit must round, not truncate", got)
	}
}

func TestParseCoinbaseSpotRejectsBadPayloads(t *testing.T) {
	cases := map[string]string{
		"not json":        `<html>rate limited</html>`,
		"wrong currency":  `{"data":{"amount":"64188.42","currency":"EUR"}}`,
		"missing amount":  `{"data":{"currency":"USD"}}`,
		"amount not a number": `{"data":{"amount":"n/a","currency":"USD"}}`,
		"zero amount":     `{"data":{"amount":"0","currency":"USD"}}`,
		"negative amount": `{"data":{"amount":"-5","currency":"USD"}}`,
		"empty":           ``,
	}
	for name, body := range cases {
		if _, err := ParseCoinbaseSpot([]byte(body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The background poller must not be the thing that stops a node: starting it
// with a fetcher that always fails has to leave the node running and quiet.
func TestPollerSurvivesAPermanentlyFailingUpstream(t *testing.T) {
	resetFeed(t)

	stop := make(chan struct{})
	StartPriceFeed(func() (int64, error) { return 0, errors.New("always down") }, stop)
	defer close(stop)

	time.Sleep(50 * time.Millisecond)
	if _, ok := CurrentPrice(); ok {
		t.Fatal("a price was offered although every fetch failed")
	}
}

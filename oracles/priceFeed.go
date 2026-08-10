package oracles

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/qwid-org/qwid-node/logger"
)

// The price a node submits used to be a random number around 1.0 with a TODO
// on it (services/nonceService). This is the real quote instead.
//
// The single hard rule here is that nothing on this path may block block
// production. A node proposes a nonce roughly every 10 seconds; an HTTP call
// made inline would stall the chain the first time the upstream hung. So a
// background poller refreshes a cached quote, and the block path only ever
// reads that cache, without waiting and without failing.
//
// When there is no fresh quote the node submits nothing rather than something
// invented. GeneratePriceData skips a zero price, so a node with a broken feed
// simply stops contributing to the median instead of dragging it.

const (
	// PriceFeedRefreshInterval is how often the poller asks upstream. The
	// oracle window is OraclesHeightDistance blocks (~1 minute), so refreshing
	// twice inside that window keeps every submission backed by a recent quote
	// without hammering a free endpoint.
	PriceFeedRefreshInterval = 30 * time.Second

	// PriceFeedMaxAge is how long a cached quote may still be submitted. Past
	// this the node goes quiet rather than reporting a stale market.
	PriceFeedMaxAge = 5 * time.Minute

	// priceFeedTimeout bounds a single upstream request. It only ever delays
	// the background poller.
	priceFeedTimeout = 8 * time.Second

	// priceFeedURL is Coinbase's public spot endpoint: no API key, no account,
	// and a stable {"data":{"amount":"...","currency":"USD"}} shape.
	priceFeedURL = "https://api.coinbase.com/v2/prices/BTC-USD/spot"
)

// PriceFetcher returns the current BTC/USD quote in 8-decimal fixed point,
// matching the on-chain representation. Injected so tests never touch the
// network.
type PriceFetcher func() (int64, error)

var (
	priceFeedMutex sync.RWMutex
	priceFeedValue int64
	priceFeedAt    time.Time

	// priceFeedNow is overridable so staleness can be tested without sleeping.
	priceFeedNow = time.Now
)

// CurrentPrice returns the cached quote and whether it is fresh enough to
// submit. It never blocks on the network and never returns an error: a node
// that cannot reach the feed must keep producing blocks.
func CurrentPrice() (int64, bool) {
	priceFeedMutex.RLock()
	defer priceFeedMutex.RUnlock()
	if priceFeedValue <= 0 || priceFeedAt.IsZero() {
		return 0, false
	}
	if priceFeedNow().Sub(priceFeedAt) > PriceFeedMaxAge {
		return 0, false
	}
	return priceFeedValue, true
}

// setPrice publishes a quote to the cache. Rejects non-positive values so a
// malformed response can never become a submission.
func setPrice(v int64) error {
	if v <= 0 {
		return fmt.Errorf("price feed returned a non-positive quote: %d", v)
	}
	priceFeedMutex.Lock()
	defer priceFeedMutex.Unlock()
	priceFeedValue = v
	priceFeedAt = priceFeedNow()
	return nil
}

// RefreshPrice performs one fetch-and-publish cycle. Exposed for the poller
// and for tests; callers on the block path must use CurrentPrice instead.
func RefreshPrice(fetch PriceFetcher) error {
	v, err := fetch()
	if err != nil {
		return err
	}
	return setPrice(v)
}

// StartPriceFeed refreshes the cached quote in the background until stop is
// closed. Safe to call with a nil fetcher, which selects the default upstream.
//
// A failed refresh is logged and retried on the next tick; it never clears the
// cache, so a brief upstream outage does not silence a node that already has a
// usable quote.
func StartPriceFeed(fetch PriceFetcher, stop <-chan struct{}) {
	if fetch == nil {
		fetch = FetchBTCUSD
	}
	go func() {
		if err := RefreshPrice(fetch); err != nil {
			logger.GetLogger().Println("price feed: initial fetch failed:", err)
		}
		ticker := time.NewTicker(PriceFeedRefreshInterval)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				if err := RefreshPrice(fetch); err != nil {
					logger.GetLogger().Println("price feed: refresh failed:", err)
				}
			}
		}
	}()
}

// FetchBTCUSD reads the spot quote from the public endpoint and converts it to
// 8-decimal fixed point.
func FetchBTCUSD() (int64, error) {
	client := &http.Client{Timeout: priceFeedTimeout}
	resp, err := client.Get(priceFeedURL)
	if err != nil {
		return 0, fmt.Errorf("price feed request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("price feed returned status %d", resp.StatusCode)
	}
	// Bounded read: a hostile or broken upstream must not be able to make the
	// node allocate without limit.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return 0, fmt.Errorf("price feed body unreadable: %w", err)
	}
	return ParseCoinbaseSpot(body)
}

// ParseCoinbaseSpot converts {"data":{"amount":"64188.42","currency":"USD"}}
// into 8-decimal fixed point. Separate from the HTTP call so the parsing is
// testable against captured payloads.
func ParseCoinbaseSpot(body []byte) (int64, error) {
	var payload struct {
		Data struct {
			Amount   string `json:"amount"`
			Currency string `json:"currency"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return 0, fmt.Errorf("price feed response is not JSON: %w", err)
	}
	if payload.Data.Currency != "USD" {
		return 0, fmt.Errorf("price feed returned currency %q, want USD", payload.Data.Currency)
	}
	if payload.Data.Amount == "" {
		return 0, fmt.Errorf("price feed response has no amount")
	}
	amount, err := strconv.ParseFloat(payload.Data.Amount, 64)
	if err != nil {
		return 0, fmt.Errorf("price feed amount %q is not a number: %w", payload.Data.Amount, err)
	}
	if amount <= 0 || math.IsInf(amount, 0) || math.IsNaN(amount) {
		return 0, fmt.Errorf("price feed amount %q is not a usable quote", payload.Data.Amount)
	}
	// Round rather than truncate so the last digit is not biased downwards.
	scaled := math.Round(amount * 1e8)
	if scaled > float64(math.MaxInt64) {
		return 0, fmt.Errorf("price feed amount %q overflows int64 fixed point", payload.Data.Amount)
	}
	return int64(scaled), nil
}

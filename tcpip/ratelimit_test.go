package tcpip

import (
	"testing"

	"github.com/wonabru/qwid-node/common"
)

func TestMaxMessageSizeForTopic(t *testing.T) {
	cases := []struct {
		topic [2]byte
		want  int32
	}{
		{NonceTopic, common.MaxMsgSizeSmall},
		{SelfNonceTopic, common.MaxMsgSizeSmall},
		{TransactionTopic, common.MaxMessageSizeBytes},
		{SyncTopic, common.MaxMsgSizeSync},
		{RPCTopic, common.MaxMsgSizeRPC},
		{[2]byte{'?', '?'}, common.MaxMsgSizeSmall}, // unknown -> tightest
	}
	for _, c := range cases {
		if got := MaxMessageSizeForTopic(c.topic); got != c.want {
			t.Errorf("topic %v: got %d want %d", c.topic, got, c.want)
		}
	}
}

func TestAllowInWindow(t *testing.T) {
	w := &rateWindow{}
	const limit, window = 3, 10
	base := int64(1000)
	// First `limit` events in the window are allowed; the next is not.
	for i := 0; i < limit; i++ {
		if !allowInWindow(w, base, limit, window) {
			t.Fatalf("event %d within limit should be allowed", i)
		}
	}
	if allowInWindow(w, base, limit, window) {
		t.Fatal("event over limit within window must be denied")
	}
	// Advancing past the window resets the count.
	if !allowInWindow(w, base+window, limit, window) {
		t.Fatal("first event in a new window must be allowed")
	}
}

func TestAllowMessageFromIPWhitelistBypass(t *testing.T) {
	wl := [4]byte{9, 9, 9, 9}
	AddWhiteListIPs(wl)
	// Hammer well past the limit; a whitelisted IP is never throttled.
	for i := 0; i < common.MessageRateLimit+50; i++ {
		if !AllowMessageFromIP(wl) {
			t.Fatal("whitelisted IP must never be message-rate-limited")
		}
	}
}

func TestAllowMessageFromIPThrottles(t *testing.T) {
	ip := [4]byte{7, 0, 0, 1} // not whitelisted, not banned
	// This test uses the real clock, so tolerate at most ONE window reset: the
	// loop runs in microseconds, so it can straddle at most one 1-second
	// boundary => at most 2 windows => at most 2*limit allowed. Doing 2*limit+1
	// calls therefore GUARANTEES at least one denial. (The exact per-window
	// count is covered deterministically by TestAllowInWindow with an injected
	// clock.)
	n := 2*common.MessageRateLimit + 1
	allowed := 0
	for i := 0; i < n; i++ {
		if AllowMessageFromIP(ip) {
			allowed++
		}
	}
	if allowed >= n {
		t.Fatalf("AllowMessageFromIP never throttled: %d/%d allowed", allowed, n)
	}
}

func TestPruneRateLimitsOnBan(t *testing.T) {
	ip := [4]byte{7, 0, 0, 2}
	AllowMessageFromIP(ip)
	AllowConnectionFromIP(ip)
	pruneRateLimits(ip)
	msgRateMutex.Lock()
	_, m := msgRate[ip]
	msgRateMutex.Unlock()
	connRateMutex.Lock()
	_, c := connRate[ip]
	connRateMutex.Unlock()
	if m || c {
		t.Fatal("pruneRateLimits must delete both rate entries")
	}
}

func TestBannedTimeSecondsLengthened(t *testing.T) {
	if common.BannedTimeSeconds != 60 {
		t.Fatalf("BannedTimeSeconds = %d, want 60", common.BannedTimeSeconds)
	}
}

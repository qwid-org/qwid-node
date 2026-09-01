package transactionsDefinition

import (
	"testing"
	"time"

	"github.com/qwid-org/qwid-node/common"
)

func addrOf(t *testing.T, seed byte) common.Address {
	t.Helper()
	b := make([]byte, common.AddressLength)
	for i := range b {
		b[i] = seed + byte(i)
	}
	a := common.Address{}
	if err := a.Init(b); err != nil {
		t.Fatalf("could not build an address: %v", err)
	}
	return a
}

func resetVerifyLogThrottle() {
	verifyLogMutex.Lock()
	verifyLogTimes = map[[common.AddressLength]byte]time.Time{}
	verifyLogSkipped = map[[common.AddressLength]byte]int{}
	verifyLogFolded = 0
	verifyLogMutex.Unlock()
}

// Verification failures come from untrusted input: anyone can send transactions
// this node refuses, and an untuned line turns one forged transaction into a
// guaranteed write. A flood must cost a constant trickle of log, while the
// first occurrence is still reported at once.
func TestVerifyFailureLoggingIsBounded(t *testing.T) {
	resetVerifyLogThrottle()
	sender := addrOf(t, 0x30)

	if ok, _ := shouldLogVerifyFailure(sender); !ok {
		t.Fatal("the first failure was suppressed; an operator must see the condition start")
	}
	const flood = 10000
	for i := 0; i < flood; i++ {
		if ok, _ := shouldLogVerifyFailure(sender); ok {
			t.Fatalf("failure %d was logged inside the quiet period", i)
		}
	}

	verifyLogMutex.Lock()
	var key [common.AddressLength]byte
	copy(key[:], sender.GetBytes())
	verifyLogTimes[key] = time.Now().Add(-2 * verifyLogInterval)
	verifyLogMutex.Unlock()

	ok, skipped := shouldLogVerifyFailure(sender)
	if !ok {
		t.Fatal("nothing was reported after the period elapsed")
	}
	if skipped != flood {
		t.Fatalf("reported %d suppressed failures, expected %d — a silent gap invites wrong conclusions", skipped, flood)
	}
}

// The throttle must not become its own memory exhaustion: a flood from forged
// sender addresses would otherwise grow the bookkeeping without limit.
func TestVerifyFailureThrottleDoesNotGrowUnbounded(t *testing.T) {
	resetVerifyLogThrottle()
	for i := 0; i < 500; i++ {
		shouldLogVerifyFailure(addrOf(t, byte(i)))
	}
	verifyLogMutex.Lock()
	for a := range verifyLogTimes {
		verifyLogTimes[a] = time.Now().Add(-2 * verifyLogInterval)
	}
	verifyLogMutex.Unlock()

	shouldLogVerifyFailure(addrOf(t, 0xF0)) // prunes on the way through

	verifyLogMutex.Lock()
	n := len(verifyLogTimes)
	verifyLogMutex.Unlock()
	if n > 2 {
		t.Fatalf("the throttle retained %d senders after they expired", n)
	}
}

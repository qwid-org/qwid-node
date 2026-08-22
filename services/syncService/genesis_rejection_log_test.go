package syncServices

import (
	"testing"
	"time"
)

// withRejectionLogTimes swaps in a fresh genesisRejectionLogTimes map for the
// duration of fn, so these tests do not interfere with each other or with
// state any other test (or production code exercised via OnMessage) may have
// left behind.
func withRejectionLogTimes(t *testing.T, times map[[4]byte]time.Time, fn func()) {
	t.Helper()
	genesisRejectionLogTimesMutex.Lock()
	saved := genesisRejectionLogTimes
	genesisRejectionLogTimes = times
	genesisRejectionLogTimesMutex.Unlock()
	defer func() {
		genesisRejectionLogTimesMutex.Lock()
		genesisRejectionLogTimes = saved
		genesisRejectionLogTimesMutex.Unlock()
	}()
	fn()
}

// TestShouldLogRejectionDedupsPerAddress proves design requirement 4 ("log
// once per peer address"): repeated rejections from the same address within
// the interval are only worth logging once, while a different address still
// gets its own, independent log-worthy event. This is the direct test for
// the churn Finding 1 describes - 'hi' rebroadcast roughly every second and a
// reconnect roughly every ten - since without this, every one of those
// reconnects would produce another log line forever.
func TestShouldLogRejectionDedupsPerAddress(t *testing.T) {
	addrA := [4]byte{203, 0, 113, 30}
	addrB := [4]byte{203, 0, 113, 31}

	withRejectionLogTimes(t, map[[4]byte]time.Time{}, func() {
		if !shouldLogRejection(addrA) {
			t.Fatal("first rejection from a fresh address must be logged")
		}
		if shouldLogRejection(addrA) {
			t.Fatal("second rejection from the same address within the interval must be suppressed")
		}
		if shouldLogRejection(addrA) {
			t.Fatal("third rejection from the same address within the interval must be suppressed")
		}
		if !shouldLogRejection(addrB) {
			t.Fatal("a different address must produce its own log-worthy event")
		}
		if shouldLogRejection(addrB) {
			t.Fatal("second rejection from addrB within the interval must be suppressed")
		}
	})
}

// TestShouldLogRejectionLogsAgainAfterInterval proves the dedup is time-bound,
// not permanent: an address last logged before genesisRejectionLogInterval
// elapsed is worth logging again, so a persistent misconfiguration stays
// visible to an operator instead of going silent forever after the first line.
func TestShouldLogRejectionLogsAgainAfterInterval(t *testing.T) {
	addr := [4]byte{203, 0, 113, 32}
	stale := map[[4]byte]time.Time{addr: time.Now().Add(-genesisRejectionLogInterval - time.Second)}

	withRejectionLogTimes(t, stale, func() {
		if !shouldLogRejection(addr) {
			t.Fatal("an address last logged before the interval elapsed must be logged again")
		}
	})
}

// TestShouldLogRejectionPrunesExpiredEntries proves the map cannot grow
// without bound under a flood of forged source addresses: an entry older
// than the interval is deleted outright on the next call, not merely
// ignored while it sits in the map forever.
func TestShouldLogRejectionPrunesExpiredEntries(t *testing.T) {
	stale := [4]byte{203, 0, 113, 33}
	fresh := [4]byte{203, 0, 113, 34}
	seed := map[[4]byte]time.Time{
		stale: time.Now().Add(-genesisRejectionLogInterval - time.Second),
	}

	withRejectionLogTimes(t, seed, func() {
		shouldLogRejection(fresh) // triggers the prune pass as a side effect

		genesisRejectionLogTimesMutex.Lock()
		_, staleStillPresent := genesisRejectionLogTimes[stale]
		_, freshPresent := genesisRejectionLogTimes[fresh]
		count := len(genesisRejectionLogTimes)
		genesisRejectionLogTimesMutex.Unlock()

		if staleStillPresent {
			t.Fatal("an expired entry was not pruned")
		}
		if !freshPresent {
			t.Fatal("the entry just recorded should still be present")
		}
		if count != 1 {
			t.Fatalf("expected exactly 1 entry after pruning, got %d", count)
		}
	})
}

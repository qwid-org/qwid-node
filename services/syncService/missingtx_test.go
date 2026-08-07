package syncServices

import (
	"testing"
	"time"

	"github.com/wonabru/qwid-node/common"
)

func withFreshMissingTx(t *testing.T) {
	t.Helper()
	missingTxMutex.Lock()
	saved := missingTx
	missingTx = map[[common.HashLength]byte]missingTxState{}
	missingTxMutex.Unlock()
	t.Cleanup(func() {
		missingTxMutex.Lock()
		missingTx = saved
		missingTxMutex.Unlock()
	})
}

func txHash(b byte) []byte {
	h := make([]byte, common.HashLength)
	h[0] = b
	return h
}

// TestDueMissingTxRequests: the same hash must not be re-requested more often
// than missingTxRetryInterval - the old code asked twice a second forever -
// and after missingTxEscalateAfter unanswered tries it must be flagged for
// escalation to other peers.
func TestDueMissingTxRequests(t *testing.T) {
	withFreshMissingTx(t)
	t0 := time.Now()
	h1, h2 := txHash(1), txHash(2)

	due, esc := dueMissingTxRequests([][]byte{h1, h2}, t0)
	if len(due) != 2 || len(esc) != 0 {
		t.Fatalf("pierwsza runda: due=%d esc=%d, oczekiwano 2/0", len(due), len(esc))
	}

	// Half a second later (the old spam cadence): nothing is due.
	if due, _ = dueMissingTxRequests([][]byte{h1, h2}, t0.Add(500*time.Millisecond)); len(due) != 0 {
		t.Fatalf("po 500ms due=%d, oczekiwano 0 (throttle)", len(due))
	}

	// After the retry interval both are due again.
	if due, _ = dueMissingTxRequests([][]byte{h1, h2}, t0.Add(missingTxRetryInterval+time.Second)); len(due) != 2 {
		t.Fatalf("po interwale due=%d, oczekiwano 2", len(due))
	}

	// Drive h1 to the escalation threshold.
	now := t0.Add(missingTxRetryInterval + time.Second)
	escalated := false
	for i := 0; i < missingTxEscalateAfter; i++ {
		now = now.Add(missingTxRetryInterval + time.Second)
		_, esc = dueMissingTxRequests([][]byte{h1}, now)
		if len(esc) == 1 {
			escalated = true
		}
	}
	if !escalated {
		t.Fatalf("po %d próbach hash nie został eskalowany", 2+missingTxEscalateAfter)
	}

	// clearMissingTx starts a fresh cycle: immediately due again, no escalation.
	clearMissingTx()
	due, esc = dueMissingTxRequests([][]byte{h1}, now)
	if len(due) != 1 || len(esc) != 0 {
		t.Fatalf("po wyczyszczeniu due=%d esc=%d, oczekiwano 1/0", len(due), len(esc))
	}
}

// TestMissingTxForget: bookkeeping for hashes not asked about for a long time
// is dropped, so the map cannot grow without bound across a long sync.
func TestMissingTxForget(t *testing.T) {
	withFreshMissingTx(t)
	t0 := time.Now()

	dueMissingTxRequests([][]byte{txHash(1)}, t0)
	dueMissingTxRequests([][]byte{txHash(2)}, t0.Add(missingTxForget+time.Minute))

	missingTxMutex.Lock()
	n := len(missingTx)
	missingTxMutex.Unlock()
	if n != 1 {
		t.Fatalf("mapa ma %d wpisów, oczekiwano 1 (stary wpis zapomniany)", n)
	}
}

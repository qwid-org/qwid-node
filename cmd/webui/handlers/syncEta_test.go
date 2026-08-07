package handlers

import (
	"testing"
	"time"
)

// TestSyncEtaTracker: the estimate must come from how fast the DISTANCE to the
// network height shrinks (the network keeps producing while we import), report
// -1 while there is no honest estimate, and recover quickly after a rewind.
func TestSyncEtaTracker(t *testing.T) {
	tr := &syncEtaTracker{}
	t0 := time.Now()

	// First sample: window too fresh for any estimate.
	rate, eta := tr.observe(t0, 100000, 10000)
	if eta != -1 {
		t.Fatalf("ETA po pierwszej próbce = %d, oczekiwano -1", eta)
	}

	// Import 100 blocks/s while the network produces 0.1/s: after 10s the
	// height moved 1000 up and the distance shrank by 999.
	rate, eta = tr.observe(t0.Add(10*time.Second), 101000, 9001)
	if rate < 99 || rate > 101 {
		t.Fatalf("tempo importu = %.1f blk/s, oczekiwano ~100", rate)
	}
	// Closing speed 99.9/s over 9001 blocks -> ~90s.
	if eta < 88 || eta > 93 {
		t.Fatalf("ETA = %ds, oczekiwano ~90s", eta)
	}

	// A stalled sync (no progress) must not report a finite ETA forever.
	tr2 := &syncEtaTracker{}
	tr2.observe(t0, 100000, 10000)
	if _, eta = tr2.observe(t0.Add(10*time.Second), 100000, 10001); eta != -1 {
		t.Fatalf("ETA przy zastoju = %d, oczekiwano -1", eta)
	}

	// A rewind (remaining jumps up) discards the poisoned window: the next
	// short-span sample has no estimate, then a fresh one forms.
	tr3 := &syncEtaTracker{}
	tr3.observe(t0, 100000, 100)
	if _, eta = tr3.observe(t0.Add(time.Second), 99000, 1100); eta != -1 {
		t.Fatalf("ETA tuż po rewindzie = %d, oczekiwano -1 (okno wyczyszczone)", eta)
	}
	if _, eta = tr3.observe(t0.Add(11*time.Second), 99500, 600); eta < 10 || eta > 15 {
		t.Fatalf("ETA po odbudowie okna = %ds, oczekiwano ~12s", eta)
	}

	// Synced node: remaining 0 -> no ETA row.
	tr4 := &syncEtaTracker{}
	tr4.observe(t0, 100000, 2)
	if _, eta = tr4.observe(t0.Add(10*time.Second), 100001, 0); eta != -1 {
		t.Fatalf("ETA przy zsynchronizowanym węźle = %d, oczekiwano -1", eta)
	}
}

// TestSyncEtaTrackerWindowSlides: samples older than the window must fall out,
// so the rate follows the RECENT speed, not the whole session's average.
func TestSyncEtaTrackerWindowSlides(t *testing.T) {
	tr := &syncEtaTracker{}
	t0 := time.Now()
	// 10 minutes of slow sync (1 blk/s), then two minutes of fast sync.
	for i := 0; i <= 600; i += 10 {
		tr.observe(t0.Add(time.Duration(i)*time.Second), 100000+int64(i), 50000-int64(i))
	}
	base := int64(600)
	var rate float64
	for i := int64(10); i <= 120; i += 10 {
		rate, _ = tr.observe(t0.Add(time.Duration(base+i)*time.Second),
			100000+base+100*i, 50000-base-100*i)
	}
	if rate < 95 {
		t.Fatalf("tempo po zmianie prędkości = %.1f blk/s, oczekiwano ~100 (stare próbki poza oknem)", rate)
	}
}

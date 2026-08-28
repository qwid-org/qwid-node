package logger

import (
	"bytes"
	"fmt"
	"log"
	"strings"
	"sync"
	"testing"
	"time"
)

// safeBuffer collects output; the drain goroutine writes to it while the test
// reads.
type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *safeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *safeBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// blockingWriter stands in for a slow disk or an undrained stdout — the
// condition that made synchronous logging stop block production.
type blockingWriter struct{ release chan struct{} }

func (w *blockingWriter) Write(p []byte) (int, error) {
	<-w.release
	return len(p), nil
}

// The property the whole change exists for: logging must never block the
// caller, however slow the destination is. This is asserted against a writer
// that never completes — the pathological case of the disk or terminal stall
// that put latency into the node's receive loop.
func TestWriteNeverBlocksOnASlowDestination(t *testing.T) {
	blocked := &blockingWriter{release: make(chan struct{})}
	defer close(blocked.release)
	w := newAsyncWriter(blocked)

	// Far more lines than the queue holds, so the queue is certainly full and
	// the destination is certainly stuck.
	start := time.Now()
	for i := 0; i < asyncQueueDepth*3; i++ {
		if _, err := w.Write([]byte("a log line\n")); err != nil {
			t.Fatalf("Write reported an error: %v", err)
		}
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("writing took %v against a stalled destination — the caller was blocked", elapsed)
	}
	if w.dropped.Load() == 0 {
		t.Fatal("nothing was recorded as dropped, so the queue silently swallowed the overflow")
	}
}

// A gap in the log must never be silent: a reader who cannot tell that lines
// are missing will draw conclusions from evidence that was never complete.
func TestDroppedLinesAreReported(t *testing.T) {
	out := &safeBuffer{}
	w := newAsyncWriter(out)
	w.dropped.Store(42)
	w.Flush()

	got := out.String()
	if !strings.Contains(got, "42 log line(s) dropped") {
		t.Fatalf("the suppressed count was not reported; output was %q", got)
	}
}

// log.Logger formats into a buffer it reuses between calls, so queueing the
// slice it hands over would let the next line overwrite one still waiting.
// Every line must arrive intact and exactly once.
func TestQueuedLinesAreNotCorruptedByReuse(t *testing.T) {
	out := &safeBuffer{}
	w := newAsyncWriter(out)
	lg := log.New(w, "", 0)

	const n = 500
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			lg.Printf("line-%04d-end", i)
		}(i)
	}
	wg.Wait()
	w.Flush()

	got := out.String()
	for i := 0; i < n; i++ {
		if !strings.Contains(got, fmt.Sprintf("line-%04d-end", i)) {
			t.Fatalf("line %d is missing or was corrupted by buffer reuse", i)
		}
	}
}

// Flush is what makes Fatal survive os.Exit, and it must keep working
// afterwards: a recovered panic flushes too, and a logger that went silent
// after the first flush would hide everything that followed.
func TestFlushIsRepeatable(t *testing.T) {
	out := &safeBuffer{}
	w := newAsyncWriter(out)

	w.Write([]byte("before\n"))
	w.Flush()
	if !strings.Contains(out.String(), "before") {
		t.Fatal("the first flush did not deliver the queued line")
	}

	w.Write([]byte("after\n"))
	w.Flush()
	if !strings.Contains(out.String(), "after") {
		t.Fatal("logging stopped working after a flush")
	}
}

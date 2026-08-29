package logger

import (
	"fmt"
	"io"
	"sync/atomic"
	"time"
)

// asyncWriter decouples emitting a log line from writing it out.
//
// The writers underneath are a file and stdout, both synchronous, and
// log.Logger serialises every caller through one mutex. That put disk and
// terminal latency directly inside the node's receive loop — the same loop that
// carries sync and nonce traffic — so a burst of logging at 500 TPS stopped
// block production. Logging must never be able to do that: a node that cannot
// describe what it is doing is a nuisance, one that stops validating is an
// outage.
//
// Write therefore never blocks and never fails. It hands the line to a drain
// goroutine and returns; if the queue is full the line is DROPPED and counted.
// Dropping is the deliberate choice — the alternative under sustained overload
// is unbounded memory or a blocked caller, and both are worse than a gap in the
// log that is explicitly reported.
type asyncWriter struct {
	out   io.Writer
	queue chan []byte

	dropped atomic.Int64

	// flushReq carries a request to write out everything queued and answer when
	// it has reached the underlying writers. It is a repeatable handshake
	// rather than a one-shot close: a recovered panic must leave the logger
	// working, and a Flush that killed the drain goroutine would silently stop
	// all logging from that point on.
	flushReq chan chan struct{}
}

// asyncQueueDepth is how many lines may be in flight. Deep enough to absorb the
// bursts that motivated this (thousands of messages while a full pool drains),
// small enough that the backlog cannot grow into a memory problem.
const asyncQueueDepth = 8192

func newAsyncWriter(out io.Writer) *asyncWriter {
	w := &asyncWriter{
		out:      out,
		queue:    make(chan []byte, asyncQueueDepth),
		flushReq: make(chan chan struct{}),
	}
	go w.drain()
	return w
}

func (w *asyncWriter) Write(p []byte) (int, error) {
	// log.Logger reuses its formatting buffer across calls, so the bytes handed
	// here are only valid until this call returns. Queueing the slice itself
	// would let the next log line rewrite a message still waiting to be
	// written — a copy is not optional.
	line := make([]byte, len(p))
	copy(line, p)

	select {
	case w.queue <- line:
	default:
		w.dropped.Add(1)
	}
	// Always report success: a logging failure must not propagate into callers
	// that are doing real work, and there is nothing they could do about it.
	return len(p), nil
}

func (w *asyncWriter) drain() {
	// Report suppressed lines periodically, so a gap in the log is never
	// silent. A log that quietly loses messages is worse than one that stops:
	// it invites conclusions drawn from evidence that was never complete.
	report := time.NewTicker(5 * time.Second)
	defer report.Stop()

	for {
		select {
		case line := <-w.queue:
			w.out.Write(line)
		case <-report.C:
			w.reportDropped()
		case ack := <-w.flushReq:
			for {
				stop := false
				select {
				case line := <-w.queue:
					w.out.Write(line)
				default:
					stop = true
				}
				if stop {
					break
				}
			}
			w.reportDropped()
			close(ack)
		}
	}
}

func (w *asyncWriter) reportDropped() {
	if n := w.dropped.Swap(0); n > 0 {
		fmt.Fprintf(w.out, "WARNING: %d log line(s) dropped: the logger could not keep up and discarded them rather than block the node\n", n)
	}
}

// Flush writes everything already queued and waits for it to reach the
// underlying writers. Called before the process exits — os.Exit does not run
// deferred work or let goroutines finish, so without this the very last
// message, which on a Fatal is the reason the node died, would be the one
// message guaranteed to be lost.
//
// The wait is bounded: a logger that cannot drain must not be what stops a node
// from exiting.
func (w *asyncWriter) Flush() {
	ack := make(chan struct{})
	select {
	case w.flushReq <- ack:
	case <-time.After(flushTimeout):
		return
	}
	select {
	case <-ack:
	case <-time.After(flushTimeout):
	}
}

const flushTimeout = 2 * time.Second

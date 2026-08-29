package logger

import (
	"fmt"
	"log"
	"os"
	"strings"
)

// Logger wraps log.Logger so that the calls which END the process flush the
// queue first.
//
// This exists only because of asynchronous writing. log.Fatal writes and then
// calls os.Exit, which runs no deferred work and does not wait for goroutines:
// with a queue in between, the message explaining why the node died would be
// the single message most likely to be lost. Print-style calls stay exactly as
// they were — enqueue and return.
//
// The method set is the one the codebase actually uses (Println, Printf, Print,
// Fatal, Fatalf, Fatalln, Panic, Panicf, Panicln), so no call site changes.
type Logger struct {
	l *log.Logger
	// w is nil when logging is disabled, and flush is then a no-op.
	w *asyncWriter
}

func (lg *Logger) flush() {
	if lg.w != nil {
		lg.w.Flush()
	}
}

// blank reports whether a formatted message carries nothing. A line that is
// only a timestamp costs a reader attention and gives back nothing, and the
// usual source is a variable that happened to be empty rather than a
// deliberate separator — so it is dropped at the one place that sees every
// message, instead of being chased through a thousand call sites.
//
// Note this suppresses the LINE, not just its content: the timestamp prefix is
// added by log.Logger after this point, so a skipped message produces no
// output at all rather than a bare prefix.
func blank(s string) bool {
	return strings.TrimSpace(s) == ""
}

// The Print family reproduces log.Logger's own formatting exactly — Println
// uses Sprintln, Print uses Sprint, Printf uses Sprintf — because the message
// has to be built here in order to be judged empty.
func (lg *Logger) Println(v ...interface{}) {
	if s := fmt.Sprintln(v...); !blank(s) {
		lg.l.Output(2, s)
	}
}

func (lg *Logger) Print(v ...interface{}) {
	if s := fmt.Sprint(v...); !blank(s) {
		lg.l.Output(2, s)
	}
}

func (lg *Logger) Printf(format string, v ...interface{}) {
	if s := fmt.Sprintf(format, v...); !blank(s) {
		lg.l.Output(2, s)
	}
}

func (lg *Logger) Fatal(v ...interface{}) {
	lg.l.Output(2, fmt.Sprint(v...))
	lg.flush()
	os.Exit(1)
}

func (lg *Logger) Fatalf(format string, v ...interface{}) {
	lg.l.Output(2, fmt.Sprintf(format, v...))
	lg.flush()
	os.Exit(1)
}

func (lg *Logger) Fatalln(v ...interface{}) {
	lg.l.Output(2, fmt.Sprintln(v...))
	lg.flush()
	os.Exit(1)
}

// Panic variants flush before panicking: the panic may be recovered, but it may
// equally take the process down, and the queued explanation must survive either
// way. Flush is a repeatable handshake, so logging still works if the panic is
// recovered.
func (lg *Logger) Panic(v ...interface{}) {
	s := fmt.Sprint(v...)
	lg.l.Output(2, s)
	lg.flush()
	panic(s)
}

func (lg *Logger) Panicf(format string, v ...interface{}) {
	s := fmt.Sprintf(format, v...)
	lg.l.Output(2, s)
	lg.flush()
	panic(s)
}

func (lg *Logger) Panicln(v ...interface{}) {
	s := fmt.Sprintln(v...)
	lg.l.Output(2, s)
	lg.flush()
	panic(s)
}

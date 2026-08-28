package logger

import (
	"fmt"
	"log"
	"os"
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

func (lg *Logger) Println(v ...interface{}) { lg.l.Println(v...) }
func (lg *Logger) Print(v ...interface{})   { lg.l.Print(v...) }

func (lg *Logger) Printf(format string, v ...interface{}) { lg.l.Printf(format, v...) }

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

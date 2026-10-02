package logger

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// S9-05: swapping the file writer during rotation must not race with the
// async writer goroutine (run under -race).
func TestMultiWriterSwapIsRaceFree(t *testing.T) {
	var a, b bytes.Buffer
	m := &MultiWriter{writers: []io.Writer{&bytes.Buffer{}, &a}}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			m.Write([]byte("x"))
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			m.setWriter(1, &b)
		}
	}()
	wg.Wait()
}

// S9-05: daily files rotate at midnight, not 24 h after start.
func TestUntilMidnight(t *testing.T) {
	now := time.Date(2026, 10, 2, 23, 30, 0, 0, time.Local)
	if d := untilMidnight(now); d != 30*time.Minute {
		t.Fatalf("until midnight = %v", d)
	}
}

// S9-05: log files hold peer addresses and accounts; owner-only.
func TestLogFilePermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "logs")
	f, err := openLogFile(dir, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	fi, _ := f.Stat()
	di, _ := os.Stat(dir)
	if fi.Mode().Perm() != 0o600 || di.Mode().Perm() != 0o700 {
		t.Fatalf("file %v dir %v", fi.Mode().Perm(), di.Mode().Perm())
	}
}

// S9-05: reading keeps only the requested window, newest first.
func TestReadLogFileWindow(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mining-x.log")
	var buf bytes.Buffer
	for i := 0; i < 5000; i++ {
		tag := "info"
		if i%2 == 0 {
			tag = "warn"
		}
		fmt.Fprintf(&buf, "line %d %s\n", i, tag)
	}
	os.WriteFile(path, buf.Bytes(), 0o600)
	lines, total, err := ReadLogFile(path, "warn", 1, 3)
	if err != nil || total != 2500 {
		t.Fatalf("total=%d err=%v", total, err)
	}
	want := []string{"line 4996 warn", "line 4994 warn", "line 4992 warn"}
	if len(lines) != 3 || lines[0] != want[0] || lines[2] != want[2] {
		t.Fatalf("lines=%q", lines)
	}
}

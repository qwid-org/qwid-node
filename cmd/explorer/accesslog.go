package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Access log for the requests that reach the explorer DIRECTLY.
//
// HTTPS arrives through nginx, which logs it (/var/log/nginx/access.log) and
// connects from loopback. WAN port 80, however, is forwarded straight to this
// process (deploy/TLS-explorer.md), so that traffic was in no log at all. This
// middleware records every request whose connection is NOT from loopback - the
// direct ones - in the same Apache/nginx "combined" format, so
// www/deploy/explorer-traffic-stats.py and GoAccess read both logs alike and
// nothing is counted twice.
//
// One file per day, explorer-access-YYYY-MM-DD.log, in
// EXPLORER_ACCESS_LOG_DIR (default ~/.qwid/logs/explorer); files older than
// EXPLORER_ACCESS_LOG_DAYS (default 90) are removed when a new day starts.
// EXPLORER_ACCESS_LOG=off disables it.

const accessLogPrefix = "explorer-access-"

type accessLog struct {
	dir      string
	keepDays int
	now      func() time.Time

	mu   sync.Mutex
	day  string
	file *os.File
	warn sync.Once
}

func newAccessLogFromEnv() *accessLog {
	if strings.EqualFold(os.Getenv("EXPLORER_ACCESS_LOG"), "off") {
		return nil
	}
	dir := os.Getenv("EXPLORER_ACCESS_LOG_DIR")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Println("explorer access log disabled: no home directory:", err)
			return nil
		}
		dir = filepath.Join(home, ".qwid", "logs", "explorer")
	}
	keep := 90
	if v := os.Getenv("EXPLORER_ACCESS_LOG_DAYS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			keep = n
		}
	}
	return &accessLog{dir: dir, keepDays: keep, now: time.Now}
}

// middleware logs each direct request after it is served.
func (l *accessLog) middleware(next http.Handler) http.Handler {
	if l == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			next.ServeHTTP(w, r) // via nginx: already in its log
			return
		}
		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		l.write(host, r, rec.status(), rec.size)
	})
}

func (l *accessLog) write(ip string, r *http.Request, status int, size int64) {
	t := l.now()
	line := fmt.Sprintf("%s - - [%s] \"%s %s %s\" %d %d \"%s\" \"%s\"\n",
		ip, t.Format("02/Jan/2006:15:04:05 -0700"),
		logField(r.Method), logField(r.RequestURI), logField(r.Proto),
		status, size, logField(r.Referer()), logField(r.UserAgent()))

	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.openFor(t); err != nil {
		l.warn.Do(func() { fmt.Println("explorer access log not written:", err) })
		return
	}
	_, _ = l.file.WriteString(line)
}

// openFor makes l.file the file of t's day, pruning old days on a change.
func (l *accessLog) openFor(t time.Time) error {
	day := t.Format("2006-01-02")
	if l.file != nil && l.day == day {
		return nil
	}
	if err := os.MkdirAll(l.dir, 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(l.dir, accessLogPrefix+day+".log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if l.file != nil {
		_ = l.file.Close()
	}
	l.file, l.day = f, day
	l.prune(t)
	return nil
}

func (l *accessLog) prune(t time.Time) {
	cutoff := t.AddDate(0, 0, -l.keepDays).Format("2006-01-02")
	entries, err := os.ReadDir(l.dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, accessLogPrefix) || !strings.HasSuffix(name, ".log") {
			continue
		}
		day := strings.TrimSuffix(strings.TrimPrefix(name, accessLogPrefix), ".log")
		if len(day) == len("2006-01-02") && day < cutoff {
			_ = os.Remove(filepath.Join(l.dir, name))
		}
	}
}

// logField makes a client-supplied value safe inside a quoted log field: it
// escapes quotes and backslashes and replaces control characters, so a
// request cannot end the field or forge a log line.
func logField(s string) string {
	if s == "" {
		return "-"
	}
	var b strings.Builder
	for _, c := range s {
		switch {
		case c == '"' || c == '\\':
			b.WriteByte('\\')
			b.WriteRune(c)
		case c < 0x20 || c == 0x7f:
			fmt.Fprintf(&b, "\\x%02x", c)
		default:
			b.WriteRune(c)
		}
	}
	return b.String()
}

// statusRecorder captures the status code and body size of a response.
type statusRecorder struct {
	http.ResponseWriter
	code int
	size int64
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.code == 0 {
		s.code = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.code == 0 {
		s.code = http.StatusOK
	}
	n, err := s.ResponseWriter.Write(b)
	s.size += int64(n)
	return n, err
}

func (s *statusRecorder) status() int {
	if s.code == 0 {
		return http.StatusOK
	}
	return s.code
}

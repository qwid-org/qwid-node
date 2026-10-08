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
//
// A request flood from many addresses must not fill the disk (audit
// 2026-10-07 F1-04): a day's file stops growing at EXPLORER_ACCESS_LOG_MAX_MB
// (default 256) - later requests that day are served but not logged, with one
// warning on stdout - and client-supplied fields are cut to a fixed length, so
// one request cannot write an 8 KB line.

const (
	accessLogPrefix = "explorer-access-"
	// maxURILen and maxHeaderFieldLen bound the client-supplied fields of a
	// line; a cut field ends in "...".
	maxURILen         = 2048
	maxHeaderFieldLen = 512
	defaultMaxDayMB   = 256
)

type accessLog struct {
	dir         string
	keepDays    int
	maxDayBytes int64
	now         func() time.Time

	mu      sync.Mutex
	day     string
	file    *os.File
	written int64 // size of the current day's file
	full    bool  // the day's cap was reached and reported
	warn    sync.Once
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
	maxMB := int64(defaultMaxDayMB)
	if v := os.Getenv("EXPLORER_ACCESS_LOG_MAX_MB"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			maxMB = n
		}
	}
	return &accessLog{dir: dir, keepDays: keep, maxDayBytes: maxMB << 20, now: time.Now}
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
		logField(r.Method, maxHeaderFieldLen), logField(r.RequestURI, maxURILen), logField(r.Proto, maxHeaderFieldLen),
		status, size, logField(r.Referer(), maxHeaderFieldLen), logField(r.UserAgent(), maxHeaderFieldLen))

	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.openFor(t); err != nil {
		l.warn.Do(func() { fmt.Println("explorer access log not written:", err) })
		return
	}
	if l.maxDayBytes > 0 && l.written+int64(len(line)) > l.maxDayBytes {
		if !l.full {
			l.full = true
			fmt.Printf("explorer access log for %s reached %d MB - not logging more requests today\n", l.day, l.maxDayBytes>>20)
		}
		return
	}
	n, _ := l.file.WriteString(line)
	l.written += int64(n)
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
	var size int64
	if st, err := f.Stat(); err == nil {
		size = st.Size() // a restart continues today's file and its budget
	}
	if l.file != nil {
		_ = l.file.Close()
	}
	l.file, l.day, l.written, l.full = f, day, size, false
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
// request cannot end the field or forge a log line. Values longer than max
// bytes are cut and end in "...".
func logField(s string, max int) string {
	if s == "" {
		return "-"
	}
	cut := false
	if len(s) > max {
		s, cut = s[:max], true
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
	if cut {
		b.WriteString("...")
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

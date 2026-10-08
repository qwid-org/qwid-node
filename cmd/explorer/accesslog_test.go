package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testAccessLog(t *testing.T, now time.Time) *accessLog {
	t.Helper()
	return &accessLog{dir: t.TempDir(), keepDays: 90, now: func() time.Time { return now }}
}

func serve(l *accessLog, remote, target string, hdr map[string]string) {
	h := l.middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("nope"))
	}))
	r := httptest.NewRequest("GET", target, nil)
	r.RemoteAddr = remote
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	h.ServeHTTP(httptest.NewRecorder(), r)
}

func readLog(t *testing.T, l *accessLog, day string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(l.dir, accessLogPrefix+day+".log"))
	if err != nil {
		return ""
	}
	return string(b)
}

// Direct requests are logged in combined format; nginx-forwarded (loopback)
// ones are not, since nginx logs them itself.
func TestAccessLogRecordsOnlyDirectRequests(t *testing.T) {
	now := time.Date(2026, 10, 7, 12, 30, 0, 0, time.FixedZone("CEST", 2*3600))
	l := testAccessLog(t, now)
	serve(l, "127.0.0.1:5555", "/api/stats", nil)
	serve(l, "203.0.113.9:4444", "/.env?x=1", map[string]string{"User-Agent": "curl/8", "Referer": "http://x/"})

	got := readLog(t, l, "2026-10-07")
	want := `203.0.113.9 - - [07/Oct/2026:12:30:00 +0200] "GET /.env?x=1 HTTP/1.1" 404 4 "http://x/" "curl/8"` + "\n"
	if got != want {
		t.Fatalf("log =\n%q\nwant\n%q", got, want)
	}
}

// A client cannot break out of a quoted field or forge a second line.
func TestAccessLogEscapesClientFields(t *testing.T) {
	l := testAccessLog(t, time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC))
	serve(l, "203.0.113.9:1", "/", map[string]string{"User-Agent": "evil\" \"x\n1.2.3.4 - - [fake]"})
	got := readLog(t, l, "2026-10-07")
	if strings.Count(got, "\n") != 1 || !strings.Contains(got, `"evil\" \"x\x0a1.2.3.4 - - [fake]"`) {
		t.Fatalf("unescaped field: %q", got)
	}
}

// One file per day; days older than keepDays are removed.
func TestAccessLogRotatesAndPrunes(t *testing.T) {
	day := time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)
	l := testAccessLog(t, day)
	l.keepDays = 2
	old := filepath.Join(l.dir, accessLogPrefix+"2026-10-01.log")
	keep := filepath.Join(l.dir, accessLogPrefix+"2026-10-06.log")
	for _, f := range []string{old, keep} {
		if err := os.WriteFile(f, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	serve(l, "203.0.113.9:1", "/a", nil)
	l.now = func() time.Time { return day.AddDate(0, 0, 1) }
	serve(l, "203.0.113.9:1", "/b", nil)

	if readLog(t, l, "2026-10-07") == "" || !strings.Contains(readLog(t, l, "2026-10-08"), "/b") {
		t.Fatal("expected one file per day")
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatal("a file older than keepDays was kept")
	}
	if _, err := os.Stat(keep); err != nil {
		t.Fatal("a recent file was removed")
	}
}

// Audit 2026-10-07 F1-04: a day's file stops at its size cap, and a long
// client-supplied field is cut, so a flood cannot fill the disk.
func TestAccessLogIsBounded(t *testing.T) {
	l := testAccessLog(t, time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC))
	l.maxDayBytes = 2000
	serve(l, "203.0.113.9:1", "/"+strings.Repeat("a", 5000), map[string]string{"User-Agent": strings.Repeat("u", 5000)})
	got := readLog(t, l, "2026-10-07")
	if got != "" {
		t.Fatalf("a %d-byte line over a 2000-byte cap was written", len(got))
	}

	l.maxDayBytes = 1 << 20
	serve(l, "203.0.113.9:1", "/"+strings.Repeat("a", 5000), map[string]string{"User-Agent": strings.Repeat("u", 5000)})
	got = readLog(t, l, "2026-10-07")
	if len(got) > maxURILen+maxHeaderFieldLen+300 || !strings.Contains(got, "a...") || !strings.Contains(got, "u...") {
		t.Fatalf("long fields were not cut: %d bytes", len(got))
	}

	l.maxDayBytes = int64(len(got)) * 3
	for i := 0; i < 10; i++ {
		serve(l, "203.0.113.9:1", "/x", nil)
	}
	if size := int64(len(readLog(t, l, "2026-10-07"))); size > l.maxDayBytes {
		t.Fatalf("file grew to %d bytes past its %d-byte cap", size, l.maxDayBytes)
	}
}

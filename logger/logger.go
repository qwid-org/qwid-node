package logger

import (
	"bufio"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var DefaultLogsHomePath = "/.qwid/logs/"

// LoggingEnabled controls whether logging is active (set to false to disable all logs)
var LoggingEnabled = true

var (
	logFile *os.File
	mw      *MultiWriter
	logger  *Logger
	async   *asyncWriter
	once    sync.Once
)

type MultiWriter struct {
	mu      sync.Mutex // rotation swaps a writer while the async goroutine writes (S9-05)
	writers []io.Writer
}

func (t *MultiWriter) setWriter(i int, w io.Writer) {
	t.mu.Lock()
	t.writers[i] = w
	t.mu.Unlock()
}

func (t *MultiWriter) Write(p []byte) (n int, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, w := range t.writers {
		n, err = w.Write(p)
		if err != nil {
			return
		}
		if n != len(p) {
			err = io.ErrShortWrite
			return
		}
	}
	return len(p), nil
}

func InitLogger() {
	once.Do(func() {
		// If logging is disabled, use discard writer
		if !LoggingEnabled {
			mw = &MultiWriter{
				writers: []io.Writer{io.Discard},
			}
			logger = &Logger{l: log.New(io.Discard, "", 0)}
			log.SetOutput(io.Discard)
			return
		}

		homePath, err := os.UserHomeDir()
		if err != nil {
			log.Fatal(err)
		}
		logsDir := filepath.Join(homePath, DefaultLogsHomePath)
		// Assign the package-level logFile (S9-05): ":=" here declared a local
		// one, so CloseLogger and the first rotation never closed the file.
		logFile, err = openLogFile(logsDir, time.Now())
		if err != nil {
			log.Fatal(err)
		}
		mw = &MultiWriter{
			writers: []io.Writer{
				os.Stdout,
				logFile,
			},
		}
		// Everything below writes through the async queue, so no log call can
		// put file or terminal latency into the node's network path.
		async = newAsyncWriter(mw)
		logger = &Logger{l: log.New(async, "", log.LstdFlags), w: async}
		log.SetOutput(async)
		log.SetFlags(log.LstdFlags)
		// Start cleanup routine
		go cleanupOldLogs(logsDir)
	})
}

func GetLogger() *Logger {
	InitLogger()
	return logger
}

func CloseLogger() {
	// Order matters: drain the queue into the file before closing it, or a
	// clean shutdown loses whatever was still in flight.
	if async != nil {
		async.Flush()
	}
	if logFile != nil {
		logFile.Close()
	}
}

// openLogFile opens today's log file. Logs carry peer addresses, accounts
// and transaction hashes, so the directory and files are owner-only (S9-05);
// existing ones are tightened too, since the mode only applies on creation.
func openLogFile(logsDir string, now time.Time) (*os.File, error) {
	if err := os.MkdirAll(logsDir, 0o700); err != nil {
		return nil, err
	}
	_ = os.Chmod(logsDir, 0o700)
	path := filepath.Join(logsDir, "mining-"+now.Format("2006-01-02")+".log")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	_ = f.Chmod(0o600)
	return f, nil
}

// untilMidnight is the wait until the next local midnight, so each daily
// file holds one calendar day (rotation used to run 24 h after start).
func untilMidnight(now time.Time) time.Duration {
	y, m, d := now.Date()
	return time.Date(y, m, d+1, 0, 0, 0, 0, now.Location()).Sub(now)
}

// cleanupOldLogs removes log files older than 7 days
func cleanupOldLogs(logsDir string) {
	for {
		time.Sleep(untilMidnight(time.Now()))
		rotateLogFile(logsDir)
		// Get all log files
		files, err := filepath.Glob(filepath.Join(logsDir, "mining-*.log"))
		if err != nil {
			log.Printf("Error getting log files: %v", err)
			continue
		}
		// Remove files older than 7 days
		for _, file := range files {
			info, err := os.Stat(file)
			if err != nil {
				log.Printf("Error getting file info: %v", err)
				continue
			}
			if time.Since(info.ModTime()) > 7*24*time.Hour {
				if err := os.Remove(file); err != nil {
					log.Printf("Error removing old log file: %v", err)
				}
			}
		}
	}
}

// rotateLogFile creates a new log file for the current day
func rotateLogFile(logsDir string) {
	f, err := openLogFile(logsDir, time.Now())
	if err != nil {
		log.Printf("cannot rotate log file: %v", err)
		return
	}
	old := logFile
	mw.setWriter(1, f) // the old file is closed only once nothing writes to it
	logFile = f
	if old != nil {
		old.Close()
	}
}

// GetHomePath returns the user's home directory
func GetHomePath() string {
	homePath, err := os.UserHomeDir()
	if err != nil {
		return "/root"
	}
	return homePath
}

// GetLogFiles returns list of log files in the directory
func GetLogFiles(dir string) ([]string, error) {
	files, err := filepath.Glob(filepath.Join(dir, "mining-*.log"))
	if err != nil {
		return nil, err
	}
	// Extract just filenames and sort by date (newest first)
	result := make([]string, 0, len(files))
	for i := len(files) - 1; i >= 0; i-- {
		result = append(result, filepath.Base(files[i]))
	}
	return result, nil
}

// ReadLogFile reads a log file with optional filtering. It streams the file
// with a buffered scanner and keeps only the offset+limit newest matching
// lines (S9-05): reading byte by byte and holding every line made one request
// on a sync-sized log take minutes and hundreds of MB.
func ReadLogFile(path, filter string, offset, limit int) ([]string, int, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer file.Close()
	if offset < 0 {
		offset = 0
	}
	if limit < 0 {
		limit = 0
	}
	keep := offset + limit
	ring := make([]string, 0, min(keep, 4096))
	next, total := 0, 0
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if filter != "" && !strings.Contains(line, filter) {
			continue
		}
		total++
		if keep == 0 {
			continue
		}
		if len(ring) < keep {
			ring = append(ring, line)
		} else {
			ring[next] = line
			next = (next + 1) % keep
		}
	}
	// ring holds the newest min(total, keep) lines, oldest at index next.
	ordered := make([]string, 0, len(ring))
	for i := 0; i < len(ring); i++ {
		ordered = append(ordered, ring[(next+i)%len(ring)])
	}
	lines := []string{}
	for i := len(ordered) - 1 - offset; i >= 0 && len(lines) < limit; i-- {
		lines = append(lines, ordered[i])
	}
	return lines, total, scanner.Err()
}

package logger

import (
	"io"
	"log"
	"os"
	"path/filepath"
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
	writers []io.Writer
}

func (t *MultiWriter) Write(p []byte) (n int, err error) {
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

		if err := os.MkdirAll(logsDir, 0755); err != nil {
			log.Fatal(err)
		}
		// Create daily log file
		timestamp := time.Now().Format("2006-01-02")
		logFilePath := filepath.Join(logsDir, "mining-"+timestamp+".log")
		logFile, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
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

// cleanupOldLogs removes log files older than 7 days
func cleanupOldLogs(logsDir string) {
	for {
		time.Sleep(24 * time.Hour) // Run cleanup once per day
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
	if logFile != nil {
		logFile.Close()
	}
	var err error
	timestamp := time.Now().Format("2006-01-02")
	logFilePath := filepath.Join(logsDir, "mining-"+timestamp+".log")
	logFile, err = os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Fatal(err)
	}
	mw.writers[1] = logFile
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

// ReadLogFile reads a log file with optional filtering
func ReadLogFile(path, filter string, offset, limit int) ([]string, int, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer file.Close()

	var lines []string
	var allLines []string
	scanner := newScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		// Apply filter if specified
		if filter == "" || containsFilter(line, filter) {
			allLines = append(allLines, line)
		}
	}

	totalLines := len(allLines)

	// Apply offset and limit (from end for most recent logs)
	if offset >= totalLines {
		return []string{}, totalLines, nil
	}

	// Get lines from the end (most recent first)
	start := totalLines - offset - limit
	if start < 0 {
		start = 0
	}
	end := totalLines - offset

	for i := end - 1; i >= start; i-- {
		lines = append(lines, allLines[i])
	}

	return lines, totalLines, scanner.Err()
}

func newScanner(file *os.File) *lineScanner {
	return &lineScanner{file: file, buf: make([]byte, 0, 64*1024)}
}

type lineScanner struct {
	file *os.File
	buf  []byte
	line string
	err  error
	pos  int64
}

func (s *lineScanner) Scan() bool {
	s.buf = s.buf[:0]
	for {
		b := make([]byte, 1)
		n, err := s.file.Read(b)
		if n == 0 || err != nil {
			if len(s.buf) > 0 {
				s.line = string(s.buf)
				return true
			}
			s.err = err
			if err == io.EOF {
				s.err = nil
			}
			return false
		}
		if b[0] == '\n' {
			s.line = string(s.buf)
			return true
		}
		s.buf = append(s.buf, b[0])
	}
}

func (s *lineScanner) Text() string {
	return s.line
}

func (s *lineScanner) Err() error {
	return s.err
}

func containsFilter(line, filter string) bool {
	return stringContains(line, filter)
}

func stringContains(s, substr string) bool {
	return indexOf(s, substr) >= 0
}

func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

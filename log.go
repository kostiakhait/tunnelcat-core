// Copyright (c) 2026 Konstantin Khait

package core

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	logMaxBytes   = 10 * 1024 * 1024  // 10 MB per file before rotation
	logTotalBytes = 200 * 1024 * 1024 // 200 MB total across all log files
	logKeepDays   = 7
	logRingSize   = 256 << 10 // 256 KB in-memory ring buffer for log upload

	tunLogMaxBytes   = 2 * 1024 * 1024  // 2 MB per tun-traffic log file
	tunLogTotalBytes = 20 * 1024 * 1024 // 20 MB total across all tun-traffic log files
	tunLogKeepDays   = 3
)

// LogRing is a circular buffer that captures recent log output for upload.
// It is populated by InitLogging and read by LogUploader.
var LogRing = newRingBuffer(logRingSize)

// Version is set at build time via -ldflags "-X github.com/kostiakhait/tunnelcat-core.Version=202604120936".
// Format: YYYYMMDDHHmm. Defaults to "dev" when not set.
var Version = "dev"

// Log is the package-level logger. Initialised by InitLogging; falls back to
// stderr if InitLogging has not been called.
var Log = log.New(os.Stderr, "[tunnelcat] ", log.LstdFlags|log.Lmsgprefix)

// TunLog logs every TCP/UDP connection entering the TUN interface.
// Initialised by InitTunLogging; discards output until then.
var TunLog = log.New(io.Discard, "", log.LstdFlags)

// InitLogging opens (or creates) today's log file in dir, redirects the
// package logger there, and prunes old log files.
// Call once from main before anything else.
func InitLogging(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("log dir: %w", err)
	}

	pruneLogFiles(dir, "snc_", logMaxBytes, logTotalBytes, logKeepDays)

	rw, err := newRotatingWriter(dir, "snc_", logMaxBytes, logTotalBytes, logKeepDays)
	if err != nil {
		return err
	}

	tee := io.MultiWriter(rw, LogRing)
	Log.SetOutput(tee)
	log.SetOutput(tee)
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)

	Log.Printf("=== tunnelcat-core %s started ===", Version)
	return nil
}

// InitTunLogging opens a separate rotating log file for TUN traffic.
// Call after InitLogging.
func InitTunLogging(dir string) error {
	rw, err := newRotatingWriter(dir, "snc_tun_", tunLogMaxBytes, tunLogTotalBytes, tunLogKeepDays)
	if err != nil {
		return err
	}
	TunLog.SetOutput(rw)
	return nil
}

// ── Rotating writer ───────────────────────────────────────────────────────────

type rotatingWriter struct {
	mu         sync.Mutex
	dir        string
	prefix     string
	maxBytes   int64
	totalBytes int64
	keepDays   int
	f          *os.File
	written    int64
}

func newRotatingWriter(dir, prefix string, maxBytes, totalBytes int64, keepDays int) (*rotatingWriter, error) {
	rw := &rotatingWriter{dir: dir, prefix: prefix, maxBytes: maxBytes, totalBytes: totalBytes, keepDays: keepDays}
	if err := rw.openNew(); err != nil {
		return nil, err
	}
	return rw, nil
}

func (rw *rotatingWriter) Write(p []byte) (int, error) {
	rw.mu.Lock()

	if rw.written+int64(len(p)) > rw.maxBytes {
		_ = rw.f.Close()
		if err := rw.openNewLocked(); err != nil {
			rw.mu.Unlock()
			// Rotation failed; old file is closed. Fall back to stderr so the
			// message is not lost, then return as if written (avoid log.Printf loops).
			_, werr := os.Stderr.Write(p)
			return len(p), werr
		}
		// Prune in a goroutine to avoid deadlock (pruneLogFiles may call Log.Printf → Write).
		dir, prefix, maxB, total, days := rw.dir, rw.prefix, rw.maxBytes, rw.totalBytes, rw.keepDays
		go pruneLogFiles(dir, prefix, maxB, total, days)
	}

	n, err := rw.f.Write(p)
	rw.written += int64(n)
	rw.mu.Unlock()
	return n, err
}

func (rw *rotatingWriter) openNew() error {
	rw.mu.Lock()
	defer rw.mu.Unlock()
	return rw.openNewLocked()
}

func (rw *rotatingWriter) openNewLocked() error {
	name := filepath.Join(rw.dir,
		rw.prefix+time.Now().Format("2006-01-02_150405")+".log")
	f, err := os.OpenFile(name, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("log rotate: %w", err)
	}
	if fi, err := f.Stat(); err == nil {
		rw.written = fi.Size()
	} else {
		rw.written = 0
	}
	rw.f = f
	return nil
}

var _ io.Writer = (*rotatingWriter)(nil)

// ── Old log pruning ───────────────────────────────────────────────────────────

func pruneLogFiles(dir, prefix string, _, totalBytes int64, keepDays int) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	cutoff := time.Now().AddDate(0, 0, -keepDays)

	type logFile struct {
		path string
		size int64
		mod  time.Time
	}
	var logs []logFile
	for _, e := range entries {
		name := e.Name()
		// Require exact prefix: the character after the prefix must be a digit (start
		// of the timestamp), so "snc_" does not accidentally match "snc_tun_" files.
		if e.IsDir() || !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, ".log") {
			continue
		}
		if rest := name[len(prefix):]; len(rest) == 0 || rest[0] < '0' || rest[0] > '9' {
			continue
		}
		fi, err := os.Stat(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		logs = append(logs, logFile{filepath.Join(dir, e.Name()), fi.Size(), fi.ModTime()})
	}
	sort.Slice(logs, func(i, j int) bool { return logs[i].path < logs[j].path })

	deleted := 0

	var keep []logFile
	for _, lf := range logs {
		if lf.mod.Before(cutoff) {
			if os.Remove(lf.path) == nil {
				deleted++
			}
		} else {
			keep = append(keep, lf)
		}
	}

	var total int64
	for _, lf := range keep {
		total += lf.size
	}
	for i := 0; i < len(keep) && total > totalBytes; i++ {
		if os.Remove(keep[i].path) == nil {
			total -= keep[i].size
			deleted++
		}
	}

	if deleted > 0 {
		Log.Printf("log: pruned %d %s*.log file(s) (keep_days=%d, total_limit=%dMB)", deleted, prefix, keepDays, totalBytes>>20)
	}
}

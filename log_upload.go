// Copyright (c) 2026 Konstantin Khait

package core

import (
	"bytes"
	"compress/gzip"
	"net/http"
	"strings"
	"sync"
	"time"
)

const logUploadInterval = 5 * time.Minute

// ringBuffer is a fixed-capacity circular byte buffer that captures recent log
// output. Thread-safe; overwrites oldest data when full.
type ringBuffer struct {
	mu   sync.Mutex
	buf  []byte
	pos  int
	full bool
}

func newRingBuffer(size int) *ringBuffer {
	return &ringBuffer{buf: make([]byte, size)}
}

// Write implements io.Writer.
func (rb *ringBuffer) Write(p []byte) (int, error) {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	n := len(p)
	cap := len(rb.buf)
	if n >= cap {
		copy(rb.buf, p[n-cap:])
		rb.pos = 0
		rb.full = true
		return n, nil
	}
	end := rb.pos + n
	if end <= cap {
		copy(rb.buf[rb.pos:], p)
	} else {
		first := cap - rb.pos
		copy(rb.buf[rb.pos:], p[:first])
		copy(rb.buf, p[first:])
		rb.full = true
	}
	rb.pos = end % cap
	return n, nil
}

// Snapshot returns a linear copy of buffer contents in chronological order.
func (rb *ringBuffer) Snapshot() []byte {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	cap := len(rb.buf)
	if !rb.full {
		out := make([]byte, rb.pos)
		copy(out, rb.buf[:rb.pos])
		return out
	}
	out := make([]byte, cap)
	copy(out, rb.buf[rb.pos:])
	copy(out[cap-rb.pos:], rb.buf[:rb.pos])
	return out
}

// LogUploader periodically gzip-compresses LogRing and POSTs it to the
// control's /p/v1/log/upload endpoint via the relay API channel.
type LogUploader struct {
	srvURL string
	nodeID string
	auth   *Authenticator
	stop   chan struct{}
}

// NewLogUploader creates a LogUploader. Call Start to begin periodic uploads.
func NewLogUploader(srvURL, nodeID string, auth *Authenticator) *LogUploader {
	return &LogUploader{
		srvURL: strings.TrimRight(srvURL, "/"),
		nodeID: nodeID,
		auth:   auth,
		stop:   make(chan struct{}),
	}
}

// Start launches the background upload goroutine. Uploads once immediately,
// then every 5 minutes. Non-blocking.
func (lu *LogUploader) Start() {
	go func() {
		lu.upload()
		t := time.NewTicker(logUploadInterval)
		defer t.Stop()
		for {
			select {
			case <-lu.stop:
				return
			case <-t.C:
				lu.upload()
			}
		}
	}()
}

// Stop shuts down the upload goroutine.
func (lu *LogUploader) Stop() {
	close(lu.stop)
}

// UploadOnce performs a single log upload synchronously. Useful for testing.
func (lu *LogUploader) UploadOnce() { lu.upload() }

func (lu *LogUploader) upload() {
	snap := LogRing.Snapshot()
	if len(snap) == 0 {
		return
	}

	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	if _, err := w.Write(snap); err != nil {
		Log.Printf("log-upload: gzip write: %v", err)
		return
	}
	if err := w.Close(); err != nil {
		Log.Printf("log-upload: gzip close: %v", err)
		return
	}

	client := NewRelayAPIH1Client()
	req, err := http.NewRequest(http.MethodPost, lu.srvURL+"/p/v1/log/upload", &gz)
	if err != nil {
		Log.Printf("log-upload: build request: %v", err)
		return
	}
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Session", lu.auth.Token())
	req.Header.Set("X-Node-ID", lu.nodeID)
	req.Header.Set("X-Node-Type", "windows")
	req.Header.Set("X-SNC-Version", Version)

	resp, err := client.Do(req)
	if err != nil {
		Log.Printf("log-upload: post: %v", err)
		return
	}
	resp.Body.Close()
	Log.Printf("log-upload: sent %d bytes compressed, status=%d", gz.Len(), resp.StatusCode)
}

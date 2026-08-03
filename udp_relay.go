// Copyright (c) 2026 Konstantin Khait

package core

// UDPRelayConn multiplexes tunnel request/response over a hole-punched
// *net.UDPConn.  It acts as both a client (send relay requests to peer) and a
// server (forward incoming relay requests from peer to Control).
//
// Frame layout:
//   Request:  [4B magic][4B req_id][1B=0x01][2B path_len][path][2B token_len][token][4B body_len][body]
//   Response: [4B magic][4B req_id][1B=0x02][2B status][4B body_len][body]

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

const (
	udpRelayMagic          = uint32(0x534E4355) // 'SNCU'
	udpRelayTypeRequest    = byte(0x01)
	udpRelayTypeResponse   = byte(0x02)
	udpRelayTypeKeepalive  = byte(0x03) // keepalive ping — no forwarding, peer replies with pong
	udpRelayTypePong       = byte(0x04) // keepalive pong
	udpRelayRetries        = 3
	udpRelayTimeout        = 700 * time.Millisecond
	udpRelayMaxFrame       = 65536 // must match udpTunnelMaxFrame on the control side
	udpRelayFailThresh     = 5     // consecutive RoundTrip errors before marking as failed
	udpRelayKeepaliveEvery = 20 * time.Second
	udpRelayKeepaliveMiss  = 3 // missed pongs before marking failed
)

type udpPendingResp struct {
	status int
	body   []byte
}

// UDPRelayConn is the core P2P relay transport.
// Create with NewUDPRelayConn; call Close when done.
type UDPRelayConn struct {
	conn       *net.UDPConn
	controlURL string // forwarding target when acting as relay server
	httpClient *http.Client

	mu      sync.Mutex
	pending map[uint32]chan udpPendingResp
	rng     *rand.Rand

	failCount    atomic.Int32 // consecutive RoundTrip errors; reset on success
	failed       atomic.Bool  // set permanently when failCount >= udpRelayFailThresh
	missedPongs  atomic.Int32 // consecutive keepalive pongs not received
	successCount atomic.Int64 // total successful RoundTrips; for periodic "still alive" logging

	once   sync.Once
	stopCh chan struct{}
}

// Failed reports whether this relay has exceeded the consecutive-error threshold.
// When true, callers should fall back to TCP and request a pool rebuild.
func (c *UDPRelayConn) Failed() bool { return c.failed.Load() }

// NewUDPRelayConn wraps conn as a bidirectional relay transport.
// controlURL is the base URL used when this node forwards requests on behalf of
// a remote peer (e.g. "https://203.0.113.1:443").  Pass "" to disable server mode.
func NewUDPRelayConn(conn *net.UDPConn, controlURL string) *UDPRelayConn {
	c := &UDPRelayConn{
		conn:       conn,
		controlURL: controlURL,
		// Use uTLS (browser fingerprint + ChRelayAPI channel) so the relay's
		// outbound connections to the control are indistinguishable from a
		// browser HTTPS session to a DPI observer in censored networks.
		httpClient: NewRelayAPIH1Client(),
		pending:    make(map[uint32]chan udpPendingResp),
		rng:        rand.New(rand.NewSource(time.Now().UnixNano())),
		stopCh:     make(chan struct{}),
	}
	go c.readLoop()
	go c.keepaliveLoop()
	return c
}

func (c *UDPRelayConn) readLoop() {
	buf := make([]byte, udpRelayMaxFrame)
	for {
		c.conn.SetReadDeadline(time.Now().Add(2 * time.Second)) //nolint:errcheck
		n, err := c.conn.Read(buf)
		select {
		case <-c.stopCh:
			return
		default:
		}
		if err != nil {
			continue
		}
		data := make([]byte, n)
		copy(data, buf[:n])

		if len(data) < 9 || binary.BigEndian.Uint32(data) != udpRelayMagic {
			Log.Printf("udp-relay: dropped malformed frame (%d bytes)", n)
			continue
		}
		reqID := binary.BigEndian.Uint32(data[4:])
		typ := data[8]

		switch typ {
		case udpRelayTypeResponse:
			resp, ok := udpDecodeResponse(data)
			if !ok {
				continue
			}
			c.mu.Lock()
			ch := c.pending[reqID]
			c.mu.Unlock()
			if ch != nil {
				select {
				case ch <- resp:
				default:
				}
			}

		case udpRelayTypeRequest:
			if c.controlURL == "" {
				continue
			}
			path, token, body, ok := udpDecodeRequest(data)
			if !ok {
				continue
			}
			go c.serveRequest(reqID, path, token, body)

		case udpRelayTypeKeepalive:
			// Peer is checking the hole is alive — reply with pong.
			pong := udpEncodeKeepalive(reqID, udpRelayTypePong)
			c.conn.Write(pong) //nolint:errcheck

		case udpRelayTypePong:
			// Our keepalive was acknowledged — reset miss counter.
			c.missedPongs.Store(0)

		default:
			Log.Printf("udp-relay: unknown frame type=0x%02x reqID=%d", typ, reqID)
		}
	}
}

func (c *UDPRelayConn) serveRequest(reqID uint32, path, token string, body []byte) {
	status, respBody, err := c.forwardToControl(path, token, body)
	if err != nil {
		Log.Printf("udp-relay: forward error path=%s: %v", path, err)
		status, respBody = 503, nil
	}
	frame := udpEncodeResponse(reqID, status, respBody)
	if _, err := c.conn.Write(frame); err != nil {
		Log.Printf("udp-relay: send response: %v", err)
	}
}

func (c *UDPRelayConn) forwardToControl(path, token string, body []byte) (int, []byte, error) {
	url := c.controlURL + path
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Session", token)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	return resp.StatusCode, data, err
}

// RoundTrip sends a tunnel POST request to the relay peer and returns the
// (status, body) from Control.  Retries up to udpRelayRetries times on timeout.
func (c *UDPRelayConn) RoundTrip(path, token string, body []byte) (int, []byte, error) {
	c.mu.Lock()
	var reqID uint32
	for {
		reqID = c.rng.Uint32()
		if _, exists := c.pending[reqID]; !exists {
			break
		}
	}
	ch := make(chan udpPendingResp, 1)
	c.pending[reqID] = ch
	c.mu.Unlock()

	defer func() {
		c.mu.Lock()
		delete(c.pending, reqID)
		c.mu.Unlock()
	}()

	frame := udpEncodeRequest(reqID, path, token, body)
	for attempt := 0; attempt < udpRelayRetries; attempt++ {
		if _, err := c.conn.Write(frame); err != nil {
			c.recordFailure("write error: " + err.Error())
			return 0, nil, fmt.Errorf("udp-relay write: %w", err)
		}
		// Exponential backoff: 700ms → 1400ms → 2800ms — reduces retry storms
		// against an overloaded or rebooting control node.
		timeout := udpRelayTimeout << uint(attempt)
		select {
		case resp := <-ch:
			c.failCount.Store(0)
			// Log the first success immediately (confirms the path is alive)
			// then only every 100th after that, so a healthy relay doesn't
			// spam the log for the lifetime of the connection.
			if n := c.successCount.Add(1); n == 1 || n%100 == 0 {
				Log.Printf("udp-relay: round-trip ok path=%s success_count=%d", path, n)
			}
			return resp.status, resp.body, nil
		case <-time.After(timeout):
			Log.Printf("udp-relay: timeout attempt=%d/%d reqID=%d timeout=%s", attempt+1, udpRelayRetries, reqID, timeout)
		case <-c.stopCh:
			return 0, nil, fmt.Errorf("udp-relay: closed")
		}
	}
	c.recordFailure(fmt.Sprintf("%d retries exhausted for path=%s", udpRelayRetries, path))
	return 0, nil, fmt.Errorf("udp-relay: %d retries exhausted", udpRelayRetries)
}

// recordFailure increments the consecutive-error counter and, once it
// crosses udpRelayFailThresh, marks the connection permanently failed.
func (c *UDPRelayConn) recordFailure(reason string) {
	n := c.failCount.Add(1)
	if n >= udpRelayFailThresh {
		c.markFailed(fmt.Sprintf("%s (fail_count=%d)", reason, n))
	}
}

// markFailed sets failed=true and logs exactly once, at the actual
// false→true transition — regardless of which path (RoundTrip errors or
// missed keepalives) triggered it. Without this, a relay dying via RoundTrip
// timeouts left no log line explaining why, unlike the keepalive path.
func (c *UDPRelayConn) markFailed(reason string) {
	if !c.failed.Swap(true) {
		Log.Printf("udp-relay: marked FAILED reason=%s", reason)
	}
}

// keepaliveLoop sends periodic ping frames and marks the connection failed
// if no pong is received for udpRelayKeepaliveMiss consecutive intervals.
func (c *UDPRelayConn) keepaliveLoop() {
	ticker := time.NewTicker(udpRelayKeepaliveEvery)
	defer ticker.Stop()
	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.mu.Lock()
			reqID := c.rng.Uint32()
			c.mu.Unlock()
			ping := udpEncodeKeepalive(reqID, udpRelayTypeKeepalive)
			if _, err := c.conn.Write(ping); err != nil {
				c.recordFailure("keepalive write error: " + err.Error())
				return
			}
			if n := c.missedPongs.Add(1); n >= udpRelayKeepaliveMiss {
				c.markFailed(fmt.Sprintf("%d consecutive keepalive misses", n))
				return
			}
		}
	}
}

// StopCh returns a channel that is closed when the connection is shut down.
func (c *UDPRelayConn) StopCh() <-chan struct{} { return c.stopCh }

// Close tears down the relay connection.
func (c *UDPRelayConn) Close() {
	c.once.Do(func() {
		close(c.stopCh)
		c.conn.Close()
	})
}

// ── Frame codec ───────────────────────────────────────────────────────────────

func udpEncodeRequest(reqID uint32, path, token string, body []byte) []byte {
	pb, tb := []byte(path), []byte(token)
	buf := make([]byte, 4+4+1+2+len(pb)+2+len(tb)+4+len(body))
	o := 0
	binary.BigEndian.PutUint32(buf[o:], udpRelayMagic)
	o += 4
	binary.BigEndian.PutUint32(buf[o:], reqID)
	o += 4
	buf[o] = udpRelayTypeRequest
	o++
	binary.BigEndian.PutUint16(buf[o:], uint16(len(pb)))
	o += 2
	o += copy(buf[o:], pb)
	binary.BigEndian.PutUint16(buf[o:], uint16(len(tb)))
	o += 2
	o += copy(buf[o:], tb)
	binary.BigEndian.PutUint32(buf[o:], uint32(len(body)))
	o += 4
	copy(buf[o:], body)
	return buf
}

func udpDecodeRequest(data []byte) (path, token string, body []byte, ok bool) {
	if len(data) < 9+2+2+4 {
		return
	}
	o := 9
	pLen := int(binary.BigEndian.Uint16(data[o:]))
	o += 2
	if o+pLen+2 > len(data) {
		return
	}
	path = string(data[o : o+pLen])
	o += pLen
	tLen := int(binary.BigEndian.Uint16(data[o:]))
	o += 2
	if o+tLen+4 > len(data) {
		return
	}
	token = string(data[o : o+tLen])
	o += tLen
	bLen := int(binary.BigEndian.Uint32(data[o:]))
	o += 4
	if o+bLen > len(data) {
		return
	}
	body = data[o : o+bLen]
	ok = true
	return
}

// udpEncodeKeepalive encodes a keepalive ping or pong frame (no body).
func udpEncodeKeepalive(reqID uint32, typ byte) []byte {
	buf := make([]byte, 4+4+1)
	binary.BigEndian.PutUint32(buf[0:], udpRelayMagic)
	binary.BigEndian.PutUint32(buf[4:], reqID)
	buf[8] = typ
	return buf
}

func udpEncodeResponse(reqID uint32, status int, body []byte) []byte {
	buf := make([]byte, 4+4+1+2+4+len(body))
	o := 0
	binary.BigEndian.PutUint32(buf[o:], udpRelayMagic)
	o += 4
	binary.BigEndian.PutUint32(buf[o:], reqID)
	o += 4
	buf[o] = udpRelayTypeResponse
	o++
	binary.BigEndian.PutUint16(buf[o:], uint16(status))
	o += 2
	binary.BigEndian.PutUint32(buf[o:], uint32(len(body)))
	o += 4
	copy(buf[o:], body)
	return buf
}

func udpDecodeResponse(data []byte) (resp udpPendingResp, ok bool) {
	if len(data) < 4+4+1+2+4 {
		return
	}
	o := 9
	resp.status = int(binary.BigEndian.Uint16(data[o:]))
	o += 2
	bLen := int(binary.BigEndian.Uint32(data[o:]))
	o += 4
	if o+bLen > len(data) {
		return
	}
	resp.body = data[o : o+bLen]
	ok = true
	return
}

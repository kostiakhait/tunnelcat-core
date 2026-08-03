// Copyright (c) 2026 Konstantin Khait

package core

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/yamux"
)

// parseFirstJSON extracts the first newline-terminated JSON object from buf
// and decodes it into v.  Used by para-exit and other yamux stream handlers.
func parseFirstJSON(buf []byte, v interface{}) error {
	end := bytes.IndexByte(buf, '\n')
	if end < 0 {
		end = len(buf)
	}
	return json.Unmarshal(buf[:end], v)
}

// paraRegBody is the canonical JSON struct signed for registration.
// Must match the server-side para-exit mux struct.
type paraRegBody struct {
	NodeID string `json:"node_id"`
	TS     int64  `json:"ts"`
}

// ParaExitClient connects this win-client to every regional exit node as a
// para-exit: a yamux reverse-tunnel through which the exit can route
// whitelisted traffic using this client's residential IP.
//
// The client never knows which traffic it is carrying — it just pipes TCP
// connections to whatever target address the exit requests.  All whitelist
// enforcement is done at the exit.
//
// Lifecycle:
//
//	pc := NewParaExitClient(apiURL, localIP)
//	pc.Start()   // fetches exit list and begins connecting
//	pc.Stop()    // tears down all sessions
type ParaExitClient struct {
	apiURL  string // control base URL (https://host:443) for fetching /p/v1/para-exits
	localIP string // physical NIC IP — dials targets directly, bypassing TUN

	privKey ed25519.PrivateKey
	nodeID  string // hex(pubKey)

	active atomic.Bool
	stop   chan struct{}

	mu       sync.Mutex
	sessions []*yamux.Session
}

// NewParaExitClient generates a fresh Ed25519 identity and returns a client
// that will connect to regional exits obtained from controlAPIURL.
// localIP is the physical NIC address (bypass TUN for direct target dials).
func NewParaExitClient(controlAPIURL, localIP string) (*ParaExitClient, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("para-exit: generate key: %w", err)
	}
	return &ParaExitClient{
		apiURL:  controlAPIURL,
		localIP: localIP,
		privKey: priv,
		nodeID:  hex.EncodeToString(pub),
		stop:    make(chan struct{}),
	}, nil
}

// Start fetches the exit list and begins connecting to all regional exits.
func (c *ParaExitClient) Start() {
	c.active.Store(true)
	go c.loop()
}

// Stop tears down all para-exit sessions.
func (c *ParaExitClient) Stop() {
	if c.active.CompareAndSwap(true, false) {
		close(c.stop)
		c.mu.Lock()
		for _, s := range c.sessions {
			s.Close()
		}
		c.sessions = nil
		c.mu.Unlock()
	}
}

func (c *ParaExitClient) loop() {
	backoff := 10 * time.Second
	for c.active.Load() {
		exits, err := c.fetchExits()
		if err != nil {
			Log.Printf("para-exit: fetch exits: %v — retry in %s", err, backoff)
			select {
			case <-c.stop:
				return
			case <-time.After(backoff):
			}
			if backoff < 5*time.Minute {
				backoff *= 2
			}
			continue
		}
		backoff = 10 * time.Second

		if len(exits) == 0 {
			Log.Printf("para-exit: no regional exits — retry in 5 min")
			select {
			case <-c.stop:
				return
			case <-time.After(5 * time.Minute):
			}
			continue
		}

		// Spawn one goroutine per exit.  Each manages its own reconnect loop.
		var wg sync.WaitGroup
		childStop := make(chan struct{})
		for _, addr := range exits {
			wg.Add(1)
			go func(exitAddr string) {
				defer wg.Done()
				c.connectToExit(exitAddr, childStop)
			}(addr)
		}

		// Re-fetch the exit list hourly.
		select {
		case <-c.stop:
			close(childStop)
			wg.Wait()
			return
		case <-time.After(1 * time.Hour):
			close(childStop)
			wg.Wait()
		}
	}
}

func (c *ParaExitClient) connectToExit(exitAddr string, stop <-chan struct{}) {
	backoff := time.Second
	for {
		select {
		case <-stop:
			return
		case <-c.stop:
			return
		default:
		}
		if err := c.runSession(exitAddr, stop); err != nil {
			Log.Printf("para-exit: session to %s: %v — retry in %s", exitAddr, err, backoff)
			select {
			case <-stop:
				return
			case <-c.stop:
				return
			case <-time.After(backoff):
			}
			if backoff < 60*time.Second {
				backoff *= 2
			}
		} else {
			// Planned reconnect — no backoff.
			backoff = time.Second
		}
	}
}

func (c *ParaExitClient) runSession(exitAddr string, stop <-chan struct{}) error {
	// Dial via physical NIC to bypass TUN — the para-exit connection must NOT
	// go through the tunnel itself (that would be circular).
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	if c.localIP != "" {
		dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP(c.localIP)}
	}
	rawConn, err := dialer.Dial("tcp", exitAddr)
	if err != nil {
		return fmt.Errorf("dial %s: %w", exitAddr, err)
	}
	tlsConn, err := wrapUTLS(rawConn, ChParaExit, "")
	if err != nil {
		return fmt.Errorf("tls: %w", err)
	}

	cfg := yamux.DefaultConfig()
	cfg.LogOutput = io.Discard
	cfg.EnableKeepAlive = false // persistent yamux is a DPI signature; we reconnect periodically instead
	session, err := yamux.Client(tlsConn, cfg)
	if err != nil {
		tlsConn.Close()
		return fmt.Errorf("yamux: %w", err)
	}
	defer session.Close()

	c.mu.Lock()
	c.sessions = append(c.sessions, session)
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		for i, s := range c.sessions {
			if s == session {
				c.sessions = append(c.sessions[:i], c.sessions[i+1:]...)
				break
			}
		}
		c.mu.Unlock()
	}()

	// Registration: open first stream, send Ed25519-signed frame.
	if err := c.register(session); err != nil {
		return fmt.Errorf("register with %s: %w", exitAddr, err)
	}
	Log.Printf("para-exit: registered node_id=%.8s… exit=%s", c.nodeID, exitAddr)

	// Planned reconnect: jitter [10,30] min to avoid persistent yamux signature.
	plannedReconnect := make(chan struct{})
	reconnectAfter := 10*time.Minute + time.Duration(mrand.Intn(int(20*time.Minute)))
	go func() {
		select {
		case <-time.After(reconnectAfter):
			Log.Printf("para-exit: planned reconnect after %s (5 s grace) exit=%s",
				reconnectAfter.Round(time.Second), exitAddr)
			time.Sleep(5 * time.Second)
			close(plannedReconnect)
			session.Close()
		case <-stop:
		case <-c.stop:
		}
	}()

	// Accept yamux streams from exit; each carries one proxied connection.
	for {
		stream, err := session.AcceptStream()
		if err != nil {
			select {
			case <-plannedReconnect:
				return nil // planned reconnect — no backoff
			default:
				return fmt.Errorf("accept from %s: %w", exitAddr, err)
			}
		}
		go c.handleStream(stream)
	}
}

// register opens the first yamux stream and sends a signed registration frame.
// Frame: {"node_id":"<hex>","ts":<unix>,"sig":"<base64url>"}
// Sig covers json.Marshal(paraRegBody{NodeID,TS}).
func (c *ParaExitClient) register(session *yamux.Session) error {
	stream, err := session.OpenStream()
	if err != nil {
		return fmt.Errorf("open reg stream: %w", err)
	}
	defer stream.Close()

	ts := time.Now().Unix()
	bodyBytes, err := json.Marshal(paraRegBody{NodeID: c.nodeID, TS: ts})
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	sig := ed25519.Sign(c.privKey, bodyBytes)

	frame := map[string]interface{}{
		"node_id": c.nodeID,
		"ts":      ts,
		"sig":     base64.RawURLEncoding.EncodeToString(sig),
	}
	return json.NewEncoder(stream).Encode(frame)
}

// handleStream reads the dispatch header sent by the exit, dials the target
// directly (bypassing TUN), and pipes traffic bidirectionally.
func (c *ParaExitClient) handleStream(stream net.Conn) {
	defer stream.Close()

	// Read single-line JSON dispatch: {"target":"host:port"}
	var hdr struct {
		Target string `json:"target"`
	}
	hdrBuf := make([]byte, 256)
	stream.SetReadDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
	n, err := stream.Read(hdrBuf)
	stream.SetReadDeadline(time.Time{}) //nolint:errcheck
	if err != nil || n == 0 {
		Log.Printf("para-exit: read stream header: %v", err)
		return
	}
	if err := parseFirstJSON(hdrBuf[:n], &hdr); err != nil || hdr.Target == "" {
		Log.Printf("para-exit: bad stream header: %v", err)
		return
	}

	// Dial target directly via physical NIC — do NOT go through the tunnel.
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	if c.localIP != "" {
		dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP(c.localIP)}
	}
	target, err := dialer.Dial("tcp", hdr.Target)
	if err != nil {
		Log.Printf("para-exit: dial target %s: %v", hdr.Target, err)
		return
	}
	defer target.Close()

	Log.Printf("para-exit: proxy open → target=%s", hdr.Target)
	start := time.Now()
	done := make(chan int64, 2)
	go func() { n, _ := io.Copy(target, stream); done <- n }()
	go func() { n, _ := io.Copy(stream, target); done <- n }()
	up := <-done
	target.Close()
	stream.Close()
	down := <-done
	Log.Printf("para-exit: proxy close target=%s dur=%s up=%d down=%d bytes",
		hdr.Target, time.Since(start).Round(time.Millisecond), up, down)
}

// fetchExits calls GET /p/v1/para-exits on the control relay API and returns
// the list of exit addresses for this region.
func (c *ParaExitClient) fetchExits() ([]string, error) {
	client := newRelayAPIHTTPClient()
	resp, err := client.Get(c.apiURL + "/p/v1/para-exits")
	if err != nil {
		return nil, fmt.Errorf("GET para-exits: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("GET para-exits: status %d", resp.StatusCode)
	}
	var result struct {
		Exits []struct {
			Addr string `json:"addr"`
		} `json:"exits"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode para-exits: %w", err)
	}
	addrs := make([]string, 0, len(result.Exits))
	for _, e := range result.Exits {
		if e.Addr != "" {
			addrs = append(addrs, exitDialAddr(e.Addr))
		}
	}
	return addrs, nil
}

// exitDialAddr ensures the exit address is in host:port form.
// Exits always listen on :443 when no port is specified.
func exitDialAddr(addr string) string {
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return addr + ":443"
	}
	return addr
}

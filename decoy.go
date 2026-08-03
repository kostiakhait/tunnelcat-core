// Copyright (c) 2026 Konstantin Khait

package core

import (
	"context"
	"crypto/tls"
	"io"
	"math/rand"
	"net"
	"net/http"
	"sync"
	"syscall"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

const (
	// decoyBusyWindow: if the tunnel had activity within this interval, it is
	// considered busy and the decoy is suppressed.
	decoyBusyWindow = 500 * time.Millisecond

	// decoyDormantAfter: after this long without any tunnel activity the decoy
	// enters dormant mode (plausibly mimics a closed browser tab).
	decoyDormantAfter = 10 * time.Minute

	// Decoy fires once every 20–60 s when the tunnel is lightly loaded.
	decoyMinInterval = 20 * time.Second
	decoyMaxInterval = 60 * time.Second
)

// decoyTargets is a pool of popular CDN endpoints. Choosing a random one each
// time ensures the decoy traffic looks like ordinary browser asset requests.
var decoyTargets = []string{
	"https://cdn.jsdelivr.net/",
	"https://cdnjs.cloudflare.com/",
	"https://ajax.googleapis.com/",
	"https://fonts.googleapis.com/css2",
	"https://code.jquery.com/jquery-3.7.1.min.js",
	"https://unpkg.com/react@18/umd/react.production.min.js",
	"https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css",
	"https://d3js.org/d3.v7.min.js",
	"https://cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.21/lodash.min.js",
	"https://maxcdn.bootstrapcdn.com/font-awesome/4.7.0/css/font-awesome.min.css",
}

// DecoyManager sends background HTTPS GET requests to blend the client's TLS
// traffic pattern with normal browser activity:
//   - Tunnel busy (activity within 500 ms): silent
//   - Lightly loaded: 1–3 req/min with jitter, targeting CDN endpoints
//   - Long idle (> 10 min): dormant
//
// Outgoing connections are bound to physIP (the physical NIC address) so they
// bypass the TUN default route and go directly to the target server. Decoy
// traffic therefore does NOT consume tunnel bandwidth.
type DecoyManager struct {
	transport http.RoundTripper
	targets   []string // URL pool to pick from

	hookMu  sync.RWMutex
	lastAct time.Time

	ctx    context.Context
	cancel context.CancelFunc
}

// NewDecoyManager creates a DecoyManager. physIP is the physical NIC source
// address used to bypass TUN routing; pass "" to use default routing (tests).
func NewDecoyManager(physIP string) *DecoyManager {
	ctx, cancel := context.WithCancel(context.Background())
	return &DecoyManager{
		transport: newDecoyTransport(physIP, nil),
		targets:   decoyTargets,
		ctx:       ctx,
		cancel:    cancel,
	}
}

// NewDecoyManagerWithTransport creates a DecoyManager using a caller-supplied
// transport.  Use on platforms where TCP bypass requires a control function
// rather than LocalAddr binding (e.g. Android VpnService.protect).
func NewDecoyManagerWithTransport(transport http.RoundTripper) *DecoyManager {
	ctx, cancel := context.WithCancel(context.Background())
	return &DecoyManager{transport: transport, targets: decoyTargets, ctx: ctx, cancel: cancel}
}

// MarkActivity records that the tunnel just transmitted data.
// Call this from TunnelDialer.doPost() on every request.
func (d *DecoyManager) MarkActivity() {
	d.hookMu.Lock()
	d.lastAct = time.Now()
	d.hookMu.Unlock()
}

// Start launches the background decoy loop. Call once after creation.
func (d *DecoyManager) Start() { go d.loop() }

// Stop shuts down the decoy loop.
func (d *DecoyManager) Stop() { d.cancel() }

func (d *DecoyManager) idleSince() time.Duration {
	d.hookMu.RLock()
	t := d.lastAct
	d.hookMu.RUnlock()
	if t.IsZero() {
		return decoyDormantAfter + time.Second // no activity yet → start dormant
	}
	return time.Since(t)
}

func (d *DecoyManager) loop() {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	for {
		var wait time.Duration

		idle := d.idleSince()
		switch {
		case idle < decoyBusyWindow:
			// Tunnel is active — sleep until the busy window expires.
			wait = decoyBusyWindow - idle + 50*time.Millisecond

		case idle > decoyDormantAfter:
			// Long pause — stay dormant but keep polling in case traffic resumes.
			wait = 2 * time.Minute

		default:
			// Lightly loaded — fire a decoy, then wait 20–60 s.
			go d.fire(rng.Intn(len(d.targets)))
			wait = decoyMinInterval + time.Duration(rng.Int63n(int64(decoyMaxInterval-decoyMinInterval)))
		}

		select {
		case <-d.ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// burst fires n sequential decoy requests with short random gaps between them,
// simulating a browser loading multiple assets for a single page.
func (d *DecoyManager) burst(n int, seed int64) {
	rng := rand.New(rand.NewSource(seed))
	for i := 0; i < n; i++ {
		select {
		case <-d.ctx.Done():
			return
		default:
		}
		d.fire(rng.Intn(len(d.targets)))
		if i < n-1 {
			time.Sleep(150*time.Millisecond + time.Duration(rng.Int63n(int64(750*time.Millisecond))))
		}
	}
}

func (d *DecoyManager) fire(idx int) {
	target := d.targets[idx]
	ctx, cancel := context.WithTimeout(d.ctx, 15*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return
	}
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Cache-Control", "no-cache")

	resp, err := d.transport.RoundTrip(req)
	if err != nil {
		Log.Printf("decoy: GET %s: %v", target, err)
		return
	}
	io.Copy(io.Discard, resp.Body) //nolint:errcheck
	resp.Body.Close()
	Log.Printf("decoy: GET %s status=%d", target, resp.StatusCode)
}

// newDecoyTransport returns a uTLS-backed http.RoundTripper whose TCP
// connections are bound to physIP (bypassing TUN routing).  Unlike the tunnel
// transport, this one uses real TLS certificate verification because it
// connects to actual public servers.
// NewDecoyTransport is the exported variant for use on Android.
func NewDecoyTransport(physIP string, controlFn func(string, string, syscall.RawConn) error) http.RoundTripper {
	return newDecoyTransport(physIP, controlFn)
}

func newDecoyTransport(physIP string, controlFn func(string, string, syscall.RawConn) error) http.RoundTripper {
	var localAddr net.Addr
	if physIP != "" {
		localAddr = &net.TCPAddr{IP: net.ParseIP(physIP)}
	}

	preset := pickPreset()

	dialUTLS := func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
		dialer := &net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
			LocalAddr: localAddr,
			Control:   controlFn,
		}
		rawConn, err := dialer.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		// Use the real server hostname as SNI so certificate verification works.
		host, _, _ := net.SplitHostPort(addr)
		uconn := utls.UClient(rawConn, &utls.Config{
			ServerName: host,
		}, preset)
		if err := uconn.HandshakeContext(ctx); err != nil {
			rawConn.Close() //nolint:errcheck
			return nil, err
		}
		return uconn, nil
	}

	return &http2.Transport{
		DialTLSContext: dialUTLS,
	}
}

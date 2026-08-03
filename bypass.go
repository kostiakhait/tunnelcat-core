// Copyright (c) 2026 Konstantin Khait

package core

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// signedCIDRList is the wire format returned by GET /api/bypass/cidr on the exit.
type signedCIDRList struct {
	Country string   `json:"country"`
	TS      int64    `json:"ts"`
	CIDRs   []string `json:"cidrs"`
	Sig     string   `json:"sig"`
}

// BypassManager fetches, verifies and caches the CIDR bypass set for the
// client's country.  It calls the exit node's /api/bypass/cidr endpoint,
// passing the client's public IP so the exit can detect the country and
// return the appropriate arbiter-signed CIDR list.
//
// ShouldBypass checks each outbound address; BypassDialer returns a dialer
// bound to the original NIC so packets route around the TUN.
type BypassManager struct {
	exitURLs  []string          // control node base URLs, tried in order; updated by SetNodes
	pubkey    ed25519.PublicKey // arbiter pubkey; nil = skip verification (dev)
	cacheFile string

	mu      sync.RWMutex
	cidrs   *CIDRSet
	country string // ISO country code for the client's IP (e.g. "RU"); "" until first load
	enabled bool
	token   string // current session token; set via SetToken
	myIP    string // client's public IP; set via SetMyIP
	localIP string // original NIC IP set via SetLocalIP before Start

	// cidrSource tracks how the current CIDR set was obtained:
	// 0 = not loaded, 1 = loaded from on-disk cache, 2 = fetched live this session.
	cidrSource int32 // accessed atomically

	// failedIPs caches IPs where bypass recently failed but tunnel succeeded.
	// Entries expire after 30 min; checked in ShouldBypass to skip the bypass
	// path and go straight to the tunnel for those IPs.
	failedIPs sync.Map // IP string → expiry time.Time

	stop   chan struct{}
	client *http.Client
}

// NewBypassManager creates a BypassManager that will fetch CIDR data from the
// exit node at exitURL.
// pubkeyHex is the arbiter Ed25519 pubkey hex.
// Pass "" to skip signature verification (dev mode).
func NewBypassManager(exitURLs []string, pubkeyHex, cacheFile string) (*BypassManager, error) {
	trimmed := make([]string, len(exitURLs))
	for i, u := range exitURLs {
		trimmed[i] = strings.TrimRight(u, "/")
	}
	m := &BypassManager{
		exitURLs:  trimmed,
		cacheFile: cacheFile,
		enabled:   true,
		stop:      make(chan struct{}),
		client: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true, //nolint:gosec // exit nodes use self-signed certs
				},
			},
		},
	}
	if pubkeyHex != "" {
		b, err := hex.DecodeString(pubkeyHex)
		if err != nil || len(b) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("bypass: invalid arbiter pubkey hex")
		}
		m.pubkey = ed25519.PublicKey(b)
	}
	return m, nil
}

// SetToken records the current session token used to authenticate against the exit.
// Call this before Start, and again whenever the token is refreshed.
func (m *BypassManager) SetToken(token string) {
	m.mu.Lock()
	m.token = token
	m.mu.Unlock()
}

// SetMyIP records the client's public IP address used for country detection.
// Call this after FetchMyIP returns successfully.
func (m *BypassManager) SetMyIP(ip string) {
	m.mu.Lock()
	m.myIP = ip
	m.mu.Unlock()
}

// SetLocalIP records the original NIC IP used as source for bypass connections.
// Call this after RouteManager.Apply() (before Start).
func (m *BypassManager) SetLocalIP(ip string) {
	m.mu.Lock()
	m.localIP = ip
	m.mu.Unlock()
}

// HasLocalIP reports whether a local NIC IP has been set (Windows only).
// On Android, localIP is never set; UDP traffic goes through the tunnel.
func (m *BypassManager) HasLocalIP() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.localIP != ""
}

// ContainsIP reports whether ip falls within the client's home-country CIDRs.
// Unlike ShouldBypass, this ignores the enabled flag — it is used solely for
// determining whether a remote address (e.g. a control node) is in the same
// country as the client, regardless of whether bypass routing is active.
func (m *BypassManager) ContainsIP(ip net.IP) bool {
	m.mu.RLock()
	c := m.cidrs
	m.mu.RUnlock()
	if c == nil {
		return false
	}
	return c.Contains(ip)
}

// Country returns the ISO country code detected for the client's IP (e.g. "RU").
// Returns "" until the first successful CIDR fetch.
func (m *BypassManager) Country() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.country
}

// CIDRStatus returns the current CIDR load state: "none", "cached", or "fresh".
// "cached" means CIDRs were loaded from the on-disk cache this session but the
// live fetch has not yet succeeded.  "fresh" means a live fetch succeeded.
func (m *BypassManager) CIDRStatus() string {
	switch atomic.LoadInt32(&m.cidrSource) {
	case 1:
		return "cached"
	case 2:
		return "fresh"
	default:
		return "none"
	}
}

// SetEnabled toggles bypass on/off at runtime.
func (m *BypassManager) SetEnabled(v bool) {
	m.mu.Lock()
	m.enabled = v
	m.mu.Unlock()
}

// Enabled reports whether bypass is currently on.
func (m *BypassManager) Enabled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.enabled
}

// Start loads cached CIDRs and launches the refresh loop: every 30 minutes
// normally, but every 2 minutes after a failed fetch until one succeeds, so a
// transient outage doesn't leave bypass disabled for up to half an hour.
func (m *BypassManager) Start() {
	m.loadCached()
	go func() {
		const normalInterval = 30 * time.Minute
		const retryInterval = 2 * time.Minute

		interval := normalInterval
		if !m.refresh() {
			interval = retryInterval
		}
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-m.stop:
				return
			case <-t.C:
				next := normalInterval
				if !m.refresh() {
					next = retryInterval
				}
				if next != interval {
					interval = next
					t.Reset(interval)
				}
			}
		}
	}()
}

// Stop shuts down the background refresh goroutine.
func (m *BypassManager) Stop() {
	close(m.stop)
}

// ShouldBypass reports whether addr (host:port or bare host) should bypass
// the tunnel.  Returns false if bypass is disabled, CIDRs are not loaded, or
// the address was previously recorded as a bypass failure.
func (m *BypassManager) ShouldBypass(addr string) bool {
	m.mu.RLock()
	enabled := m.enabled
	cidrs := m.cidrs
	country := m.country
	m.mu.RUnlock()

	if !enabled {
		return false
	}

	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}

	ip := net.ParseIP(host)
	if ip == nil {
		addrs, err := net.LookupHost(host)
		if err != nil || len(addrs) == 0 {
			return false
		}
		ip = net.ParseIP(addrs[0])
		if ip == nil {
			return false
		}
	}

	// Check whether bypass previously failed for this IP while tunnel succeeded.
	ipStr := ip.String()
	if exp, ok := m.failedIPs.Load(ipStr); ok {
		if time.Now().Before(exp.(time.Time)) {
			return false // route through tunnel; bypass blocked for this IP
		}
		m.failedIPs.Delete(ipStr)
	}

	// TLD override — evaluated before the CIDR check and before the cidrs==nil
	// guard so that home-TLD domains (.ru for RU clients, .cn for CN clients)
	// are always bypassed even when the full CIDR list has not yet loaded.
	// country is set quickly via fetchCountry() at Start(), independently of
	// the heavy CIDR download.
	//   dc == country: home-TLD domain (e.g. .ru for a RU user) — always bypass.
	//     Government and banking sites often block non-domestic IPs outright;
	//     routing them through the tunnel breaks them even when their IP is not
	//     in the published CIDR set (CDN-fronted, government clouds, etc.).
	//   dc != country: foreign-flagged TLD served from a home-country IP (CDN
	//     edge) — route through tunnel regardless of CIDR membership.
	if country != "" {
		if fqdn := GlobalDNSCache.Get(ipStr); fqdn != "" {
			if dc := tldCountry(fqdn); dc != "" {
				return dc == country
			}
		}
	}

	if cidrs == nil || cidrs.Len() == 0 {
		return false
	}

	return cidrs.Contains(ip)
}

// tldCountry returns the ISO country code implied by a domain's TLD, or "".
func tldCountry(fqdn string) string {
	// DNS FQDNs from dnsmessage are dot-terminated ("example.ru."); accept both.
	f := strings.TrimSuffix(fqdn, ".")
	switch {
	case strings.HasSuffix(f, ".ru"):
		return "RU"
	case strings.HasSuffix(f, ".cn"):
		return "CN"
	}
	return ""
}

// RecordBypassFailure marks addr as tunnel-preferred for 30 minutes.
// Must only be called when bypass dial failed AND tunnel connection succeeded —
// not on genuine host unreachability (both paths fail).
func (m *BypassManager) RecordBypassFailure(addr string) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if net.ParseIP(host) == nil {
		return // only track numeric IPs, not hostnames
	}
	m.failedIPs.Store(host, time.Now().Add(30*time.Minute))
	Log.Printf("bypass: %s → tunnel for 30 min (bypass failed, tunnel OK)", host)
}

// BypassDialer returns a net.Dialer whose LocalAddr is set to the original NIC
// IP so that connections bypass the TUN routing table.
func (m *BypassManager) BypassDialer() *net.Dialer {
	m.mu.RLock()
	localIP := m.localIP
	m.mu.RUnlock()
	d := &net.Dialer{Timeout: 10 * time.Second, Control: dialControl}
	if localIP != "" {
		d.LocalAddr = &net.TCPAddr{IP: net.ParseIP(localIP)}
	}
	return d
}

// DialUDP opens an unconnected UDP socket bound to the original NIC IP so
// that datagrams bypass TUN routing. The caller is responsible for closing.
func (m *BypassManager) DialUDP() (*net.UDPConn, error) {
	m.mu.RLock()
	localIP := m.localIP
	m.mu.RUnlock()
	laddr := ""
	if localIP != "" {
		laddr = localIP + ":0"
	} else {
		laddr = "0.0.0.0:0"
	}
	lc := net.ListenConfig{Control: dialControl}
	pc, err := lc.ListenPacket(context.Background(), "udp4", laddr)
	if err != nil {
		return nil, fmt.Errorf("bypass: ListenUDP: %w", err)
	}
	return pc.(*net.UDPConn), nil
}

// SetNodes replaces the list of control node URLs used for CIDR and country
// fetches.  Called by the Discoverer's onChange callback so BypassManager
// always uses the current manifest node list instead of the bootstrap URL.
func (m *BypassManager) SetNodes(urls []string) {
	trimmed := make([]string, len(urls))
	for i, u := range urls {
		trimmed[i] = strings.TrimRight(u, "/")
	}
	m.mu.Lock()
	m.exitURLs = trimmed
	m.mu.Unlock()
}

// makeClient returns an HTTP client for bypass/country requests.
// On Windows (localIP set): binds to the original NIC so the socket bypasses
// the TUN routing table and the exit sees the real client IP.
// On Android (localIP empty): uses the default client, which goes through the
// TUN → tunnel path.  A protected socket would bypass the tunnel and hit
// foreign servers directly, which carriers may block.
func (m *BypassManager) makeClient(localIP string) *http.Client {
	if localIP != "" {
		d := &net.Dialer{
			Timeout:   10 * time.Second,
			LocalAddr: &net.TCPAddr{IP: net.ParseIP(localIP)},
			Control:   dialControl,
		}
		return &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				DialContext:     d.DialContext,
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
			},
		}
	}
	return m.client
}

// fetchCIDR fetches raw signed CIDR JSON from one control node URL.
func (m *BypassManager) fetchCIDR(exitURL, token, myIP, localIP string) ([]byte, bool) {
	u := exitURL + "/api/bypass/cidr"
	if myIP != "" {
		u += "?ip=" + myIP
	}
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		Log.Printf("bypass: build request [%s]: %v", exitURL, err)
		return nil, false
	}
	req.Header.Set("X-Session", token)
	resp, err := m.makeClient(localIP).Do(req)
	if err != nil {
		Log.Printf("bypass: fetch [%s]: %v", exitURL, err)
		return nil, false
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		Log.Printf("bypass: no CIDR data for this country from %s", exitURL)
		return nil, false
	}
	if resp.StatusCode != http.StatusOK {
		Log.Printf("bypass: fetch status %d from %s", resp.StatusCode, exitURL)
		return nil, false
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		Log.Printf("bypass: read body [%s]: %v", exitURL, err)
		return nil, false
	}
	return data, true
}

// refresh fetches and verifies the CIDR list from each control node in order,
// returning true on first success.
// The caller (Start) uses the result to pick a short retry interval after a
// failure instead of waiting for the next regular tick.
func (m *BypassManager) refresh() bool {
	m.mu.RLock()
	token := m.token
	myIP := m.myIP
	localIP := m.localIP
	exitURLs := append([]string(nil), m.exitURLs...)
	m.mu.RUnlock()

	if token == "" {
		Log.Printf("bypass: skip refresh: token not set yet")
		return false
	}

	for _, exitURL := range exitURLs {
		data, ok := m.fetchCIDR(exitURL, token, myIP, localIP)
		if !ok {
			continue
		}
		cidrs, err := m.verifyCIDR(data)
		if err != nil {
			Log.Printf("bypass: verify [%s]: %v", exitURL, err)
			continue
		}
		cc := cidrCountry(data)
		m.mu.Lock()
		m.cidrs = cidrs
		m.country = cc
		m.mu.Unlock()
		m.persist(data)
		atomic.StoreInt32(&m.cidrSource, 2)
		Log.Printf("bypass: loaded %d CIDRs for country=%s from %s", cidrs.Len(), cc, exitURL)
		return true
	}
	return false
}

func (m *BypassManager) verifyCIDR(data []byte) (*CIDRSet, error) {
	var payload signedCIDRList
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	if m.pubkey != nil {
		canonical, _ := json.Marshal(struct {
			Country string   `json:"country"`
			TS      int64    `json:"ts"`
			CIDRs   []string `json:"cidrs"`
		}{Country: payload.Country, TS: payload.TS, CIDRs: payload.CIDRs})
		sigBytes, err := base64.RawURLEncoding.DecodeString(payload.Sig)
		if err != nil || !ed25519.Verify(m.pubkey, canonical, sigBytes) {
			return nil, fmt.Errorf("signature verification failed")
		}
	} else {
		Log.Printf("bypass: WARNING — arbiter pubkey not set, skipping signature verification")
	}
	age := time.Since(time.Unix(payload.TS, 0))
	if age > 25*time.Hour {
		return nil, fmt.Errorf("CIDR list too old (%s)", age.Round(time.Minute))
	}
	return ParseCIDRs(payload.CIDRs), nil
}

func (m *BypassManager) loadCached() {
	if m.cacheFile == "" {
		return
	}
	enc, err := os.ReadFile(m.cacheFile)
	if err != nil {
		Log.Printf("bypass: no cached CIDRs: %v", err)
		return
	}
	plain, err := nodeIDDecrypt(enc)
	if err != nil {
		// Legacy plaintext file — accept once, will be re-saved encrypted.
		Log.Printf("bypass: cache decrypt failed (%v) — trying legacy plaintext", err)
		plain = enc
	}
	cidrs, err := m.verifyCIDR(plain)
	if err != nil {
		Log.Printf("bypass: cached CIDRs invalid: %v", err)
		return
	}
	cc := cidrCountry(plain)
	m.mu.Lock()
	m.cidrs = cidrs
	m.country = cc
	m.mu.Unlock()
	atomic.StoreInt32(&m.cidrSource, 1)
	Log.Printf("bypass: loaded %d CIDRs from cache country=%s", cidrs.Len(), cc)
}

func (m *BypassManager) persist(data []byte) {
	if m.cacheFile == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(m.cacheFile), 0700); err != nil {
		Log.Printf("bypass: cache dir: %v", err)
		return
	}
	enc, err := nodeIDEncrypt(data)
	if err != nil {
		Log.Printf("bypass: cache encrypt: %v", err)
		return
	}
	if err := os.WriteFile(m.cacheFile, enc, 0600); err != nil {
		Log.Printf("bypass: cache write: %v", err)
	}
}

func cidrCountry(data []byte) string {
	var p struct {
		Country string `json:"country"`
	}
	json.Unmarshal(data, &p) //nolint:errcheck
	return p.Country
}

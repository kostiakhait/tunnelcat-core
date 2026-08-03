// Copyright (c) 2026 Konstantin Khait

package core

import (
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// manifestNode is a control node entry in the signed manifest.
// Fields must stay in sync with the server-side signing implementation's NodeEntry — the
// canonical JSON reconstructed here must be byte-identical to what the
// arbiter signed.
type manifestNode struct {
	Addr        string  `json:"addr"`
	Fingerprint string  `json:"fingerprint,omitempty"`
	RTTms       float64 `json:"rtt_ms,omitempty"`
	Load        float64 `json:"load,omitempty"`
	DataPlaneOK *bool   `json:"data_plane_ok,omitempty"`
}

// Notification is an admin broadcast message delivered in the manifest.
// Advisory only — not covered by the arbiter's Ed25519 signature.
type Notification struct {
	ID        string `json:"id"`
	Message   string `json:"message"`
	CreatedAt int64  `json:"created_at"`
}

// signedManifest is the wire format returned by the exit's /api/manifest endpoint.
// The arbiter signs it; the exit relays it verbatim.
type signedManifest struct {
	Type            string              `json:"type"` // must be "manifest"
	TS              int64               `json:"ts"`
	Nodes           []manifestNode      `json:"nodes"`
	Sig             string              `json:"sig"`                          // base64url Ed25519 over {type,ts,nodes}
	Regions         map[string]string   `json:"regions,omitempty"`            // addr → ISO region code; advisory, not signed
	Notifications   []Notification      `json:"notifications,omitempty"`      // advisory; not signed
	NodeSNIs        map[string][]string `json:"node_snis,omitempty"`          // advisory; addr → SNI rotation list
	Excluded        []string            `json:"excluded,omitempty"`           // advisory; addrs clients must skip (decommissioned nodes)
	NodeAltUDPPorts map[string][]int    `json:"node_alt_udp_ports,omitempty"` // advisory; addr → dynamic alternate-transport UDP ports
}

// Discoverer fetches the signed control-node manifest from the control's relay
// API (channel 0x01, /p/v1/manifest), verifies the arbiter's Ed25519 signature,
// and maintains a refreshed list of controls.
// It persists the manifest to disk so the updated list survives restarts.
type Discoverer struct {
	pubkey    ed25519.PublicKey // arbiter pubkey; nil = skip sig verification (dev)
	client    *http.Client      // retained for API compatibility; no longer used by fetch()
	cacheFile string            // path to persist the manifest on disk; "" = no persistence

	// httpClientFactory, if non-nil, overrides the HTTP client used by fetch().
	// Default (nil) uses NewRelayAPIH1Client (channel 0x01 uTLS). Override in tests.
	httpClientFactory func() *http.Client

	mu              sync.RWMutex
	serverURLs      []string             // https:// URLs of all known controls; updated after each successful fetch
	controls        []string             // current list of control addresses
	regions         map[string]string    // addr → ISO region code (advisory, from arbiter)
	nodeSNIs        map[string][]string  // addr → SNI rotation list (advisory, from arbiter)
	nodeAltUDPPorts map[string][]int     // addr → dynamic alternate-transport UDP ports (advisory, from arbiter)
	notifications   []Notification       // pending broadcast notifications (advisory, from arbiter)
	onChange        func([]string)       // called when controls change; may be nil
	onFetch         func([]byte, int64)  // called after each successful fetch (raw, ts)
	onNotifications func([]Notification) // called when new notifications arrive; may be nil

	// manifestSource tracks how the current manifest was obtained:
	// 0 = not loaded, 1 = loaded from on-disk cache, 2 = fetched live this session.
	manifestSource int32 // accessed atomically

	done chan struct{} // closed by Stop() to terminate the background polling goroutine
}

// NewDiscoveryClient returns an http.Client suitable for talking to exit nodes
// that present self-signed TLS certificates.  Use this when creating a
// Discoverer outside of an existing Authenticator context.
func NewDiscoveryClient() *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // self-signed exit nodes
		},
	}
}

// NewDiscoverer creates a Discoverer for the given exit server URL.
//
// pubkeyHex is the arbiter's Ed25519 public key in hex.
// Pass "" to skip signature verification (development only).
//
// client should be the same http.Client used for tunnel requests (InsecureSkipVerify
// is already set there for self-signed exit certs).
//
// cacheFile is the full path where the raw manifest JSON is persisted; pass ""
// to disable on-disk caching.
//
// onChange is called whenever the control list changes; may be nil.
func NewDiscoverer(serverURL, pubkeyHex string, client *http.Client, cacheFile string, onChange func([]string)) (*Discoverer, error) {
	d := &Discoverer{
		serverURLs: []string{strings.TrimRight(serverURL, "/")},
		client:     client,
		cacheFile:  cacheFile,
		onChange:   onChange,
		done:       make(chan struct{}),
	}
	if pubkeyHex != "" {
		b, err := hex.DecodeString(pubkeyHex)
		if err != nil || len(b) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("discovery: invalid arbiter pubkey hex (need %d bytes)", ed25519.PublicKeySize)
		}
		d.pubkey = ed25519.PublicKey(b)
	}
	return d, nil
}

// ReadManifestCacheControls reads and verifies a cached manifest file and returns
// the list of control addresses it contains.  Useful for augmenting bootstrap
// candidates before a Discoverer instance is available.
//
// pubkeyHex is the arbiter's Ed25519 public key in hex; pass "" to skip
// signature verification (development only).  Returns nil on any error
// (missing file, bad signature, etc.) — the caller should treat absence as
// non-fatal.
func ReadManifestCacheControls(cacheFile, pubkeyHex string) []string {
	addrs, _ := ReadManifestCacheControlsAndRegions(cacheFile, pubkeyHex)
	return addrs
}

// ReadManifestCacheControlsAndRegions is like ReadManifestCacheControls but
// also returns the addr→country-code map from the cached manifest.
// The map is nil when regions are unavailable (first run, bad cache, etc.).
func ReadManifestCacheControlsAndRegions(cacheFile, pubkeyHex string) ([]string, map[string]string) {
	enc, err := os.ReadFile(cacheFile)
	if err != nil {
		return nil, nil
	}
	plain, err := nodeIDDecrypt(enc)
	if err != nil {
		plain = enc // legacy plaintext
	}
	d := &Discoverer{}
	if pubkeyHex != "" {
		if b, err := hex.DecodeString(pubkeyHex); err == nil && len(b) == ed25519.PublicKeySize {
			d.pubkey = ed25519.PublicKey(b)
		}
	}
	addrs, regions, _, _, _, err := d.verify(plain)
	if err != nil {
		return nil, nil
	}
	return addrs, regions
}

// LoadCached reads a previously-persisted manifest from disk and populates the
// in-memory control list.  Returns a non-nil error if the cache is missing or
// the manifest fails to parse/verify — the caller should treat this as a
// non-fatal condition (the live fetch will fill the list shortly).
func (d *Discoverer) LoadCached() error {
	if d.cacheFile == "" {
		return fmt.Errorf("discovery: no cache file configured")
	}
	enc, err := os.ReadFile(d.cacheFile)
	if err != nil {
		return err
	}
	plain, err := nodeIDDecrypt(enc)
	if err != nil {
		// Legacy plaintext file — accept once, will be re-saved encrypted.
		Log.Printf("discovery: cache decrypt failed (%v) — trying legacy plaintext", err)
		plain = enc
	}
	addrs, regions, notifs, snis, altUDPPorts, err := d.verify(plain)
	if err != nil {
		return fmt.Errorf("discovery: cached manifest invalid: %w", err)
	}
	d.setControls(addrs, regions, notifs, snis, altUDPPorts)
	atomic.StoreInt32(&d.manifestSource, 1)
	Log.Printf("discovery: loaded %d controls from cache", len(addrs))
	return nil
}

// Start performs an immediate manifest fetch and then refreshes on interval.
// Errors are logged but do not stop the loop.
func (d *Discoverer) Start(interval time.Duration) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				Log.Printf("discovery: PANIC in background fetch: %v\n%s", r, debug.Stack())
			}
		}()
		d.fetchAndApply()
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-d.done:
				return
			case <-t.C:
				d.fetchAndApply()
			}
		}
	}()
}

// Stop signals the background polling goroutine started by Start to exit.
// Safe to call multiple times; no-op if Start was never called.
func (d *Discoverer) Stop() {
	select {
	case <-d.done:
	default:
		close(d.done)
	}
}

// Controls returns a snapshot of the current control node addresses.
func (d *Discoverer) Controls() []string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]string, len(d.controls))
	copy(out, d.controls)
	return out
}

// Regions returns a snapshot of the current addr → ISO region map.
// The map is advisory (not covered by the arbiter's signature).
func (d *Discoverer) Regions() map[string]string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.regions == nil {
		return nil
	}
	out := make(map[string]string, len(d.regions))
	for k, v := range d.regions {
		out[k] = v
	}
	return out
}

// SNIFor returns a randomly chosen SNI hostname for the given control addr
// (host:port). Returns "" if no SNI list is configured for that addr.
func (d *Discoverer) SNIFor(addr string) string {
	d.mu.RLock()
	snis := d.nodeSNIs[addr]
	d.mu.RUnlock()
	if len(snis) == 0 {
		return ""
	}
	return snis[rand.Intn(len(snis))]
}

// AltUDPPorts returns a copy of the dynamic alternate-transport port list for the given
// control address, or nil if none have been received from the control-plane yet.
func (d *Discoverer) AltUDPPorts(ctrlAddr string) []int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if p := d.nodeAltUDPPorts[ctrlAddr]; len(p) > 0 {
		out := make([]int, len(p))
		copy(out, p)
		return out
	}
	return nil
}

// UseAsSNIProvider registers this discoverer as the process-wide SNI source
// for uTLS connections to control nodes. Call once after creating the discoverer.
func (d *Discoverer) UseAsSNIProvider() {
	ControlSNILookup = d.SNIFor
}

// SetFetchCallback registers a function called after each successful manifest
// fetch.  The callback receives the raw signed manifest JSON and the manifest
// ts — use this to feed the manifest into the DHT gossip layer.
func (d *Discoverer) SetFetchCallback(fn func(raw []byte, ts int64)) {
	d.mu.Lock()
	d.onFetch = fn
	d.mu.Unlock()
}

// SetNotificationCallback registers a function called whenever the manifest
// delivers one or more new broadcast notifications.  The callback receives
// only the advisory slice as-is; deduplication/TTL are the caller's job.
func (d *Discoverer) SetNotificationCallback(fn func([]Notification)) {
	d.mu.Lock()
	d.onNotifications = fn
	d.mu.Unlock()
}

// Notifications returns a snapshot of the most-recently-received notifications.
func (d *Discoverer) Notifications() []Notification {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if len(d.notifications) == 0 {
		return nil
	}
	out := make([]Notification, len(d.notifications))
	copy(out, d.notifications)
	return out
}

// InjectRaw accepts a raw signed manifest from an external source (e.g. DHT
// gossip).  It verifies the signature, applies the control list, and persists
// it — identical to a local fetch but without the HTTP round-trip.
// Returns an error if verification fails; the caller should not apply or
// re-gossip invalid data.
func (d *Discoverer) InjectRaw(data []byte) error {
	addrs, regions, notifs, snis, altUDPPorts, err := d.verify(data)
	if err != nil {
		return fmt.Errorf("discovery: inject verify: %w", err)
	}
	d.setControls(addrs, regions, notifs, snis, altUDPPorts)
	if d.cacheFile != "" {
		d.persist(data)
	}
	Log.Printf("discovery: applied manifest from DHT gossip (%d controls)", len(addrs))
	return nil
}

// ManifestStatus returns the current manifest load state: "none", "cached", or "fresh".
func (d *Discoverer) ManifestStatus() string {
	switch atomic.LoadInt32(&d.manifestSource) {
	case 1:
		return "cached"
	case 2:
		return "fresh"
	default:
		return "none"
	}
}

// fetchAndApply fetches the manifest, verifies it, and updates the control list.
func (d *Discoverer) fetchAndApply() {
	data, err := d.fetch()
	if err != nil {
		Log.Printf("discovery: fetch failed: %v", err)
		return
	}
	addrs, regions, notifs, snis, altUDPPorts, err := d.verify(data)
	if err != nil {
		Log.Printf("discovery: verify failed: %v", err)
		return
	}
	d.setControls(addrs, regions, notifs, snis, altUDPPorts)
	atomic.StoreInt32(&d.manifestSource, 2)
	if d.cacheFile != "" {
		d.persist(data)
	}
	// Notify DHT layer so it can gossip this fresh manifest to peers.
	d.mu.RLock()
	cb := d.onFetch
	d.mu.RUnlock()
	if cb != nil {
		ts := manifestTS(data)
		cb(data, ts)
	}
}

// fetch fetches the manifest from the control's relay API (channel 0x01,
// /p/v1/manifest). Tries all known control URLs in random order so that a
// dead bootstrap control does not permanently block manifest refresh.
func (d *Discoverer) fetch() ([]byte, error) {
	factory := d.httpClientFactory
	if factory == nil {
		factory = NewRelayAPIH1Client
	}

	d.mu.RLock()
	urls := make([]string, len(d.serverURLs))
	copy(urls, d.serverURLs)
	d.mu.RUnlock()

	// Shuffle so all controls share fetch load and a dead first-in-list
	// does not always block the round.
	rand.Shuffle(len(urls), func(i, j int) { urls[i], urls[j] = urls[j], urls[i] })

	var lastErr error
	for _, srvURL := range urls {
		data, err := func() ([]byte, error) {
			client := factory()
			req, err := http.NewRequest(http.MethodGet, srvURL+"/p/v1/manifest", nil)
			if err != nil {
				return nil, err
			}
			resp, err := client.Do(req)
			if err != nil {
				return nil, err
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
			}
			data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
			if err != nil {
				return nil, err
			}
			if len(data) == 0 {
				return nil, fmt.Errorf("empty response")
			}
			return data, nil
		}()
		if err != nil {
			Log.Printf("discovery: fetch %s: %v", srvURL, err)
			lastErr = err
			continue
		}
		return data, nil
	}
	if lastErr != nil {
		return nil, fmt.Errorf("GET /p/v1/manifest: %w", lastErr)
	}
	return nil, fmt.Errorf("discovery: no controls to fetch from")
}

// ProbeManifest fetches /p/v1/manifest once and returns (nodeCount, error).
// Intended for a manifest-probing diagnostic tool; not used in normal client operation.
func (d *Discoverer) ProbeManifest(timeout time.Duration) (nodes int, err error) {
	old := d.httpClientFactory
	d.httpClientFactory = func() *http.Client {
		c := NewRelayAPIH1Client()
		c.Timeout = timeout
		return c
	}
	defer func() { d.httpClientFactory = old }()

	data, err := d.fetch()
	if err != nil {
		return 0, err
	}
	addrs, _, _, _, _, err := d.verify(data)
	if err != nil {
		return 0, fmt.Errorf("verify: %w (raw size=%d)", err, len(data))
	}
	return len(addrs), nil
}

// verify parses and optionally verifies the Ed25519 signature on a raw manifest.
// Returns control addresses, advisory regions, advisory notifications, advisory
// node SNI lists, and advisory alternate-transport port maps on success.
func (d *Discoverer) verify(data []byte) ([]string, map[string]string, []Notification, map[string][]string, map[string][]int, error) {
	var m signedManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("parse: %w", err)
	}
	if m.Type != "manifest" {
		return nil, nil, nil, nil, nil, fmt.Errorf("unexpected manifest type %q", m.Type)
	}

	if d.pubkey != nil {
		// Reconstruct the canonical payload the arbiter signed (advisory fields excluded).
		payload := struct {
			Type  string         `json:"type"`
			TS    int64          `json:"ts"`
			Nodes []manifestNode `json:"nodes"`
		}{Type: m.Type, TS: m.TS, Nodes: m.Nodes}
		canonical, _ := json.Marshal(payload)

		sigBytes, err := base64.RawURLEncoding.DecodeString(m.Sig)
		if err != nil || !ed25519.Verify(d.pubkey, canonical, sigBytes) {
			return nil, nil, nil, nil, nil, fmt.Errorf("signature verification failed")
		}
	} else {
		Log.Printf("discovery: WARNING — arbiter pubkey not set, skipping signature verification")
	}

	excluded := make(map[string]bool, len(m.Excluded))
	for _, addr := range m.Excluded {
		excluded[addr] = true
	}
	if len(excluded) > 0 {
		Log.Printf("discovery: manifest excludes %d node(s): %v", len(excluded), m.Excluded)
	}

	addrs := make([]string, 0, len(m.Nodes))
	for _, n := range m.Nodes {
		if n.Addr != "" && !excluded[n.Addr] {
			addrs = append(addrs, n.Addr)
		}
	}
	if len(addrs) == 0 {
		return nil, nil, nil, nil, nil, fmt.Errorf("manifest contains no control nodes")
	}
	return addrs, m.Regions, m.Notifications, m.NodeSNIs, m.NodeAltUDPPorts, nil
}

// setControls atomically replaces the control list, regions, notifications,
// node SNI lists, and alternate-transport port assignments, then fires callbacks.
func (d *Discoverer) setControls(addrs []string, regions map[string]string, notifs []Notification, snis map[string][]string, altUDPPorts map[string][]int) {
	d.mu.Lock()
	changed := !stringSliceEqual(d.controls, addrs)
	d.controls = addrs
	d.regions = regions
	d.notifications = notifs
	d.nodeSNIs = snis
	d.nodeAltUDPPorts = altUDPPorts
	cbNotif := d.onNotifications
	// Keep serverURLs in sync with the full control list so future fetch()
	// calls try every known control, not just the initial bootstrap URL.
	urls := make([]string, 0, len(addrs))
	for _, a := range addrs {
		if strings.HasPrefix(a, "http") {
			urls = append(urls, a)
		} else {
			urls = append(urls, "https://"+a)
		}
	}
	if len(urls) > 0 {
		d.serverURLs = urls
	}
	d.mu.Unlock()

	Log.Printf("discovery: %d control nodes (changed=%v), %d notification(s)", len(addrs), changed, len(notifs))
	if changed && d.onChange != nil {
		d.onChange(addrs)
	}
	if len(notifs) > 0 && cbNotif != nil {
		cbNotif(notifs)
	}
}

// persist writes the DPAPI-encrypted manifest to cacheFile.
func (d *Discoverer) persist(data []byte) {
	if err := os.MkdirAll(filepath.Dir(d.cacheFile), 0700); err != nil {
		Log.Printf("discovery: mkdir %s: %v", filepath.Dir(d.cacheFile), err)
		return
	}
	enc, err := nodeIDEncrypt(data)
	if err != nil {
		Log.Printf("discovery: cache encrypt: %v", err)
		return
	}
	if err := os.WriteFile(d.cacheFile, enc, 0600); err != nil {
		Log.Printf("discovery: write cache %s: %v", d.cacheFile, err)
	}
}

// manifestTS extracts the ts field from a raw manifest JSON without full parsing.
// Returns 0 if the field is missing or malformed.
func manifestTS(data []byte) int64 {
	var m struct {
		TS int64 `json:"ts"`
	}
	json.Unmarshal(data, &m) //nolint:errcheck
	return m.TS
}

func stringSliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

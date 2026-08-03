// Copyright (c) 2026 Konstantin Khait

package core

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"sort"
	"sync"
	"time"
)

// Router selects the best path through available relay nodes to the control.
//
// Route structures (in priority order):
//
//	A:        Client → Relay → Control → Exit
//	B:        Client → Relay → Relay → Control → Exit          (future: route vector)
//	C:        Client → Relay → Relay → Relay → Control → Exit  (future: route vector)
//	Fallback: Client → Control → Exit
//
// Multiple control nodes are supported. BuildPaths generates candidate paths
// across all alive controls; scoring naturally prefers lower-latency controls.
// Advance() cycles through paths, which may switch to a different control.
//
// Control selection policy (see memory/project_control_routing_policy.md):
//   - In-country hard filter: if any in-country control is alive, out-of-country
//     controls are excluded entirely (not just de-prioritised).
//   - RTT threshold: only controls with score ≤ best×1.5 qualify.
//   - Top-5 cap.
//   - RTT is measured via a real HTTP data-plane probe, not a TCP SYN/ACK,
//     so DPI body-stripping is detected at probe time.
//
// When myCountry is set, same-region relays are preferred.  If none are alive
// the router falls back to all alive relays (connectivity beats policy).
type Router struct {
	mu        sync.Mutex
	relays    []*routerNode
	controls  []*routerNode // all known control nodes (replaces single control field)
	paths     []RouterPath
	pathIdx   int
	myCountry string // ISO country code of the client (e.g. "RU"); "" = no filter

	// dataDead maps control addr → expiry time.  A control is excluded from
	// BuildPaths even if TCP-reachable, to handle DPI body-stripping attacks.
	dataDead map[string]time.Time

	// udpDataFailed maps control addr → expiry time.  During the TTL ProbeDataPlane
	// skips the UDP fallback probe so a broken UDP channel is not re-created.
	// After the TTL the probe runs again: if UDP is fixed it re-enables; if still
	// broken it extends the TTL.
	udpDataFailed map[string]time.Time

	selfNodeID string // own DHT node ID; entries with this ID are skipped in MergeDHTRelays

	udpMu    sync.RWMutex
	udpPeers map[string]*UDPRelayConn // nodeID or addr → live UDP relay conn

	// flapMu protects flaps. Separate from mu so RecordControlFlap can be
	// called from data-path goroutines without blocking BuildPaths readers.
	flapMu sync.Mutex
	flaps  map[string][]time.Time // control addr → timestamps of recent stream evictions
}

// Flap penalty: each stream eviction within flapWindow adds flapPenaltyPerEviction
// to the control's effective RTT, capped at flapPenaltyCap. This deprioritises
// controls that are under active DPI interference without permanently excluding them.
const (
	flapWindow             = 5 * time.Minute
	flapPenaltyPerEviction = 200 * time.Millisecond
	flapPenaltyCap         = 2 * time.Second
)

// controlTransport records which protocol the router detected for a control node.
type controlTransport uint8

const (
	transportTCP controlTransport = 0 // default; TCP data-plane probe succeeded
	transportUDP controlTransport = 1 // TCP failed, UDP /p/v1/ping succeeded
)

// routerNode is an internal node representation with measurement state.
type routerNode struct {
	ID          string
	Addr        string        // host or host:port
	OperatorID  string        // used to avoid selecting two nodes from the same operator
	CountryCode string        // ISO country code reported by the relay (may be "")
	RTT         time.Duration // 0 = unmeasured; updated by ProbeDataPlane
	TrafficRTT  time.Duration // 0 = unmeasured; updated by passive POST round-trip observation
	Loss        float64       // 0.0–1.0 (reserved for future probing)
	LastSeen    time.Time
	IsAlive     bool
	transport   controlTransport // TCP or UDP; only meaningful for control nodes
}

// RouterPath is a scored candidate path returned by BuildPaths.
type RouterPath struct {
	// Relays is the ordered list of relay hops (0–3 nodes).
	// Currently only len 0 (direct) and len 1 (single relay) are executed;
	// multi-hop entries are generated for scoring but require route-vector
	// support before they can be used.
	Relays      []*RouterPathNode
	ControlAddr string
	Score       float64       // lower is better (ms-equivalent)
	UDPRelay    *UDPRelayConn // non-nil if first relay hop has a live UDP conn (M4.5)
}

// RouterPathNode is a relay node reference returned in RouterPath.
type RouterPathNode struct {
	ID   string
	Addr string
}

func (p *RouterPath) IsDirect() bool { return len(p.Relays) == 0 }

// NewRouter creates an idle router.  Call SetControl + UpdateRelays +
// MeasureRTTs + BuildPaths before using Primary.
func NewRouter() *Router {
	return &Router{
		udpPeers:      make(map[string]*UDPRelayConn),
		dataDead:      make(map[string]time.Time),
		udpDataFailed: make(map[string]time.Time),
	}
}

// SetSelfNodeID tells the router its own DHT node ID so it can exclude itself
// from relay selection in MergeDHTRelays.
func (r *Router) SetSelfNodeID(id string) {
	r.mu.Lock()
	r.selfNodeID = id
	r.mu.Unlock()
}

// MarkControlDataDead temporarily excludes a control from path building even if
// it is TCP-reachable.  Use when the data plane is blocked (e.g. DPI body
// stripping) so BuildPaths routes around it until the deadline.
func (r *Router) MarkControlDataDead(addr string, until time.Time) {
	r.mu.Lock()
	r.dataDead[addr] = until
	r.mu.Unlock()
	Log.Printf("router: control %s marked data-dead until %s", addr, until.Format(time.RFC3339))
}

// MarkControlAlive refreshes the liveness timestamp for the control at addr.
// Callers using an external dial function (SetDialFunc) may skip direct TCP
// probing (ProbeDataPlane) entirely, treating their own transport's auth
// success as the real liveness signal instead — so without this,
// LastSeen is stamped once at bootstrap and goes stale after 30s, making
// alive() (and therefore BuildPaths/QualifyingControlAddrs) falsely report
// every control as unreachable on the very next rebuild.
func (r *Router) MarkControlAlive(addr string) {
	norm := normaliseAddr(addr)
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, n := range r.controls {
		if n.Addr == norm {
			n.IsAlive = true
			n.LastSeen = time.Now()
			return
		}
	}
}

// MarkUDPDataFailed forces addr to TCP-only for 5 minutes.  ProbeDataPlane will
// skip the UDP fallback probe during this window so a broken UDP channel is not
// re-created immediately.  After the TTL, probing resumes: if UDP has recovered
// the control reverts to transportUDP; if still broken, the TTL is extended.
func (r *Router) MarkUDPDataFailed(addr string) {
	r.mu.Lock()
	// Downgrade transport immediately so NewControlDialer returns a TCP dialer.
	for _, c := range r.controls {
		if c.Addr == addr && c.transport == transportUDP {
			c.transport = transportTCP
			break
		}
	}
	r.udpDataFailed[addr] = time.Now().Add(5 * time.Minute)
	r.mu.Unlock()
	Log.Printf("router: control %s UDP data-plane failed — downgraded to TCP for 5 min", addr)
}

// RegisterUDPPeer registers a live UDP relay connection to a peer identified
// by nodeID (or addr when nodeID is unknown).  The router gives this peer a
// score bonus so it is preferred when building paths.
func (r *Router) RegisterUDPPeer(key string, conn *UDPRelayConn) {
	r.udpMu.Lock()
	if old, ok := r.udpPeers[key]; ok {
		old.Close()
	}
	r.udpPeers[key] = conn
	r.udpMu.Unlock()
	Log.Printf("router: udp peer registered key=%s", key)
}

// RemoveUDPPeer removes and closes the UDP relay connection for key.
func (r *Router) RemoveUDPPeer(key string) {
	r.udpMu.Lock()
	if c, ok := r.udpPeers[key]; ok {
		c.Close()
		delete(r.udpPeers, key)
		Log.Printf("router: udp peer removed key=%s", key)
	}
	r.udpMu.Unlock()
}

// CloseAllUDPPeers closes and removes all registered UDP relay connections.
func (r *Router) CloseAllUDPPeers() {
	r.udpMu.Lock()
	for k, c := range r.udpPeers {
		c.Close()
		delete(r.udpPeers, k)
	}
	r.udpMu.Unlock()
}

// udpPeer returns the UDP conn for a relay node (matched by ID or Addr).
func (r *Router) udpPeer(id, addr string) *UDPRelayConn {
	r.udpMu.RLock()
	defer r.udpMu.RUnlock()
	if c, ok := r.udpPeers[id]; ok {
		return c
	}
	if c, ok := r.udpPeers[addr]; ok {
		return c
	}
	return nil
}

// SetMyCountry sets the client's ISO country code (e.g. "RU").
// BuildPaths will only consider relays with a matching CountryCode.
// Pass "" to disable regional filtering (consider all relays).
func (r *Router) SetMyCountry(cc string) {
	r.mu.Lock()
	r.myCountry = cc
	r.mu.Unlock()
	Log.Printf("router: my country set to %q", cc)
}

// SetControls replaces the control node list. The first address is the preferred
// control; additional addresses are fallbacks. Call MeasureRTTs + BuildPaths after.
func (r *Router) SetControls(addrs []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.controls = make([]*routerNode, len(addrs))
	for i, addr := range addrs {
		r.controls[i] = &routerNode{
			ID:         addr,
			Addr:       normaliseAddr(addr),
			OperatorID: addr,
			LastSeen:   time.Now(),
			IsAlive:    true,
		}
	}
}

// SetControl sets a single control node. Compatibility shim; prefer SetControls.
func (r *Router) SetControl(addr string) { r.SetControls([]string{addr}) }

// SetControlsWithRegions sets the control list and annotates each address with
// its ISO country code from the regions map (addr → cc).  Use this instead of
// SetControls whenever region data is available (e.g. from the discoverer manifest
// on Windows or from bypass CIDR classification on Android).
func (r *Router) SetControlsWithRegions(addrs []string, regions map[string]string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.controls = make([]*routerNode, len(addrs))
	for i, addr := range addrs {
		cc := ""
		if regions != nil {
			cc = regions[addr]
		}
		r.controls[i] = &routerNode{
			ID:          addr,
			Addr:        normaliseAddr(addr),
			OperatorID:  addr,
			CountryCode: cc,
			LastSeen:    time.Now(),
			IsAlive:     true,
		}
	}
}

// UpdateRelays replaces the relay list.  Existing RTT measurements are
// discarded; call MeasureRTTs afterwards.
func (r *Router) UpdateRelays(relays []RelayEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.relays = make([]*routerNode, len(relays))
	for i, re := range relays {
		host := re.Addr
		if h, _, err := net.SplitHostPort(re.Addr); err == nil {
			host = h // use only host for operator ID
		}
		r.relays[i] = &routerNode{
			ID:          re.NodeID,
			Addr:        normaliseAddr(re.Addr),
			OperatorID:  host,
			CountryCode: re.CountryCode,
			LastSeen:    time.Now(),
			IsAlive:     true,
		}
	}
}

// MergeDHTRelays adds relay entries discovered via the DHT that are not already
// known from the control API.  Existing relay RTT measurements are preserved.
// New entries are inserted with IsAlive=true; they will be probed on the next
// MeasureRTTs call.
func (r *Router) MergeDHTRelays(entries []DHTRelayEntry) {
	if len(entries) == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	// Build a set of already-known node IDs.
	known := make(map[string]struct{}, len(r.relays))
	for _, n := range r.relays {
		known[n.ID] = struct{}{}
	}

	added := 0
	for _, e := range entries {
		if _, exists := known[e.NodeID]; exists {
			continue
		}
		if r.selfNodeID != "" && e.NodeID == r.selfNodeID {
			continue // never route through ourselves
		}
		host := e.Addr
		if h, _, err := net.SplitHostPort(e.Addr); err == nil {
			host = h
		}
		r.relays = append(r.relays, &routerNode{
			ID:          e.NodeID,
			Addr:        normaliseAddr(e.Addr),
			OperatorID:  host,
			CountryCode: e.CountryCode,
			LastSeen:    time.Now(),
			IsAlive:     true,
		})
		known[e.NodeID] = struct{}{}
		added++
	}
	if added > 0 {
		Log.Printf("router: merged %d DHT relay(s) (total=%d)", added, len(r.relays))
	}
}

// MarkRelayAlive marks the relay identified by id (NodeID or Addr) as alive
// with the current timestamp.  Call this when a UDP hole-punch connection to
// the relay is successfully established.
func (r *Router) MarkRelayAlive(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, n := range r.relays {
		if n.ID == id || n.Addr == id {
			n.IsAlive = true
			n.LastSeen = time.Now()
			Log.Printf("router: relay %s marked alive (UDP hole-punch)", n.Addr)
			return
		}
	}
}

// ProbeDataPlane probes the data plane health of control nodes:
//   - Controls: HTTP GET /p/v1/ping via the uTLS ChRelayAPI channel (H1).
//     A non-empty response body confirms the data plane is intact — a TCP-only
//     probe would pass even when DPI strips HTTP bodies.
//   - Relays are NOT probed via TCP (they are NAT-behind client nodes, not servers).
//     Relay liveness is determined by RegisterUDPPeer / MarkRelayAlive only.
//
// Nodes that fail are marked !IsAlive; successful probes update RTT.
// Call this instead of MeasureRTTs whenever reliable data-plane detection matters.
func (r *Router) ProbeDataPlane(timeout time.Duration) {
	r.mu.Lock()
	controls := make([]*routerNode, len(r.controls))
	copy(controls, r.controls)
	r.mu.Unlock()

	var wg sync.WaitGroup

	// Control probe: HTTP GET /p/v1/ping (TCP), then UDP fallback.
	// TCP probe confirms both connectivity and data-plane integrity (non-empty body).
	// If TCP fails, try a UDP SNCU ping — covers DPI body-stripping and TCP blocking.
	for _, n := range controls {
		wg.Add(1)
		go func(n *routerNode) {
			defer wg.Done()
			rtt, ok := probeControlPing(n.Addr, timeout)
			if ok {
				r.mu.Lock()
				n.RTT = rtt
				n.IsAlive = true
				n.LastSeen = time.Now()
				n.transport = transportTCP
				r.mu.Unlock()
				return
			}
			// TCP probe failed — try UDP unless it was recently marked as failed.
			r.mu.Lock()
			udpSuppressed := time.Now().Before(r.udpDataFailed[n.Addr])
			r.mu.Unlock()
			if udpSuppressed {
				r.mu.Lock()
				n.IsAlive = false
				n.transport = transportTCP
				r.mu.Unlock()
				Log.Printf("router: control %s TCP failed, UDP suppressed (data-failed TTL active)", n.Addr)
				return
			}
			udpRTT, udpOK := probeControlUDP(n.Addr, timeout)
			r.mu.Lock()
			if udpOK {
				n.RTT = udpRTT
				n.IsAlive = true
				n.LastSeen = time.Now()
				n.transport = transportUDP
				Log.Printf("router: control %s TCP blocked, UDP alive rtt=%s", n.Addr, udpRTT)
			} else {
				n.IsAlive = false
				n.transport = transportTCP // reset to default
				Log.Printf("router: control %s TCP+UDP both failed", n.Addr)
			}
			r.mu.Unlock()
		}(n)
	}

	wg.Wait()
}

// probeControlPing performs GET https://<addr>/p/v1/ping and returns the
// round-trip time.  ok=false when the control is unreachable or reports no
// alive exits (body.OK=false).  Mirrors ProbeControlE2E so that ProbeDataPlane
// and buildViableAddrs use the same liveness definition.
func probeControlPing(addr string, timeout time.Duration) (rtt time.Duration, ok bool) {
	client := newUTLSH1Client()
	client.Timeout = timeout
	url := fmt.Sprintf("https://%s/p/v1/ping", addr)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, false
	}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, false
	}
	defer resp.Body.Close()
	var body struct {
		OK    bool    `json:"ok"`
		RTTMs float64 `json:"rtt_ms"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil || !body.OK {
		return 0, false
	}
	elapsed := time.Since(start)
	if body.RTTMs > 0 {
		return elapsed + time.Duration(body.RTTMs*float64(time.Millisecond)), true
	}
	return elapsed, true
}

// ProbeControlE2E performs GET https://<addr>/p/v1/ping and returns the
// end-to-end RTT: the control's best measured exit latency reported in the
// response body.  Returns ok=false when the control is unreachable or reports
// no alive exits (empty body).  Uses the same uTLS transport as the tunnel so
// the probe is subject to the same DPI and dialControl constraints.
func ProbeControlE2E(addr string, timeout time.Duration) (rtt time.Duration, ok bool) {
	client := newUTLSH1Client()
	client.Timeout = timeout
	url := fmt.Sprintf("https://%s/p/v1/ping", addr)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, false
	}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, false
	}
	defer resp.Body.Close()
	var body struct {
		OK    bool    `json:"ok"`
		RTTMs float64 `json:"rtt_ms"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil || !body.OK {
		return 0, false
	}
	elapsed := time.Since(start)
	if body.RTTMs > 0 {
		return elapsed + time.Duration(body.RTTMs*float64(time.Millisecond)), true
	}
	// Control alive but no exit RTT measured yet (fresh start). Return elapsed
	// so the caller treats this as a live path with a real measured latency.
	return elapsed, true
}

// UpdateControlRTT overwrites the stored RTT for addr with the given value.
// Used by buildPoolDialers to feed real e2e latency into path scoring after
// a ProbeControlE2E call, replacing the TCP-only RTT from ProbeDataPlane.
func (r *Router) UpdateControlRTT(addr string, rtt time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, n := range r.controls {
		if n.Addr == addr {
			n.RTT = rtt
			return
		}
	}
}

// udpOnlyPenalty is added to the effective RTT of controls whose TCP path is
// blocked (transport==transportUDP).  BuildPaths already excludes them when
// any TCP-capable control is alive, but this penalty ensures they sort last in
// the DialerPool during the window between probe runs.
const udpOnlyPenalty = 30 * time.Second

// ControlRTT returns the effective RTT for addr including any flap penalty and
// a large UDP-only penalty, or 0 if the address is unknown. Used to sort pool
// dialers by effective latency so dialers[0] is always the best available control.
func (r *Router) ControlRTT(addr string) time.Duration {
	r.mu.Lock()
	var rtt time.Duration
	var isUDP bool
	for _, n := range r.controls {
		if n.Addr == addr {
			rtt = n.RTT
			isUDP = n.transport == transportUDP
			break
		}
	}
	r.mu.Unlock()
	penalty := time.Duration(r.flapPenaltyOf(addr) * float64(time.Millisecond))
	if isUDP {
		penalty += udpOnlyPenalty
	}
	return rtt + penalty
}

// RecordControlFlap records one stream eviction for addr. Called from the
// dialer's first-fail hook so the router deprioritises controls that are
// under active DPI interference within the rolling flapWindow.
func (r *Router) RecordControlFlap(addr string) {
	r.flapMu.Lock()
	defer r.flapMu.Unlock()
	now := time.Now()
	if r.flaps == nil {
		r.flaps = make(map[string][]time.Time)
	}
	cutoff := now.Add(-flapWindow)
	prev := r.flaps[addr]
	kept := prev[:0]
	for _, t := range prev {
		if !t.Before(cutoff) {
			kept = append(kept, t)
		}
	}
	r.flaps[addr] = append(kept, now)
}

// flapPenaltyOf returns the penalty in milliseconds for addr based on recent
// stream evictions within flapWindow. Safe to call while r.mu is held.
func (r *Router) flapPenaltyOf(addr string) float64 {
	r.flapMu.Lock()
	defer r.flapMu.Unlock()
	if r.flaps == nil {
		return 0
	}
	cutoff := time.Now().Add(-flapWindow)
	count := 0
	for _, t := range r.flaps[addr] {
		if !t.Before(cutoff) {
			count++
		}
	}
	penalty := float64(count) * float64(flapPenaltyPerEviction.Milliseconds())
	cap := float64(flapPenaltyCap.Milliseconds())
	if penalty > cap {
		return cap
	}
	return penalty
}

// MeasureRTTs probes all relays and all control nodes concurrently via TCP dial.
// Nodes that fail to connect within timeout are marked !IsAlive.
// Deprecated: use ProbeDataPlane for production use; MeasureRTTs does not detect
// DPI body-stripping because it only checks TCP reachability.
func (r *Router) MeasureRTTs(timeout time.Duration) {
	r.mu.Lock()
	nodes := make([]*routerNode, len(r.relays))
	copy(nodes, r.relays)
	nodes = append(nodes, r.controls...)
	r.mu.Unlock()

	var wg sync.WaitGroup
	for _, n := range nodes {
		wg.Add(1)
		go func(n *routerNode) {
			defer wg.Done()
			start := time.Now()
			conn, err := net.DialTimeout("tcp", n.Addr, timeout)
			r.mu.Lock()
			if err != nil {
				n.IsAlive = false
			} else {
				conn.Close()
				n.RTT = time.Since(start)
				n.IsAlive = true
				n.LastSeen = time.Now()
			}
			r.mu.Unlock()
		}(n)
	}
	wg.Wait()
}

// BuildPaths generates, scores, and stores the top-5 candidate paths across all
// alive control nodes.  Call after MeasureRTTs.  The result is accessible via
// Primary / Advance.
func (r *Router) BuildPaths() {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Collect alive control nodes split by country so we can supplement later.
	var aliveControls, outOfCountry []*routerNode
	for _, c := range r.controls {
		if r.alive(c) {
			aliveControls = append(aliveControls, c)
		}
	}
	if r.myCountry != "" {
		var inCountry []*routerNode
		for _, c := range aliveControls {
			if c.CountryCode == r.myCountry {
				inCountry = append(inCountry, c)
			} else {
				outOfCountry = append(outOfCountry, c)
			}
		}
		if len(inCountry) > 0 {
			Log.Printf("router: %d in-country control(s) available (cc=%s) — excluding %d out-of-country",
				len(inCountry), r.myCountry, len(outOfCountry))
			aliveControls = inCountry
		} else {
			Log.Printf("router: no in-country controls (cc=%s) — using all %d alive controls",
				r.myCountry, len(aliveControls))
			outOfCountry = nil // already all included
		}
	}
	// TCP-preference hard filter: if any alive control is reachable via TCP,
	// exclude UDP-only (TCP-blocked) controls entirely.  UDP transport is a
	// last resort used only when every known control has TCP blocked.
	var tcpAlive []*routerNode
	for _, c := range aliveControls {
		if c.transport == transportTCP {
			tcpAlive = append(tcpAlive, c)
		}
	}
	if len(tcpAlive) > 0 {
		if len(tcpAlive) < len(aliveControls) {
			Log.Printf("router: excluded %d UDP-only control(s) — %d TCP-capable available",
				len(aliveControls)-len(tcpAlive), len(tcpAlive))
		}
		aliveControls = tcpAlive
	} else {
		Log.Printf("router: no TCP-capable controls — using all %d (UDP-only fallback)", len(aliveControls))
	}
	// Also apply TCP filter to out-of-country candidates.
	var tcpOutOfCountry []*routerNode
	for _, c := range outOfCountry {
		if c.transport == transportTCP {
			tcpOutOfCountry = append(tcpOutOfCountry, c)
		}
	}
	outOfCountry = tcpOutOfCountry

	if len(aliveControls) == 0 {
		r.paths = nil
		Log.Printf("router: all controls unreachable")
		return
	}

	// If fewer than 3 controls remain, supplement from
	// out-of-country TCP-capable controls sorted by local RTT score.
	// This avoids single-point-of-failure when in-country coverage is thin.
	if len(aliveControls) < 3 && len(outOfCountry) > 0 {
		sort.Slice(outOfCountry, func(i, j int) bool {
			return r.nodeScore(outOfCountry[i]) < r.nodeScore(outOfCountry[j])
		})
		need := 3 - len(aliveControls)
		if need > len(outOfCountry) {
			need = len(outOfCountry)
		}
		Log.Printf("router: pool < 3 after filtering — supplementing with %d out-of-country control(s)", need)
		aliveControls = append(aliveControls, outOfCountry[:need]...)
	}

	// R_best: alive relays within 30 s, sorted by effective RTT+loss, top 20.
	// When myCountry is set, restrict to same-region relays only.
	var live []*routerNode
	for _, n := range r.relays {
		if r.alive(n) {
			if r.myCountry == "" || n.CountryCode == r.myCountry {
				live = append(live, n)
			}
		}
	}
	if r.myCountry != "" && len(live) == 0 {
		Log.Printf("router: no same-region relays (country=%s) — falling back to all alive relays", r.myCountry)
		for _, n := range r.relays {
			if r.alive(n) {
				live = append(live, n)
			}
		}
	}
	sort.Slice(live, func(i, j int) bool {
		return r.nodeScore(live[i]) < r.nodeScore(live[j])
	})
	if len(live) > 20 {
		live = live[:20]
	}

	var paths []RouterPath

	// Generate candidate paths for every alive control node.
	for _, ctrl := range aliveControls {
		// Direct path via this control.
		paths = append(paths, RouterPath{ControlAddr: ctrl.Addr})

		// 1-relay paths.
		for _, r1 := range live {
			paths = append(paths, RouterPath{
				Relays:      []*RouterPathNode{{ID: r1.ID, Addr: r1.Addr}},
				ControlAddr: ctrl.Addr,
			})

			// 2-relay paths (generated for future use; not yet executed).
			for _, r2 := range live {
				if r2.ID == r1.ID || r2.OperatorID == r1.OperatorID {
					continue
				}
				paths = append(paths, RouterPath{
					Relays: []*RouterPathNode{
						{ID: r1.ID, Addr: r1.Addr},
						{ID: r2.ID, Addr: r2.Addr},
					},
					ControlAddr: ctrl.Addr,
				})

				// 3-relay paths (generated for future use; not yet executed).
				for _, r3 := range live {
					if r3.ID == r1.ID || r3.ID == r2.ID {
						continue
					}
					if r3.OperatorID == r1.OperatorID || r3.OperatorID == r2.OperatorID {
						continue
					}
					paths = append(paths, RouterPath{
						Relays: []*RouterPathNode{
							{ID: r1.ID, Addr: r1.Addr},
							{ID: r2.ID, Addr: r2.Addr},
							{ID: r3.ID, Addr: r3.Addr},
						},
						ControlAddr: ctrl.Addr,
					})
				}
			}
		}
	}

	// Score all paths (scorePath looks up the control node by ControlAddr).
	for i := range paths {
		paths[i].Score = r.scorePath(&paths[i], aliveControls, live)
	}

	candidates := paths

	// Sort: relay paths first (obscure signature), then by score.
	sort.SliceStable(candidates, func(i, j int) bool {
		iRelay := len(candidates[i].Relays) > 0
		jRelay := len(candidates[j].Relays) > 0
		if iRelay != jRelay {
			return iRelay // relay paths go first
		}
		return candidates[i].Score < candidates[j].Score
	})
	if len(candidates) > 5 {
		candidates = candidates[:5]
	}

	// Shuffle all candidates so every reconnect picks a random path from the
	// full pool of alive controls. Score-based sorting above ensures the pool
	// is ordered, but weighted randomisation across all entries avoids
	// permanently pinning to the same control under partial interference.
	rand.Shuffle(len(candidates), func(i, j int) {
		candidates[i], candidates[j] = candidates[j], candidates[i]
	})

	r.paths = candidates
	r.pathIdx = 0

	var best float64
	for _, p := range r.paths {
		if best == 0 || p.Score < best {
			best = p.Score
		}
	}
	Log.Printf("router: %d paths built, best=%.0fms", len(r.paths), best)
	for i, p := range r.paths {
		tag := "direct"
		if len(p.Relays) > 0 {
			tag = p.Relays[0].Addr
		}
		Log.Printf("router: path[%d] score=%.0f hops=%d via=%s", i, p.Score, len(p.Relays), tag)
	}
}

// Primary returns the current top-ranked path, or nil if none.
func (r *Router) Primary() *RouterPath {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.paths) == 0 {
		return nil
	}
	p := r.paths[r.pathIdx]
	return &p
}

// Advance marks the current path as failed and moves to the next candidate.
// Returns true if a new path is available, false if all paths are exhausted
// (index wraps back to 0 so the next call to Primary returns the top path).
func (r *Router) Advance() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pathIdx+1 < len(r.paths) {
		r.pathIdx++
		Log.Printf("router: advanced to path[%d]", r.pathIdx)
		return true
	}
	r.pathIdx = 0
	Log.Printf("router: all paths exhausted, wrapping to path[0]")
	return false
}

// Reset returns the path index to 0 (top-ranked path).
func (r *Router) Reset() {
	r.mu.Lock()
	r.pathIdx = 0
	r.mu.Unlock()
}

// PickRandom returns a random path from the current top-N candidates.
// Unlike Primary, it does not advance pathIdx — each call picks independently.
// Use this to distribute concurrent SOCKS5 connections across the qualifying pool.
func (r *Router) PickRandom() *RouterPath {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.paths) == 0 {
		return nil
	}
	p := r.paths[rand.Intn(len(r.paths))]
	return &p
}

// PrimaryIsBetter reports whether switching to the primary path's control is
// warranted.  It returns (true, primary) when:
//   - the primary control differs from currentAddr, AND
//   - the primary's score is at least `factor` times lower than the best score
//     of the current control among the candidate paths (e.g. factor=1.5 means
//     the current control must be ≥50% slower to trigger a switch).
//
// If the current control is absent from all paths (dead), any alive primary is
// preferable and the function returns (true, primary) immediately.
// Returns (false, nil) when staying on the current control is correct.
func (r *Router) PrimaryIsBetter(currentAddr string, factor float64) (bool, *RouterPath) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.paths) == 0 {
		return false, nil
	}
	p := r.paths[r.pathIdx]
	norm := normaliseAddr(currentAddr)
	if p.ControlAddr == norm {
		return false, nil // already on the primary control
	}
	// Find the best score for the current control among candidate paths.
	currentBest := 0.0
	found := false
	for _, path := range r.paths {
		if path.ControlAddr == norm && (!found || path.Score < currentBest) {
			currentBest = path.Score
			found = true
		}
	}
	if !found {
		// Current control has dropped out of all paths — switch immediately.
		return true, &p
	}
	// Switch only when the primary is strictly better by the required margin.
	return p.Score*factor <= currentBest, &p
}

// Paths returns a snapshot of the current candidate paths (post-BuildPaths).
// Used by DialerPool to determine which control addresses qualify.
func (r *Router) Paths() []RouterPath {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]RouterPath, len(r.paths))
	copy(out, r.paths)
	return out
}

// QualifyingControlAddrs returns the unique control addresses present in the
// current candidate paths (post-BuildPaths).  The DialerPool authenticates to
// each of these and distributes connections randomly across them.
func (r *Router) QualifyingControlAddrs() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	seen := make(map[string]struct{}, len(r.paths))
	var out []string
	for _, p := range r.paths {
		if _, ok := seen[p.ControlAddr]; !ok {
			seen[p.ControlAddr] = struct{}{}
			out = append(out, p.ControlAddr)
		}
	}
	return out
}

// AllControlAddrs returns every known control address regardless of liveness.
// TCP-based liveness (alive/LastSeen) is meaningless when direct TCP to
// controls is blocked and an external dial function is in use instead — in
// that case ProbeDataPlane never runs and LastSeen goes stale after 30s.
// Filtering through QualifyingControlAddrs (which only returns addrs present
// in r.paths, itself built from r.alive()) creates a one-way death spiral: a
// control that drops out from staleness is never retried, so it never gets
// marked alive again, so it never returns. Pool building over an external
// transport must use this instead — that transport's own auth success is the
// only liveness signal that matters there.
func (r *Router) AllControlAddrs() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.controls))
	for i, c := range r.controls {
		out[i] = c.Addr
	}
	return out
}

// UnreachableControls returns control addresses that are known but currently
// not alive — i.e. candidates for relay-assisted access.
func (r *Router) UnreachableControls() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, c := range r.controls {
		if !r.alive(c) {
			out = append(out, c.Addr)
		}
	}
	return out
}

// HasUDPPeer reports whether a live UDP relay connection exists for the given node ID.
func (r *Router) HasUDPPeer(nodeID string) bool {
	r.udpMu.Lock()
	defer r.udpMu.Unlock()
	c, ok := r.udpPeers[nodeID]
	return ok && !c.Failed()
}

// ControlTransport returns the transport protocol detected for addr by the last
// ProbeDataPlane call.  Returns transportTCP for unknown addresses.
func (r *Router) ControlTransport(addr string) controlTransport {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.controls {
		if c.Addr == addr {
			return c.transport
		}
	}
	return transportTCP
}

// ControlTransportName returns a human-readable transport name for addr ("tcp" or "udp").
func (r *Router) ControlTransportName(addr string) string {
	if r.ControlTransport(addr) == transportUDP {
		return "udp"
	}
	return "tcp"
}

// NewControlDialer creates the appropriate TunnelDialer for a qualifying control
// address.  When ProbeDataPlane detected that addr is only reachable via UDP,
// the returned dialer sends all tunnel traffic over a direct UDP connection to
// the control.  Otherwise a standard TCP-backed TunnelDialer is returned.
func (r *Router) NewControlDialer(addr string, auth *Authenticator) (*TunnelDialer, error) {
	if r.ControlTransport(addr) == transportUDP {
		conn, err := newUDPControlConn(addr)
		if err != nil {
			return nil, fmt.Errorf("udp-control dialer for %s: %w", addr, err)
		}
		return NewUDPRelayDialer(conn, auth), nil
	}
	return NewTunnelDialer(auth), nil
}

// ── internal helpers ──────────────────────────────────────────────────────────

func (r *Router) alive(n *routerNode) bool {
	if !n.IsAlive || time.Since(n.LastSeen) >= 30*time.Second {
		return false
	}
	if exp, bad := r.dataDead[n.Addr]; bad && time.Now().Before(exp) {
		return false
	}
	return true
}

// UpdateTrafficRTT records a passive round-trip observation for the node at addr.
// addr is matched after normalisation (scheme + path stripped, :443 appended if
// no port is present).  Silently ignored if addr does not match any known node.
func (r *Router) UpdateTrafficRTT(addr string, rtt time.Duration) {
	norm := normaliseAddr(addr)
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.controls {
		if c.Addr == norm {
			c.TrafficRTT = rtt
			return
		}
	}
	for _, rel := range r.relays {
		if rel.Addr == norm {
			rel.TrafficRTT = rtt
			return
		}
	}
}

func (r *Router) nodeScore(n *routerNode) float64 {
	// Blend probe RTT with traffic RTT when both are available.
	// Traffic RTT (passive POST observation) reflects real node load;
	// probe RTT (synthetic ping) captures baseline latency.
	rtt := n.RTT
	if n.TrafficRTT > 0 && n.RTT > 0 {
		rtt = time.Duration(0.3*float64(n.RTT) + 0.7*float64(n.TrafficRTT))
	} else if n.TrafficRTT > 0 {
		rtt = n.TrafficRTT
	}
	return float64(rtt.Milliseconds()) + n.Loss*100 + r.flapPenaltyOf(n.Addr)
}

func instabilityPenalty(n *routerNode) float64 {
	since := time.Since(n.LastSeen)
	switch {
	case since > 15*time.Second:
		return 100
	case since > 5*time.Second:
		return 20
	default:
		return 0
	}
}

func (r *Router) scorePath(p *RouterPath, controls []*routerNode, live []*routerNode) float64 {
	// Control contribution: find the control node matching this path's ControlAddr.
	var ctrl *routerNode
	for _, c := range controls {
		if c.Addr == p.ControlAddr {
			ctrl = c
			break
		}
	}
	var s float64
	if ctrl != nil {
		s = float64(ctrl.RTT.Milliseconds()) + ctrl.Loss*100 + instabilityPenalty(ctrl)
	}

	// Relay contributions.
	for i, rn := range p.Relays {
		var node *routerNode
		for _, n := range live {
			if n.ID == rn.ID {
				node = n
				break
			}
		}
		if node != nil {
			s += float64(node.RTT.Milliseconds()) + node.Loss*100 + instabilityPenalty(node)
		}
		s += 10 // 10 ms relay overhead per hop

		// UDP bonus: direct P2P path has lower effective latency.
		if i == 0 {
			if uc := r.udpPeer(rn.ID, rn.Addr); uc != nil {
				p.UDPRelay = uc
				s -= 30 // 30 ms bonus for live UDP hole punch
			}
		}
	}
	return s
}

// normaliseAddr ensures addr is in "host:port" form.
func normaliseAddr(addr string) string {
	for _, prefix := range []string{"https://", "http://"} {
		addr = trimPrefix(addr, prefix)
	}
	if i := indexByte(addr, '/'); i >= 0 {
		addr = addr[:i]
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return addr + ":443"
	}
	return addr
}

func trimPrefix(s, prefix string) string {
	if len(s) >= len(prefix) && s[:len(prefix)] == prefix {
		return s[len(prefix):]
	}
	return s
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

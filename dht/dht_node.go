// Copyright (c) 2026 Konstantin Khait

package dht

// dht_node.go — DHT node lifecycle.
//
// Responsibilities:
//   - Bootstrap from key-string controls and peers.json warm cache
//   - Announce this node's relay entry (if running as relay) to k closest peers
//   - Respond to FIND_NODE / GET_RELAYS / PING requests
//   - Maintain routing table (add contacts from every inbound message)
//   - Persist routing table to peers.json periodically

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"
)

const (
	bootstrapAlpha = 3
	// announceEvery doubles as NAT keepalive: each announce packet refreshes the
	// UDP mapping on the client's NAT router.  Must be well within typical NAT
	// UDP idle timeout (30-60 s for mobile/Russian ISPs).
	announceEvery = 25 * time.Second
	persistEvery  = 5 * time.Minute
	pingEvery     = 15 * time.Minute
	suspectRetry  = 90 * time.Second
	maxUDPSize    = 4096
	pingTimeout   = 5 * time.Second
)

// Node is a running Kademlia DHT node.
type Node struct {
	id        ID
	conn      *net.UDPConn
	ownAddr   string // advertised address in FindNode responses; defaults to conn.LocalAddr()
	rt        *RoutingTable
	relays    *relayStore
	peersPath string

	// Optional: our own relay entry (set if this node acts as a relay).
	ownEntry *RelayEntry
	// entryRefresher, if set, is called before each announce to produce a fresh
	// signed entry (new TS). Without this, the entry timestamp grows stale after RelayTTL.
	entryRefresher func() (*RelayEntry, error)

	// pendingPings tracks contacts we pinged but haven't heard back from.
	pendingPings map[string]ID
	pingMu       sync.Mutex

	// manifest gossip — push-pull of the signed control node manifest.
	manifestMu  sync.RWMutex
	manifestRaw []byte
	manifestTS  int64
	onManifest  func([]byte)

	// content-manifest gossip — push-pull of the signed content-mirror
	// manifest (arbitrary arbiter-designated files, torrent-like
	// distribution). Independent channel from the control manifest above:
	// unrelated churn, no reason to couple them.
	contentMu       sync.RWMutex
	contentRaw      []byte
	contentTS       int64
	contentComplete bool // true once this node has fully downloaded+verified contentTS
	onContent       func([]byte)
	completePeers   *completeStore

	// holePunchHandler is called when a MsgHolePunch invitation arrives.
	holePunchHandler func(peerAddr, controlURL string)

	// mirrorPunchHandler is called when a MsgMirrorPunch invitation arrives
	// (content-chunk transfer, parallel to holePunchHandler but with no
	// control-forwarding target — see MirrorPunchPayload).
	mirrorPunchHandler func(peerAddr string)

	// Injectable peers-file crypto. Defaults to no-op (plaintext).
	encryptFn func([]byte) ([]byte, error)
	decryptFn func([]byte) ([]byte, error)

	log  *log.Logger
	mu   sync.Mutex
	done chan struct{}
}

// NewNode creates a DHT node.
// logger: used for all debug/info output — pass log.New(os.Stderr,...) or a no-op logger.
// encryptFn/decryptFn: used for peers.json persistence; pass nil for plaintext.
func NewNode(id ID, conn *net.UDPConn, peersPath string, logger *log.Logger,
	encryptFn, decryptFn func([]byte) ([]byte, error)) *Node {

	if logger == nil {
		logger = log.New(os.Stderr, "[dht] ", log.LstdFlags)
	}
	noOp := func(b []byte) ([]byte, error) { return b, nil }
	if encryptFn == nil {
		encryptFn = noOp
	}
	if decryptFn == nil {
		decryptFn = noOp
	}
	return &Node{
		id:            id,
		conn:          conn,
		rt:            NewRoutingTable(id),
		relays:        newRelayStore(),
		peersPath:     peersPath,
		pendingPings:  make(map[string]ID),
		encryptFn:     encryptFn,
		decryptFn:     decryptFn,
		log:           logger,
		done:          make(chan struct{}),
		completePeers: newCompleteStore(),
	}
}

func (n *Node) SetOwnEntry(e *RelayEntry) {
	n.mu.Lock()
	n.ownEntry = e
	n.mu.Unlock()
	// Announce immediately — don't wait for the first maintenance tick.
	go n.announce()
}

// SetEntryRefresher registers a callback that is invoked before each announce
// to produce a freshly-signed entry (updated TS).  Without this the TS baked
// into the initial entry grows stale after RelayTTL and peers reject the announce.
func (n *Node) SetEntryRefresher(f func() (*RelayEntry, error)) {
	n.mu.Lock()
	n.entryRefresher = f
	n.mu.Unlock()
}

// OwnEntry returns the node's current relay entry, or nil if not set.
func (n *Node) OwnEntry() *RelayEntry {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.ownEntry
}

// SetManifest stores the current signed manifest so this node can gossip it.
func (n *Node) SetManifest(raw []byte, ts int64) {
	n.manifestMu.Lock()
	defer n.manifestMu.Unlock()
	if ts > n.manifestTS {
		n.manifestRaw = make([]byte, len(raw))
		copy(n.manifestRaw, raw)
		n.manifestTS = ts
		n.log.Printf("dht: manifest updated ts=%d (%d bytes)", ts, len(raw))
	}
}

// SetHolePunchHandler registers a callback invoked when a MsgHolePunch invitation arrives.
// fn receives the sender's external UDP address (ip:port) and the control URL the relay
// should forward tunnel traffic to.  Pass nil to disable (controls never punch).
func (n *Node) SetHolePunchHandler(fn func(peerAddr, controlURL string)) {
	n.mu.Lock()
	n.holePunchHandler = fn
	n.mu.Unlock()
}

// SetManifestHandler registers a callback invoked when a newer manifest arrives via gossip.
func (n *Node) SetManifestHandler(fn func([]byte)) {
	n.manifestMu.Lock()
	n.onManifest = fn
	n.manifestMu.Unlock()
}

// Bootstrap seeds the routing table from known addresses and peers.json cache.
// For each seed, a FindNode (not Ping) is sent so the seed responds with its
// routing table contacts AND its own ID, allowing us to add it to our RT.
func (n *Node) Bootstrap(seeds []string) {
	n.loadPeers()
	for _, addr := range seeds {
		n.findNodeDirect(addr, n.id)
	}
	n.findNode(n.id) // query any contacts already in RT (warm peers.json cache)
	n.log.Printf("dht: bootstrap complete rt_size=%d", n.rt.Size())
}

// Start launches the receive loop and maintenance goroutines.
// Use when the Node manages its own UDP socket exclusively.
func (n *Node) Start() {
	go n.recvLoop()
	go n.maintainLoop()
}

// StartMaintenance starts only the maintenance goroutine (announce, persist, ping).
// Use when packets are dispatched externally via HandleInbound (shared socket).
func (n *Node) StartMaintenance() {
	go n.maintainLoop()
}

// HandleInbound processes a raw DHT datagram received from outside the recvLoop.
// The packet is authenticated and dispatched asynchronously.
func (n *Node) HandleInbound(pkt []byte, src *net.UDPAddr) {
	cp := make([]byte, len(pkt))
	copy(cp, pkt)
	go n.handlePacket(cp, src)
}

// SaveRelays persists current relay store entries to a JSON file so they
// survive restarts and can be used as bootstrap candidates on reconnect.
func (n *Node) SaveRelays(path string) error {
	entries := n.relays.all()
	if len(entries) == 0 {
		return nil
	}
	data, err := json.Marshal(entries)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// LoadRelays reads relay entries saved by SaveRelays and stores them.
// Stale entries (older than RelayTTL) are silently dropped.
func (n *Node) LoadRelays(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var entries []RelayEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return err
	}
	loaded := 0
	for _, e := range entries {
		if err := n.relays.store(e); err == nil {
			loaded++
		}
	}
	n.log.Printf("dht: loaded %d relay(s) from %s", loaded, path)
	return nil
}

// Stop shuts down the node.
func (n *Node) Stop() {
	close(n.done)
	n.conn.Close()
}

// Relays returns all known relay entries from the store.
func (n *Node) Relays() []RelayEntry {
	return n.relays.all()
}

// RoutingTableSize returns the number of contacts currently in the routing table.
func (n *Node) RoutingTableSize() int { return n.rt.Size() }

// SetOwnAddr sets the address this node advertises in FindNode responses.
// Call this when the node is bound to a wildcard address (0.0.0.0 / [::]) but
// the actual reachable address is known (e.g. the control node's public IP).
func (n *Node) SetOwnAddr(addr string) {
	n.mu.Lock()
	n.ownAddr = addr
	n.mu.Unlock()
}

// selfAddr returns the address to advertise in outbound messages.
func (n *Node) selfAddr() string {
	n.mu.Lock()
	a := n.ownAddr
	n.mu.Unlock()
	if a != "" {
		return a
	}
	return n.conn.LocalAddr().String()
}

// isValidContactAddr returns false for wildcard or unspecified addresses that
// cannot be used to reach a peer (e.g. "[::]:443" or "0.0.0.0:443").
func isValidContactAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return !ip.IsUnspecified()
}

// Announce sends the node's own relay entry to the k closest peers immediately.
// Exported for testing; in production the maintenance loop calls this on its own schedule.
func (n *Node) Announce() { n.announce() }

// SendHolePunch sends a MsgHolePunch invitation to relayAddr telling it to punch
// back to ownAddr and forward tunnel traffic to controlURL.
func (n *Node) SendHolePunch(relayAddr, ownAddr, controlURL string) {
	raddr, err := net.ResolveUDPAddr("udp", relayAddr)
	if err != nil {
		n.log.Printf("dht: SendHolePunch resolve %s: %v", relayAddr, err)
		return
	}
	pkt, err := Seal(MsgHolePunch, MaxTTL, HolePunchPayload{Peer: ownAddr, Control: controlURL})
	if err != nil {
		return
	}
	n.send(pkt, raddr)
	n.log.Printf("dht: sent hole_punch → %s peer=%s control=%s", relayAddr, ownAddr, controlURL)
}

// SetMirrorPunchHandler registers a callback invoked when a MsgMirrorPunch
// invitation arrives. fn receives the sender's external UDP address; the
// receiver is expected to punch back for content-chunk transfer (not
// tunnel relaying — see SetHolePunchHandler for that). Pass nil to disable.
func (n *Node) SetMirrorPunchHandler(fn func(peerAddr string)) {
	n.mu.Lock()
	n.mirrorPunchHandler = fn
	n.mu.Unlock()
}

// SendMirrorPunch sends a MsgMirrorPunch invitation to peerAddr telling it
// to punch back to ownAddr for content-chunk transfer.
func (n *Node) SendMirrorPunch(peerAddr, ownAddr string) {
	raddr, err := net.ResolveUDPAddr("udp", peerAddr)
	if err != nil {
		n.log.Printf("dht: SendMirrorPunch resolve %s: %v", peerAddr, err)
		return
	}
	pkt, err := Seal(MsgMirrorPunch, MaxTTL, MirrorPunchPayload{Peer: ownAddr})
	if err != nil {
		return
	}
	n.send(pkt, raddr)
	n.log.Printf("dht: sent mirror_punch → %s peer=%s", peerAddr, ownAddr)
}

// ── Receive loop ──────────────────────────────────────────────────────────────

func (n *Node) recvLoop() {
	buf := make([]byte, maxUDPSize)
	for {
		size, src, err := n.conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-n.done:
				return
			default:
				n.log.Printf("dht: recv error: %v", err)
				continue
			}
		}
		pkt := make([]byte, size)
		copy(pkt, buf[:size])
		go n.handlePacket(pkt, src)
	}
}

func (n *Node) handlePacket(pkt []byte, src *net.UDPAddr) {
	msgType, ttl, raw, err := Open(pkt)
	if err != nil {
		n.log.Printf("dht: drop bad packet from %s: %v", src, err)
		return
	}

	n.log.Printf("dht: recv type=0x%02x ttl=%d src=%s payload=%d bytes", msgType, ttl, src, len(raw))

	n.clearSuspectByAddr(src)

	switch msgType {
	case MsgPing:
		n.handlePing(src, ttl)
	case MsgPong:
		n.log.Printf("dht: pong from %s", src)
	case MsgFindNode:
		n.handleFindNode(src, ttl, raw)
	case MsgNodes:
		n.handleNodes(src, raw)
	case MsgAnnounce:
		n.handleAnnounce(src, raw)
	case MsgAck:
		n.log.Printf("dht: ack from %s", src)
	case MsgGetRelays:
		n.handleGetRelays(src, ttl)
	case MsgRelayList:
		n.handleRelayList(raw)
	case MsgManifestHave:
		n.handleManifestHave(src, raw)
	case MsgManifestWant:
		n.handleManifestWant(src)
	case MsgManifest:
		n.handleManifestData(raw)
	case MsgHolePunch:
		n.handleHolePunch(src, raw)
	case MsgMirrorPunch:
		n.handleMirrorPunch(src, raw)
	case MsgContentHave:
		n.handleContentHave(src, raw)
	case MsgContentWant:
		n.handleContentWant(src)
	case MsgContent:
		n.handleContentData(src, raw)
	default:
		n.log.Printf("dht: unknown msg type 0x%02x from %s — drop", msgType, src)
	}
}

func (n *Node) clearSuspectByAddr(src *net.UDPAddr) {
	addr := src.String()
	n.pingMu.Lock()
	id, pending := n.pendingPings[addr]
	if pending {
		delete(n.pendingPings, addr)
	}
	n.pingMu.Unlock()

	if pending {
		n.rt.ResetMissed(id)
		n.log.Printf("dht: contact %s responded — suspect cleared", addr)
	}
}

// ── Message handlers ─────────────────────────────────────────────────────────

func (n *Node) handlePing(src *net.UDPAddr, ttl uint8) {
	n.learnContact(src)
	pong, err := Seal(MsgPong, MaxTTL, nil)
	if err != nil {
		return
	}
	n.send(pong, src)
	n.log.Printf("dht: pong → %s", src)
}

func (n *Node) handleFindNode(src *net.UDPAddr, ttl uint8, raw []byte) {
	n.learnContact(src)

	var req FindNodePayload
	if err := json.Unmarshal(raw, &req); err != nil {
		n.log.Printf("dht: bad find_node from %s: %v", src, err)
		return
	}
	target, err := ParseID(req.Target)
	if err != nil {
		n.log.Printf("dht: bad find_node target from %s: %v", src, err)
		return
	}

	if c, err := ContactFromJSON(req.From); err == nil {
		n.rt.Add(c)
	}

	closest := n.rt.Closest(target, K)
	nodes := make([]ContactJSON, len(closest))
	for i, c := range closest {
		nodes[i] = ContactToJSON(c)
	}

	resp, err := Seal(MsgNodes, MaxTTL, NodesPayload{
		From:  ContactJSON{ID: n.id.String(), Addr: n.selfAddr()},
		Nodes: nodes,
	})
	if err != nil {
		return
	}
	n.send(resp, src)
	n.log.Printf("dht: nodes(%d) → %s for target %s", len(nodes), src, req.Target)
}

func (n *Node) handleNodes(src *net.UDPAddr, raw []byte) {
	n.learnContact(src)

	var resp NodesPayload
	if err := json.Unmarshal(raw, &resp); err != nil {
		n.log.Printf("dht: bad nodes from %s: %v", src, err)
		return
	}
	added := 0
	// Add the responder itself to the routing table using the From field.
	if resp.From.ID != "" && isValidContactAddr(resp.From.Addr) {
		if c, err := ContactFromJSON(resp.From); err == nil {
			n.rt.Add(c)
			added++
		}
	}
	for _, j := range resp.Nodes {
		if !isValidContactAddr(j.Addr) {
			continue
		}
		c, err := ContactFromJSON(j)
		if err == nil {
			n.rt.Add(c)
			added++
		}
	}
	n.log.Printf("dht: learned %d contacts from %s (rt_size=%d)", added, src, n.rt.Size())
}

func (n *Node) handleAnnounce(src *net.UDPAddr, raw []byte) {
	n.learnContact(src)

	var req AnnouncePayload
	if err := json.Unmarshal(raw, &req); err != nil {
		n.log.Printf("dht: bad announce from %s: %v", src, err)
		return
	}

	if err := n.relays.store(req.Entry); err != nil {
		n.log.Printf("dht: reject announce from %s: %v", src, err)
		return
	}
	n.log.Printf("dht: stored relay entry node=%s addr=%s cc=%s from %s",
		req.Entry.NodeID, req.Entry.Addr, req.Entry.CountryCode, src)

	ack, _ := Seal(MsgAck, MaxTTL, nil)
	n.send(ack, src)
}

func (n *Node) handleGetRelays(src *net.UDPAddr, ttl uint8) {
	n.learnContact(src)

	entries := n.relays.all()
	resp, err := Seal(MsgRelayList, MaxTTL, RelayListPayload{Entries: entries})
	if err != nil {
		return
	}
	n.send(resp, src)
	n.log.Printf("dht: relay_list(%d entries) → %s", len(entries), src)
}

func (n *Node) handleRelayList(raw []byte) {
	var resp RelayListPayload
	if err := json.Unmarshal(raw, &resp); err != nil {
		return
	}
	for _, e := range resp.Entries {
		if err := n.relays.store(e); err == nil {
			n.log.Printf("dht: relay_list: stored %s@%s", e.NodeID, e.Addr)
		}
	}
}

func (n *Node) handleManifestHave(src *net.UDPAddr, raw []byte) {
	var req ManifestHavePayload
	if err := json.Unmarshal(raw, &req); err != nil {
		n.log.Printf("dht: bad manifest_have from %s: %v", src, err)
		return
	}
	n.manifestMu.RLock()
	ours := n.manifestTS
	n.manifestMu.RUnlock()

	if req.TS > ours {
		n.log.Printf("dht: manifest_have from %s ts=%d > ours=%d — requesting", src, req.TS, ours)
		pkt, err := Seal(MsgManifestWant, MaxTTL, nil)
		if err != nil {
			return
		}
		n.send(pkt, src)
	} else {
		n.log.Printf("dht: manifest_have from %s ts=%d <= ours=%d — ignoring", src, req.TS, ours)
	}
}

func (n *Node) handleManifestWant(src *net.UDPAddr) {
	n.manifestMu.RLock()
	raw := n.manifestRaw
	ts := n.manifestTS
	n.manifestMu.RUnlock()

	if len(raw) == 0 {
		n.log.Printf("dht: manifest_want from %s — no manifest to send", src)
		return
	}
	pkt, err := Seal(MsgManifest, MaxTTL, ManifestPayload{
		TS:  ts,
		Raw: json.RawMessage(raw),
	})
	if err != nil {
		return
	}
	n.send(pkt, src)
	n.log.Printf("dht: manifest → %s ts=%d (%d bytes)", src, ts, len(raw))
}

func (n *Node) handleManifestData(raw []byte) {
	var msg ManifestPayload
	if err := json.Unmarshal(raw, &msg); err != nil {
		n.log.Printf("dht: bad manifest payload: %v", err)
		return
	}
	n.manifestMu.Lock()
	if msg.TS <= n.manifestTS {
		n.manifestMu.Unlock()
		n.log.Printf("dht: manifest ts=%d not newer than ours=%d — drop", msg.TS, n.manifestTS)
		return
	}
	cb := n.onManifest
	n.manifestMu.Unlock()

	n.log.Printf("dht: manifest ts=%d newer than ours — passing to discovery (%d bytes)", msg.TS, len(msg.Raw))
	if cb != nil {
		cb([]byte(msg.Raw))
	}
}

func (n *Node) handleHolePunch(src *net.UDPAddr, raw []byte) {
	// raw may be empty (probes from holepunch.go use nil payload).
	// Only act when there is a peer address payload — that is a punch invitation.
	if len(raw) == 0 {
		return
	}
	var payload HolePunchPayload
	if err := json.Unmarshal(raw, &payload); err != nil || payload.Peer == "" {
		n.log.Printf("dht: hole_punch from %s: bad payload: %v", src, err)
		return
	}
	n.mu.Lock()
	fn := n.holePunchHandler
	n.mu.Unlock()
	if fn == nil {
		n.log.Printf("dht: hole_punch invitation from %s (peer=%s) — no handler registered", src, payload.Peer)
		return
	}
	// Loop guard: ignore if the control URL points back at our own DHT address.
	if payload.Control != "" && payload.Control == n.selfAddr() {
		n.log.Printf("dht: hole_punch from %s: control=%s matches own addr — dropping (loop)", src, payload.Control)
		return
	}
	n.log.Printf("dht: hole_punch invitation from %s peer=%s control=%s — starting punch", src, payload.Peer, payload.Control)
	go fn(payload.Peer, payload.Control)
}

// ── Active operations ─────────────────────────────────────────────────────────

func (n *Node) pingAddr(addr string) {
	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		n.log.Printf("dht: ping resolve %s: %v", addr, err)
		return
	}
	pkt, err := Seal(MsgPing, 0, nil)
	if err != nil {
		return
	}
	n.send(pkt, raddr)
	n.log.Printf("dht: ping → %s", addr)

	closest := n.rt.Closest(n.id, K*IDBits)
	var contactID *ID
	for _, c := range closest {
		if c.Addr == addr {
			id := c.ID
			contactID = &id
			break
		}
	}
	if contactID == nil {
		return
	}
	id := *contactID
	n.pingMu.Lock()
	n.pendingPings[addr] = id
	n.pingMu.Unlock()

	go func() {
		select {
		case <-time.After(pingTimeout):
		case <-n.done:
			return
		}
		n.pingMu.Lock()
		if _, still := n.pendingPings[addr]; still {
			delete(n.pendingPings, addr)
			n.pingMu.Unlock()
			n.rt.MarkMissed(id)
			n.log.Printf("dht: ping timeout %s — missed ping count incremented", addr)
		} else {
			n.pingMu.Unlock()
		}
	}()
}

func (n *Node) findNode(target ID) {
	closest := n.rt.Closest(target, bootstrapAlpha)
	from := ContactJSON{
		ID:   n.id.String(),
		Addr: n.selfAddr(),
	}
	payload := FindNodePayload{From: from, Target: target.String()}

	for _, c := range closest {
		pkt, err := Seal(MsgFindNode, 0, payload)
		if err != nil {
			continue
		}
		raddr, err := net.ResolveUDPAddr("udp", c.Addr)
		if err != nil {
			continue
		}
		n.send(pkt, raddr)
		n.log.Printf("dht: find_node target=%s → %s", target, c.Addr)
	}
}

// findNodeDirect sends a FindNode message to a known address without requiring
// it to be in the routing table. Used during bootstrap to query seeds directly.
// The seed responds with MsgNodes containing its own ID (via From field) and
// close contacts, which seeds our routing table.
func (n *Node) findNodeDirect(addr string, target ID) {
	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		n.log.Printf("dht: find_node_direct resolve %s: %v", addr, err)
		return
	}
	from := ContactJSON{
		ID:   n.id.String(),
		Addr: n.selfAddr(),
	}
	payload := FindNodePayload{From: from, Target: target.String()}
	pkt, err := Seal(MsgFindNode, 0, payload)
	if err != nil {
		return
	}
	n.send(pkt, raddr)
	n.log.Printf("dht: find_node target=%s → %s (direct)", target, addr)
}

func (n *Node) announce() {
	n.mu.Lock()
	if n.entryRefresher != nil {
		if fresh, err := n.entryRefresher(); err == nil {
			n.ownEntry = fresh
		} else {
			n.log.Printf("dht: entry refresh failed: %v", err)
		}
	}
	entry := n.ownEntry
	n.mu.Unlock()
	if entry == nil {
		return
	}

	id, err := ParseID(entry.NodeID)
	if err != nil {
		return
	}
	closest := n.rt.Closest(id, K)
	payload := AnnouncePayload{Entry: *entry}
	sent := 0
	for _, c := range closest {
		pkt, err := Seal(MsgAnnounce, 0, payload)
		if err != nil {
			continue
		}
		raddr, err := net.ResolveUDPAddr("udp", c.Addr)
		if err != nil {
			continue
		}
		n.send(pkt, raddr)
		sent++
	}
	n.log.Printf("dht: announced relay entry to %d peers", sent)
}

func (n *Node) getRelays() {
	closest := n.rt.Closest(n.id, K)
	for _, c := range closest {
		pkt, err := Seal(MsgGetRelays, 0, nil)
		if err != nil {
			continue
		}
		raddr, err := net.ResolveUDPAddr("udp", c.Addr)
		if err != nil {
			continue
		}
		n.send(pkt, raddr)
		n.log.Printf("dht: get_relays → %s", c.Addr)
	}
}

func (n *Node) gossipManifestHave() {
	n.manifestMu.RLock()
	ts := n.manifestTS
	n.manifestMu.RUnlock()
	if ts == 0 {
		return
	}

	peers := n.rt.Closest(n.id, K)
	if len(peers) == 0 {
		return
	}
	pkt, err := Seal(MsgManifestHave, MaxTTL, ManifestHavePayload{TS: ts})
	if err != nil {
		return
	}
	for _, c := range peers {
		raddr, err := net.ResolveUDPAddr("udp", c.Addr)
		if err != nil {
			continue
		}
		n.send(pkt, raddr)
	}
	n.log.Printf("dht: gossip manifest_have ts=%d to %d peer(s)", ts, len(peers))
}

// ── Maintenance loop ──────────────────────────────────────────────────────────

func (n *Node) maintainLoop() {
	announceTick := time.NewTicker(announceEvery)
	persistTick := time.NewTicker(persistEvery)
	pingTick := time.NewTicker(pingEvery)
	suspectTick := time.NewTicker(suspectRetry)
	defer announceTick.Stop()
	defer persistTick.Stop()
	defer pingTick.Stop()
	defer suspectTick.Stop()

	time.AfterFunc(5*time.Second, func() {
		n.announce()
		n.getRelays()
	})

	for {
		select {
		case <-n.done:
			n.savePeers()
			return
		case <-announceTick.C:
			n.announce()
			n.getRelays()
			n.gossipManifestHave()
			n.gossipContentHave()
		case <-persistTick.C:
			n.savePeers()
		case <-pingTick.C:
			n.pingStale()
		case <-suspectTick.C:
			n.reprobeSuspects()
		}
	}
}

func (n *Node) reprobeSuspects() {
	suspects := n.rt.SuspectContacts()
	if len(suspects) == 0 {
		return
	}
	n.log.Printf("dht: re-probing %d suspect node(s)", len(suspects))
	for _, c := range suspects {
		n.pingAddr(c.Addr)
	}
}

func (n *Node) pingStale() {
	all := n.rt.All()
	if len(all) == 0 {
		return
	}
	oldest := all[0]
	for _, c := range all[1:] {
		if c.LastSeen.Before(oldest.LastSeen) {
			oldest = c
		}
	}
	n.pingAddr(oldest.Addr)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func (n *Node) learnContact(src *net.UDPAddr) { _ = src }

func (n *Node) send(pkt []byte, dst *net.UDPAddr) {
	if _, err := n.conn.WriteToUDP(pkt, dst); err != nil {
		n.log.Printf("dht: send to %s: %v", dst, err)
	}
}

// ── Persistence ───────────────────────────────────────────────────────────────

type peersFile struct {
	Contacts []ContactJSON `json:"contacts"`
}

func (n *Node) savePeers() {
	if n.peersPath == "" {
		return
	}
	contacts := n.rt.All()
	jc := make([]ContactJSON, len(contacts))
	for i, c := range contacts {
		jc[i] = ContactToJSON(c)
	}
	plain, err := json.Marshal(peersFile{Contacts: jc})
	if err != nil {
		n.log.Printf("dht: peers marshal: %v", err)
		return
	}
	enc, err := n.encryptFn(plain)
	if err != nil {
		n.log.Printf("dht: peers encrypt: %v", err)
		return
	}
	if err := os.WriteFile(n.peersPath, enc, 0600); err != nil {
		n.log.Printf("dht: peers write %s: %v", n.peersPath, err)
		return
	}
	n.log.Printf("dht: persisted %d contacts to %s", len(contacts), n.peersPath)
}

func (n *Node) loadPeers() {
	if n.peersPath == "" {
		return
	}
	enc, err := os.ReadFile(n.peersPath)
	if err != nil {
		if !os.IsNotExist(err) {
			n.log.Printf("dht: peers read %s: %v", n.peersPath, err)
		}
		return
	}
	plain, err := n.decryptFn(enc)
	if err != nil {
		// Try legacy plaintext.
		n.log.Printf("dht: peers decrypt failed (%v) — trying legacy plaintext", err)
		plain = enc
	}
	var pf peersFile
	if err := json.Unmarshal(plain, &pf); err != nil {
		n.log.Printf("dht: peers parse %s: %v", n.peersPath, err)
		return
	}
	loaded := 0
	for _, j := range pf.Contacts {
		c, err := ContactFromJSON(j)
		if err == nil {
			n.rt.Add(c)
			loaded++
		}
	}
	n.log.Printf("dht: loaded %d peers from %s", loaded, n.peersPath)
}

// ── RelayStore ────────────────────────────────────────────────────────────────

type relayStore struct {
	mu      sync.RWMutex
	entries map[string]RelayEntry
}

func newRelayStore() *relayStore {
	return &relayStore{entries: make(map[string]RelayEntry)}
}

func (s *relayStore) store(e RelayEntry) error {
	if err := VerifyRelayEntry(&e); err != nil {
		return fmt.Errorf("relay-store: invalid sig: %w", err)
	}
	now := time.Now().Unix()
	age := now - e.TS
	if age > int64(RelayTTL.Seconds()) || age < -int64(RelayTTL.Seconds()) {
		return fmt.Errorf("relay-store: stale/future entry ts=%d age=%ds", e.TS, age)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.entries[e.NodeID]; ok && existing.TS >= e.TS {
		return nil
	}
	s.entries[e.NodeID] = e
	return nil
}

func (s *relayStore) all() []RelayEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := time.Now().Unix()
	out := make([]RelayEntry, 0, len(s.entries))
	for _, e := range s.entries {
		if now-e.TS <= int64(RelayTTL.Seconds()) {
			out = append(out, e)
		}
	}
	return out
}

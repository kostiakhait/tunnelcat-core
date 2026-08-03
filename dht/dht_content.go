// Copyright (c) 2026 Konstantin Khait

package dht

// dht_content.go — content-manifest gossip: push-pull distribution of an
// arbiter-signed, arbitrary file manifest (torrent-like mirroring), plus a
// lightweight "who has fully downloaded it" index built as a side effect of
// the same gossip. Wire mechanics are a 1:1 mirror of the control-manifest
// gossip in dht_node.go (gossipManifestHave/handleManifestHave/
// handleManifestWant/handleManifestData) — kept as an independent channel
// because content churn (files added/removed) and control-manifest churn
// (control nodes added/removed) are unrelated events.

import (
	"encoding/json"
	"net"
	"sync"
	"time"
)

// SetContent stores the current signed content manifest so this node can
// gossip it. Called by control (after fetching+verifying via the exit-proxy)
// or by a client that just received a newer manifest via gossip and wants to
// re-serve it to its own peers. A genuinely new version always resets
// contentComplete to false — completeness must be re-earned by actually
// downloading the new version's chunks.
func (n *Node) SetContent(raw []byte, ts int64) {
	n.contentMu.Lock()
	defer n.contentMu.Unlock()
	if ts > n.contentTS {
		n.contentRaw = make([]byte, len(raw))
		copy(n.contentRaw, raw)
		n.contentTS = ts
		n.contentComplete = false
		n.log.Printf("dht: content manifest updated ts=%d (%d bytes)", ts, len(raw))
	}
}

// SetContentComplete marks (or unmarks) this node as having fully
// downloaded+verified all chunks for content-manifest version ts. Only takes
// effect if ts still matches the currently-known manifest version — a stale
// call (e.g. a download that finished after a newer manifest already
// arrived) is a no-op.
func (n *Node) SetContentComplete(ts int64, complete bool) {
	n.contentMu.Lock()
	defer n.contentMu.Unlock()
	if ts == n.contentTS {
		n.contentComplete = complete
		n.log.Printf("dht: content complete=%v ts=%d", complete, ts)
	}
}

// SetContentHandler registers a callback invoked when a newer content
// manifest arrives via gossip. Mirrors SetManifestHandler.
func (n *Node) SetContentHandler(fn func([]byte)) {
	n.contentMu.Lock()
	n.onContent = fn
	n.contentMu.Unlock()
}

// CompletePeers returns the addresses of peers known — via gossip received
// so far — to have fully downloaded content-manifest version ts. This is
// the entire "who has it" index for v1: no dedicated discovery protocol,
// just a table built opportunistically from the same Have gossip that
// announces new versions.
func (n *Node) CompletePeers(ts int64) []string {
	return n.completePeers.peersFor(ts)
}

// ── Gossip (sender side) ──────────────────────────────────────────────────────

// GossipContentHave sends the content-manifest Have advertisement to the K
// closest routing-table contacts immediately. Exported for testing; in
// production the maintenance loop calls this on its own 25s schedule
// (mirrors the existing Announce()/gossipManifestHave pairing).
func (n *Node) GossipContentHave() { n.gossipContentHave() }

func (n *Node) gossipContentHave() {
	n.contentMu.RLock()
	ts := n.contentTS
	complete := n.contentComplete
	n.contentMu.RUnlock()
	if ts == 0 {
		return
	}

	peers := n.rt.Closest(n.id, K)
	if len(peers) == 0 {
		return
	}
	pkt, err := Seal(MsgContentHave, MaxTTL, ContentHavePayload{TS: ts, Complete: complete})
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
	n.log.Printf("dht: gossip content_have ts=%d complete=%v to %d peer(s)", ts, complete, len(peers))
}

// ── Message handlers (receiver side) ──────────────────────────────────────────

func (n *Node) handleContentHave(src *net.UDPAddr, raw []byte) {
	var req ContentHavePayload
	if err := json.Unmarshal(raw, &req); err != nil {
		n.log.Printf("dht: bad content_have from %s: %v", src, err)
		return
	}

	// Record regardless of whether we end up requesting the manifest — this
	// is the only mechanism building the "who has fully downloaded it" table.
	n.completePeers.record(src.String(), req.TS, req.Complete)

	n.contentMu.RLock()
	ours := n.contentTS
	n.contentMu.RUnlock()

	if req.TS > ours {
		n.log.Printf("dht: content_have from %s ts=%d > ours=%d — requesting", src, req.TS, ours)
		pkt, err := Seal(MsgContentWant, MaxTTL, nil)
		if err != nil {
			return
		}
		n.send(pkt, src)
	} else {
		n.log.Printf("dht: content_have from %s ts=%d <= ours=%d — ignoring", src, req.TS, ours)
	}
}

func (n *Node) handleContentWant(src *net.UDPAddr) {
	n.contentMu.RLock()
	raw := n.contentRaw
	ts := n.contentTS
	n.contentMu.RUnlock()

	if len(raw) == 0 {
		n.log.Printf("dht: content_want from %s — no content manifest to send", src)
		return
	}
	pkt, err := Seal(MsgContent, MaxTTL, ContentPayload{
		TS:  ts,
		Raw: json.RawMessage(raw),
	})
	if err != nil {
		return
	}
	n.send(pkt, src)
	n.log.Printf("dht: content_manifest → %s ts=%d (%d bytes)", src, ts, len(raw))
}

func (n *Node) handleContentData(src *net.UDPAddr, raw []byte) {
	var msg ContentPayload
	if err := json.Unmarshal(raw, &msg); err != nil {
		n.log.Printf("dht: bad content_manifest payload from %s: %v", src, err)
		return
	}
	n.contentMu.Lock()
	if msg.TS <= n.contentTS {
		n.contentMu.Unlock()
		n.log.Printf("dht: content_manifest ts=%d from %s not newer than ours=%d — drop", msg.TS, src, n.contentTS)
		return
	}
	cb := n.onContent
	n.contentMu.Unlock()

	n.log.Printf("dht: content_manifest ts=%d from %s newer than ours — passing to mirror manager (%d bytes)", msg.TS, src, len(msg.Raw))
	if cb != nil {
		cb([]byte(msg.Raw))
	}
}

func (n *Node) handleMirrorPunch(src *net.UDPAddr, raw []byte) {
	if len(raw) == 0 {
		return
	}
	var payload MirrorPunchPayload
	if err := json.Unmarshal(raw, &payload); err != nil || payload.Peer == "" {
		n.log.Printf("dht: mirror_punch from %s: bad payload: %v", src, err)
		return
	}
	n.mu.Lock()
	fn := n.mirrorPunchHandler
	n.mu.Unlock()
	if fn == nil {
		n.log.Printf("dht: mirror_punch invitation from %s (peer=%s) — no handler registered", src, payload.Peer)
		return
	}
	n.log.Printf("dht: mirror_punch invitation from %s peer=%s — starting punch", src, payload.Peer)
	go fn(payload.Peer)
}

// ── "Who has it" index ─────────────────────────────────────────────────────────

type completePeerEntry struct {
	addr     string
	ts       int64
	complete bool
	lastSeen time.Time
}

// completeStore tracks, per peer address, the last content-manifest
// have-gossip we received from them. Entries older than RelayTTL are treated
// as stale (same staleness window already used for relay entries).
type completeStore struct {
	mu      sync.RWMutex
	entries map[string]completePeerEntry
}

func newCompleteStore() *completeStore {
	return &completeStore{entries: make(map[string]completePeerEntry)}
}

func (s *completeStore) record(addr string, ts int64, complete bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[addr] = completePeerEntry{addr: addr, ts: ts, complete: complete, lastSeen: time.Now()}
}

// peersFor returns addresses of peers last reported as complete for exactly
// ts, excluding entries older than RelayTTL.
func (s *completeStore) peersFor(ts int64) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cutoff := time.Now().Add(-RelayTTL)
	var out []string
	for _, e := range s.entries {
		if e.complete && e.ts == ts && e.lastSeen.After(cutoff) {
			out = append(out, e.addr)
		}
	}
	return out
}

// Copyright (c) 2026 Konstantin Khait

package dht

// Kademlia-inspired DHT for relay peer discovery.
//
// Goal: clients find each other without the control node. If ANY relay in the
// mesh can reach the control, all relays can route traffic through it.
//
// Key decisions (see PLAN.md M4.2):
//   - Algorithm: Kademlia XOR metric, k-buckets (k=8), 256-bit IDs (NodeID)
//   - Wire:      custom encrypted UDP — no recognisable Kademlia header for DPI
//   - Auth:      relay entries are Ed25519-signed by the publisher's NodeID key
//   - Bootstrap: control relay list + local peers.json cache

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/bits"
	"sort"
	"sync"
	"time"
)

const (
	K       = 8 // max contacts per bucket
	IDBits  = 256
	IDBytes = IDBits / 8
	// RelayTTL is how long a relay entry remains valid without a refresh.
	// NAT holes live 30-60 s; TTL is set to 2 min so a single missed announce
	// (25 s interval) does not immediately evict the entry, but stale addresses
	// are flushed within 2 minutes of the relay going offline.
	RelayTTL = 2 * time.Minute
)

// Message type constants for the DHT wire protocol.
const (
	MsgPing         byte = 0x01
	MsgPong         byte = 0x02
	MsgFindNode     byte = 0x03
	MsgNodes        byte = 0x04
	MsgAnnounce     byte = 0x05
	MsgAck          byte = 0x06
	MsgGetRelays    byte = 0x07
	MsgRelayList    byte = 0x08
	MsgManifestHave byte = 0x09
	MsgManifestWant byte = 0x0A
	MsgManifest     byte = 0x0B
	MsgHolePunch    byte = 0x0C
	MsgContentHave  byte = 0x0D
	MsgContentWant  byte = 0x0E
	MsgContent      byte = 0x0F
	MsgMirrorPunch  byte = 0x10
)

// ── Node ID ────────────────────────────────────────────────────────────────────

// ID is a 256-bit Kademlia node identifier (matches NodeID — Ed25519 pubkey).
type ID [IDBytes]byte

// ParseID decodes a 64-char hex string into an ID.
func ParseID(s string) (ID, error) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != IDBytes {
		var zero ID
		return zero, fmt.Errorf("dht: bad id %q", s)
	}
	var id ID
	copy(id[:], b)
	return id, nil
}

func (id ID) String() string { return hex.EncodeToString(id[:]) }

// XOR returns the XOR distance between two IDs.
func (a ID) XOR(b ID) ID {
	var out ID
	for i := range out {
		out[i] = a[i] ^ b[i]
	}
	return out
}

// BucketIndex returns the index of the k-bucket this distance falls into.
func (d ID) BucketIndex() int {
	for i, b := range d {
		if b != 0 {
			return i*8 + bits.LeadingZeros8(b)
		}
	}
	return IDBits - 1
}

// Closer reports whether a is XOR-closer to target than b.
func (a ID) Closer(b, target ID) bool {
	da := a.XOR(target)
	db := b.XOR(target)
	for i := range da {
		if da[i] != db[i] {
			return da[i] < db[i]
		}
	}
	return false
}

// ── Contacts ───────────────────────────────────────────────────────────────────

// Contact is a peer known to the routing table.
type Contact struct {
	ID          ID
	Addr        string
	LastSeen    time.Time
	MissedPings int
	Suspect     bool
}

const maxMissedPings = 4

// ── Routing table ─────────────────────────────────────────────────────────────

// RoutingTable is a Kademlia routing table.
type RoutingTable struct {
	self    ID
	mu      sync.RWMutex
	buckets [IDBits]*bucket
}

func NewRoutingTable(self ID) *RoutingTable {
	rt := &RoutingTable{self: self}
	for i := range rt.buckets {
		rt.buckets[i] = &bucket{}
	}
	return rt
}

func (rt *RoutingTable) Add(c Contact) {
	if c.ID == rt.self {
		return
	}
	idx := rt.self.XOR(c.ID).BucketIndex()
	rt.mu.Lock()
	rt.buckets[idx].add(c)
	rt.mu.Unlock()
}

func (rt *RoutingTable) Remove(id ID) {
	idx := rt.self.XOR(id).BucketIndex()
	rt.mu.Lock()
	rt.buckets[idx].remove(id)
	rt.mu.Unlock()
}

// Closest returns up to n non-suspect contacts nearest to target.
func (rt *RoutingTable) Closest(target ID, n int) []Contact {
	rt.mu.RLock()
	var all []Contact
	for _, b := range rt.buckets {
		for _, c := range b.snapshot() {
			if !c.Suspect {
				all = append(all, c)
			}
		}
	}
	rt.mu.RUnlock()

	sort.Slice(all, func(i, j int) bool {
		di := all[i].ID.XOR(target)
		dj := all[j].ID.XOR(target)
		return binary.BigEndian.Uint64(di[:8]) < binary.BigEndian.Uint64(dj[:8])
	})
	if len(all) > n {
		all = all[:n]
	}
	return all
}

func (rt *RoutingTable) SuspectContacts() []Contact {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	var out []Contact
	for _, b := range rt.buckets {
		for _, c := range b.snapshot() {
			if c.Suspect {
				out = append(out, c)
			}
		}
	}
	return out
}

func (rt *RoutingTable) All() []Contact {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	var out []Contact
	for _, b := range rt.buckets {
		out = append(out, b.snapshot()...)
	}
	return out
}

func (rt *RoutingTable) MarkMissed(id ID) {
	idx := rt.self.XOR(id).BucketIndex()
	rt.mu.Lock()
	rt.buckets[idx].markMissed(id)
	rt.mu.Unlock()
}

func (rt *RoutingTable) ResetMissed(id ID) {
	idx := rt.self.XOR(id).BucketIndex()
	rt.mu.Lock()
	rt.buckets[idx].resetMissed(id)
	rt.mu.Unlock()
}

func (rt *RoutingTable) Size() int {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	n := 0
	for _, b := range rt.buckets {
		n += b.len()
	}
	return n
}

// ── Bucket ────────────────────────────────────────────────────────────────────

type bucket struct {
	mu       sync.Mutex
	contacts []Contact
}

func (b *bucket) add(c Contact) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for i, e := range b.contacts {
		if e.ID == c.ID {
			b.contacts[i] = c
			return
		}
	}
	if len(b.contacts) >= K {
		b.contacts = b.contacts[1:]
	}
	b.contacts = append(b.contacts, c)
}

func (b *bucket) remove(id ID) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for i, e := range b.contacts {
		if e.ID == id {
			b.contacts = append(b.contacts[:i], b.contacts[i+1:]...)
			return
		}
	}
}

func (b *bucket) snapshot() []Contact {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]Contact, len(b.contacts))
	copy(out, b.contacts)
	return out
}

func (b *bucket) len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.contacts)
}

func (b *bucket) markMissed(id ID) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for i, e := range b.contacts {
		if e.ID == id {
			b.contacts[i].MissedPings++
			b.contacts[i].Suspect = true
			if b.contacts[i].MissedPings >= maxMissedPings {
				b.contacts = append(b.contacts[:i], b.contacts[i+1:]...)
			}
			return
		}
	}
}

func (b *bucket) resetMissed(id ID) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for i, e := range b.contacts {
		if e.ID == id {
			b.contacts[i].MissedPings = 0
			b.contacts[i].Suspect = false
			return
		}
	}
}

// ── Relay entry ───────────────────────────────────────────────────────────────

// RelayEntry is a signed relay announcement published to the DHT.
type RelayEntry struct {
	NodeID      string `json:"node_id"`
	Addr        string `json:"addr"`
	CountryCode string `json:"country_code,omitempty"`
	TS          int64  `json:"ts"`
	Sig         string `json:"sig"` // base64url Ed25519 over canonical payload
}

// RelayEntryPayload returns the canonical byte payload that must be signed to
// produce RelayEntry.Sig.  Used both by VerifyRelayEntry and by clients that
// build their own entry before calling SetOwnEntry.
func RelayEntryPayload(e *RelayEntry) []byte {
	return relayEntryPayload(e)
}

func relayEntryPayload(e *RelayEntry) []byte {
	return []byte(e.NodeID + "|" + e.Addr + "|" + e.CountryCode + "|" + fmt.Sprintf("%d", e.TS))
}

// VerifyRelayEntry checks the Ed25519 signature on a RelayEntry.
func VerifyRelayEntry(e *RelayEntry) error {
	if len(e.NodeID) != hex.EncodedLen(ed25519.PublicKeySize) {
		return fmt.Errorf("dht: bad node_id length %d", len(e.NodeID))
	}
	pubBytes, err := hex.DecodeString(e.NodeID)
	if err != nil {
		return fmt.Errorf("dht: node_id not hex: %w", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(e.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("dht: bad sig encoding")
	}
	payload := relayEntryPayload(e)
	if !ed25519.Verify(ed25519.PublicKey(pubBytes), payload, sig) {
		return fmt.Errorf("dht: signature verification failed")
	}
	return nil
}

// ── Contact JSON (for wire) ───────────────────────────────────────────────────

type ContactJSON struct {
	ID   string `json:"id"`
	Addr string `json:"addr"`
}

func ContactToJSON(c Contact) ContactJSON {
	return ContactJSON{ID: c.ID.String(), Addr: c.Addr}
}

func ContactFromJSON(j ContactJSON) (Contact, error) {
	id, err := ParseID(j.ID)
	return Contact{ID: id, Addr: j.Addr, LastSeen: time.Now()}, err
}

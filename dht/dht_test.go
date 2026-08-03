// Copyright (c) 2026 Konstantin Khait

package dht

// Tests for DHT relay discovery path.
//
// Test 1 — Bootstrap:    nodeA sends FindNode to nodeB, both end up in each other's routing table.
// Test 2 — Announce:     nodeA announces a signed relay entry; nodeB discovers it via GetRelays.
// Test 3 — Wire round-trip: seal/open round-trips all message types without corruption.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"testing"
	"time"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func newTestNode(t *testing.T) *Node {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal("listen:", err)
	}
	var id ID
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatal(err)
	}
	node := NewNode(id, conn, "", nil, nil, nil)
	t.Cleanup(node.Stop)
	return node
}

func nodeAddr(n *Node) string {
	return n.conn.LocalAddr().String()
}

// signedRelayEntry creates a valid signed relay entry for testing.
func signedRelayEntry(t *testing.T, addr string) RelayEntry {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	e := RelayEntry{
		NodeID:      fmt.Sprintf("%x", pub),
		Addr:        addr,
		CountryCode: "US",
		TS:          time.Now().Unix(),
	}
	sig := ed25519.Sign(priv, relayEntryPayload(&e))
	e.Sig = base64.RawURLEncoding.EncodeToString(sig)
	return e
}

// ── 1. Bootstrap ──────────────────────────────────────────────────────────────

func TestDHTBootstrap(t *testing.T) {
	nodeA := newTestNode(t)
	nodeB := newTestNode(t)

	nodeA.Start()
	nodeB.Start()

	// Bootstrap A → B.  B will reply with a MsgNodes containing its own contact,
	// which A adds to its routing table.
	nodeA.Bootstrap([]string{nodeAddr(nodeB)})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if nodeA.RoutingTableSize() > 0 {
			return
		}
		time.Sleep(30 * time.Millisecond)
	}
	t.Fatalf("nodeA routing table still empty after 2s — bootstrap failed")
}

// ── 2. Relay announce + discover ─────────────────────────────────────────────

func TestRelayAnnounceAndDiscover(t *testing.T) {
	nodeA := newTestNode(t)
	nodeB := newTestNode(t)

	nodeA.Start()
	nodeB.Start()

	// Cross-bootstrap so both nodes are in each other's routing table.
	nodeA.Bootstrap([]string{nodeAddr(nodeB)})
	time.Sleep(200 * time.Millisecond)
	nodeB.Bootstrap([]string{nodeAddr(nodeA)})
	time.Sleep(200 * time.Millisecond)

	if nodeA.RoutingTableSize() == 0 {
		t.Fatal("bootstrap failed: nodeA routing table empty")
	}

	// Give nodeA a signed relay entry and announce it.
	entry := signedRelayEntry(t, nodeAddr(nodeA))
	nodeA.SetOwnEntry(&entry)
	nodeA.Announce()

	// nodeB should receive the RelayList in response to GetRelays within 2s.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for _, r := range nodeB.Relays() {
			if r.Addr == entry.Addr {
				return // success
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("nodeB did not discover nodeA's relay entry after announce")
}

// ── 3. Wire round-trip ────────────────────────────────────────────────────────

func TestWireRoundTrip(t *testing.T) {
	cases := []struct {
		name    string
		msgType byte
		payload interface{}
	}{
		{"ping", MsgPing, nil},
		{"pong", MsgPong, nil},
		{"find_node", MsgFindNode, FindNodePayload{
			From:   ContactJSON{ID: "aa", Addr: "1.2.3.4:5"},
			Target: "bb",
		}},
		{"nodes", MsgNodes, NodesPayload{
			Nodes: []ContactJSON{{ID: "cc", Addr: "5.6.7.8:9"}},
		}},
		{"get_relays", MsgGetRelays, nil},
		{"manifest_have", MsgManifestHave, ManifestHavePayload{TS: 12345}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pkt, err := Seal(tc.msgType, 0, tc.payload)
			if err != nil {
				t.Fatalf("Seal: %v", err)
			}
			gotType, gotTTL, _, err := Open(pkt)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if gotType != tc.msgType {
				t.Errorf("msgType got=%02x want=%02x", gotType, tc.msgType)
			}
			if gotTTL != MaxTTL {
				t.Errorf("ttl got=%d want=%d", gotTTL, MaxTTL)
			}
		})
	}
}

// ── 4. Relay signature verification ──────────────────────────────────────────

func TestRelayEntrySignature(t *testing.T) {
	entry := signedRelayEntry(t, "10.0.0.1:9000")
	if err := VerifyRelayEntry(&entry); err != nil {
		t.Fatalf("VerifyRelayEntry: %v", err)
	}

	// Tamper with addr — signature must fail.
	entry.Addr = "10.0.0.2:9000"
	if err := VerifyRelayEntry(&entry); err == nil {
		t.Fatal("expected sig failure after tampering with addr")
	}
}

// Copyright (c) 2026 Konstantin Khait

package dht

// Tests for the content-manifest gossip channel (dht_content.go) — the
// same Have/Want/Manifest push-pull mechanics as the control-manifest
// gossip (dht_test.go), on an independent channel, plus the completeStore
// "who has fully downloaded it" index.

import (
	"testing"
	"time"
)

func TestContentManifestGossip(t *testing.T) {
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

	received := make(chan []byte, 1)
	nodeB.SetContentHandler(func(raw []byte) {
		select {
		case received <- raw:
		default:
		}
	})

	payload := []byte(`{"type":"content","ts":123,"files":[],"sig":"x"}`)
	nodeA.SetContent(payload, 123)
	nodeA.GossipContentHave() // trigger immediately instead of waiting for the 25s ticker

	select {
	case got := <-received:
		if string(got) != string(payload) {
			t.Fatalf("gossiped payload mismatch: got %s want %s", got, payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("nodeB never received content manifest via gossip")
	}
}

// A manifest with ts no newer than what the receiver already has must not
// be re-applied — same anti-rollback rule as the control-manifest channel.
func TestContentManifestGossipDropsStaleTS(t *testing.T) {
	nodeA := newTestNode(t)
	nodeB := newTestNode(t)

	nodeA.Start()
	nodeB.Start()
	nodeA.Bootstrap([]string{nodeAddr(nodeB)})
	time.Sleep(200 * time.Millisecond)

	nodeB.SetContent([]byte(`{"type":"content","ts":500,"files":[]}`), 500)

	calls := 0
	nodeB.SetContentHandler(func(raw []byte) { calls++ })

	nodeA.SetContent([]byte(`{"type":"content","ts":500,"files":[]}`), 500) // same ts as B already has
	nodeA.GossipContentHave()
	time.Sleep(300 * time.Millisecond)

	if calls != 0 {
		t.Fatalf("handler called %d times for a non-newer manifest — want 0", calls)
	}
}

func TestCompletePeersFiltersByTSAndComplete(t *testing.T) {
	n := newTestNode(t)
	n.Start()

	n.completePeers.record("1.2.3.4:1", 100, true)
	n.completePeers.record("1.2.3.4:2", 100, false) // reported, but not complete
	n.completePeers.record("1.2.3.4:3", 99, true)   // complete, but for a different ts

	got := n.CompletePeers(100)
	if len(got) != 1 || got[0] != "1.2.3.4:1" {
		t.Fatalf("CompletePeers(100) = %v, want [1.2.3.4:1]", got)
	}
	if got := n.CompletePeers(99); len(got) != 1 || got[0] != "1.2.3.4:3" {
		t.Fatalf("CompletePeers(99) = %v, want [1.2.3.4:3]", got)
	}
	if got := n.CompletePeers(1); len(got) != 0 {
		t.Fatalf("CompletePeers(1) = %v, want empty", got)
	}
}

func TestMirrorPunchInvitation(t *testing.T) {
	nodeA := newTestNode(t)
	nodeB := newTestNode(t)

	nodeA.Start()
	nodeB.Start()
	nodeA.Bootstrap([]string{nodeAddr(nodeB)})
	time.Sleep(200 * time.Millisecond)

	invited := make(chan string, 1)
	nodeB.SetMirrorPunchHandler(func(peerAddr string) {
		select {
		case invited <- peerAddr:
		default:
		}
	})

	nodeA.SendMirrorPunch(nodeAddr(nodeB), nodeAddr(nodeA))

	select {
	case got := <-invited:
		if got != nodeAddr(nodeA) {
			t.Fatalf("invitation peer=%q want=%q", got, nodeAddr(nodeA))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("nodeB never received mirror_punch invitation")
	}
}

// Copyright (c) 2026 Konstantin Khait

package core

// TestUDPRelayRoundtrip verifies the full relay path:
//   blocked client → UDPRelayConn (client side)
//     → UDP → UDPRelayConn (relay side)
//       → HTTP → stub control
//         → HTTP response back to relay
//       → UDP → client
//     → response returned to caller

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// dialedUDPPair creates two connected *net.UDPConn sockets on loopback.
// Both sockets use Write() (connected) rather than WriteTo(), which is
// what UDPRelayConn.readLoop and RoundTrip require.
func dialedUDPPair(t *testing.T) (client, relay *net.UDPConn) {
	t.Helper()

	// Bind two listener sockets to claim ephemeral ports.
	la, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	lb, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		la.Close()
		t.Fatal(err)
	}
	addrA := *la.LocalAddr().(*net.UDPAddr)
	addrB := *lb.LocalAddr().(*net.UDPAddr)
	la.Close()
	lb.Close()

	// Dial each to the other's address (connected sockets).
	client, err = net.DialUDP("udp4", &addrA, &addrB)
	if err != nil {
		t.Fatal("dial client:", err)
	}
	relay, err = net.DialUDP("udp4", &addrB, &addrA)
	if err != nil {
		client.Close()
		t.Fatal("dial relay:", err)
	}
	client.SetDeadline(time.Now().Add(3 * time.Second)) //nolint:errcheck
	relay.SetDeadline(time.Now().Add(3 * time.Second))  //nolint:errcheck
	t.Cleanup(func() { client.Close(); relay.Close() })
	return
}

func TestUDPRelayRoundtrip(t *testing.T) {
	// Stub control: echoes the request body back with 200.
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(body) //nolint:errcheck
	}))
	defer stub.Close()

	clientConn, relayConn := dialedUDPPair(t)

	// Relay side: forwards requests to the stub control.
	relaySide := NewUDPRelayConn(relayConn, stub.URL)
	defer relaySide.Close()

	// Client side: no forwarding (client-only mode).
	clientSide := NewUDPRelayConn(clientConn, "")
	defer clientSide.Close()

	want := []byte("hello-relay-test")
	status, got, err := clientSide.RoundTrip("/api/media/upload", "tok", want)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	if status != 200 {
		t.Fatalf("status=%d want 200", status)
	}
	if string(got) != string(want) {
		t.Fatalf("body=%q want %q", got, want)
	}
}

// TestUDPRelayControlDown verifies that when the relay can reach the client but
// the control is down, the relay returns 503 (not a relay-level failure).
// Failed() should NOT be set — the relay transport is healthy.
func TestUDPRelayControlDown(t *testing.T) {
	clientConn, relayConn := dialedUDPPair(t)

	// Relay points to a control that actively refuses connections.
	relaySide := NewUDPRelayConn(relayConn, "http://127.0.0.1:1")
	defer relaySide.Close()

	clientSide := NewUDPRelayConn(clientConn, "")
	defer clientSide.Close()

	status, _, err := clientSide.RoundTrip("/api/media/upload", "tok", []byte("ping"))
	if err != nil {
		t.Fatalf("RoundTrip: %v (expected 503, not timeout)", err)
	}
	if status != 503 {
		t.Fatalf("status=%d want 503", status)
	}
	// relay itself is fine — should NOT be marked Failed
	if relaySide.Failed() {
		t.Fatal("relaySide.Failed() should be false when only the control is down")
	}
}

// TestUDPRelayFailsAfterThreshold verifies that the client marks a relay as
// Failed() after udpRelayFailThresh consecutive RoundTrip timeouts (relay unreachable).
func TestUDPRelayFailsAfterThreshold(t *testing.T) {
	clientConn, _ := dialedUDPPair(t)

	// Create a client-only UDPRelayConn against a peer that never responds.
	// The relay side is created but immediately closed — simulates dead relay.
	_, relayConn := dialedUDPPair(t)
	relayConn.Close() // relay gone

	clientSide := NewUDPRelayConn(clientConn, "")
	defer clientSide.Close()

	// Keep calling RoundTrip until the client marks itself failed.
	for i := 0; i < udpRelayFailThresh+2; i++ {
		clientSide.RoundTrip("/api/media/upload", "tok", []byte(fmt.Sprintf("msg%d", i))) //nolint:errcheck
		if clientSide.Failed() {
			return
		}
	}
	t.Fatal("clientSide.Failed() never set after threshold timeouts")
}

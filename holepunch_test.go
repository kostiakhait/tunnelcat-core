// Copyright (c) 2026 Konstantin Khait

package core

// TestHolePunch verifies the probe crypto and success path.
//
// Real NAT traversal requires two peers to simultaneously dial each other's
// external addresses.  On loopback we simulate this with a server that:
//   1. listens on a known port (acts as "peer B with known address")
//   2. waits for an authenticated probe from the Punch() caller
//   3. responds with its own authenticated probe
//
// Punch() succeeds when it receives the server's response — the crypto (dhtSeal
// / dhtOpen) and the bidirectional-probe logic are both exercised.

import (
	"net"
	"testing"
	"time"
)

func TestHolePunch(t *testing.T) {
	// Server: listens on a known loopback address.
	serverConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal("server listen:", err)
	}
	defer serverConn.Close()
	serverConn.SetDeadline(time.Now().Add(4 * time.Second)) //nolint:errcheck

	serverAddr := serverConn.LocalAddr().String()
	serverDone := make(chan error, 1)

	go func() {
		buf := make([]byte, 256)
		n, src, err := serverConn.ReadFromUDP(buf)
		if err != nil {
			serverDone <- err
			return
		}
		// Verify the probe is an authenticated DHT HolePunch message.
		msgType, _, _, err := dhtOpen(buf[:n])
		if err != nil {
			serverDone <- err
			return
		}
		if msgType != dhtMsgHolePunch {
			serverDone <- nil // not a hole-punch probe — ignore
			return
		}
		// Respond with an authenticated probe back to the client's source address.
		probe, err := dhtSeal(dhtMsgHolePunch, 1, nil)
		if err != nil {
			serverDone <- err
			return
		}
		_, err = serverConn.WriteToUDP(probe, src)
		serverDone <- err
	}()

	// Client calls Punch to the server's known address.
	// Punch dials to serverAddr, sends probes, and returns when it receives
	// an authenticated probe from serverAddr (the response above).
	conn, err := Punch("", serverAddr)
	if err != nil {
		t.Fatalf("Punch: %v", err)
	}
	conn.Close()

	// Confirm the server also completed cleanly.
	if err := <-serverDone; err != nil {
		t.Errorf("server error: %v", err)
	}
}

func TestHolePunchTimeout(t *testing.T) {
	// Dial to a port that has no server — Punch must timeout cleanly.
	// Use an address that will refuse/drop all packets without blocking forever.
	conn, err := Punch("", "127.0.0.1:1") // port 1 is never open on loopback
	if err == nil {
		conn.Close()
		t.Fatal("expected timeout error, got success")
	}
}

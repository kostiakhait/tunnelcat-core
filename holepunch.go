// Copyright (c) 2026 Konstantin Khait

package core

// Punch attempts UDP hole punching to peerAddr.
//
// Both peers receive each other's external UDP endpoint via the control's
// signal channel (core/signal.go) and call Punch simultaneously.  Each side
// sends encrypted probe datagrams to the peer at 100 ms intervals; success is
// declared when an authenticated probe from the peer arrives within punchTimeout.
//
// Probes are encrypted with dhtSeal (dhtMsgHolePunch, TTL=1) — they are
// indistinguishable from DHT traffic on the wire (random nonce + ChaCha20-Poly1305
// ciphertext).  The AEAD tag verifies the probe came from a node that knows
// dhtKey, not from a random port scanner.
//
// localIP is the physical NIC address (from bypass manager) so the socket
// bypasses TUN.  Pass "" in tests or when TUN is not active.
//
// On success returns a connected *net.UDPConn (deadline cleared).
// On timeout returns an error — callers fall back to the relay path.

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	// PunchTimeout is how long Punch waits for a probe from the peer.
	PunchTimeout = 3 * time.Second

	punchInterval = 100 * time.Millisecond
)

// Punch performs UDP hole punching to peerAddr and returns a connected
// *net.UDPConn on success.  The connection has no deadline set.
func Punch(localIP, peerAddr string) (*net.UDPConn, error) {
	return punch(localIP, peerAddr, nil)
}

// PunchProtected is the Android variant: uses dialControl (VpnService.protect)
// to bypass the TUN instead of binding to a specific local IP.
func PunchProtected(peerAddr string, dialControl func(string, string, syscall.RawConn) error) (*net.UDPConn, error) {
	return punch("", peerAddr, dialControl)
}

// punch is the internal variant that accepts an optional dialControl function
// for platforms where socket protection is required rather than LocalAddr binding.
func punch(localIP, peerAddr string, dialControl func(string, string, syscall.RawConn) error) (*net.UDPConn, error) {
	raddr, err := net.ResolveUDPAddr("udp", peerAddr)
	if err != nil {
		return nil, fmt.Errorf("punch: resolve %s: %w", peerAddr, err)
	}

	var laddr net.Addr
	if localIP != "" {
		laddr = &net.UDPAddr{IP: net.ParseIP(localIP)}
	}
	d := net.Dialer{LocalAddr: laddr, Control: dialControl}
	rawConn, err := d.DialContext(context.Background(), "udp", raddr.String())
	if err != nil {
		return nil, fmt.Errorf("punch: dial: %w", err)
	}
	conn := rawConn.(*net.UDPConn)

	// Build one probe packet (re-used; nonce is random per dhtSeal call so
	// each send produces a distinct ciphertext — no replay pattern).
	buildProbe := func() ([]byte, error) {
		return dhtSeal(dhtMsgHolePunch, 1, nil)
	}

	// Stop the probe sender once we succeed or timeout.
	stop := make(chan struct{})
	var once sync.Once
	stopOnce := func() { once.Do(func() { close(stop) }) }
	var probesSent atomic.Int64

	go func() {
		ticker := time.NewTicker(punchInterval)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				pkt, err := buildProbe()
				if err != nil {
					continue
				}
				conn.Write(pkt) //nolint:errcheck
				probesSent.Add(1)
				Log.Printf("holepunch: probe #%d → %s", probesSent.Load(), peerAddr)
			}
		}
	}()

	Log.Printf("holepunch: start peer=%s local=%q timeout=%s", peerAddr, localIP, PunchTimeout)

	conn.SetDeadline(time.Now().Add(PunchTimeout)) //nolint:errcheck

	buf := make([]byte, 256)
	var last error
	for {
		n, err := conn.Read(buf)
		if err != nil {
			last = err
			break
		}
		Log.Printf("holepunch: recv %d bytes from %s (sent %d probes so far)", n, peerAddr, probesSent.Load())
		msgType, _, _, openErr := dhtOpen(buf[:n])
		if openErr != nil {
			Log.Printf("holepunch: recv: auth failed from %s: %v — ignoring", peerAddr, openErr)
			continue
		}
		if msgType != dhtMsgHolePunch {
			Log.Printf("holepunch: unexpected msg type 0x%02x from %s — ignoring", msgType, peerAddr)
			continue
		}
		stopOnce()
		conn.SetDeadline(time.Time{}) //nolint:errcheck
		Log.Printf("holepunch: SUCCESS peer=%s local=%s probes_sent=%d", peerAddr, localIP, probesSent.Load())
		return conn, nil
	}

	stopOnce()
	conn.Close()
	Log.Printf("holepunch: FAILED peer=%s probes_sent=%d err=%v — relay fallback", peerAddr, probesSent.Load(), last)
	return nil, fmt.Errorf("punch: timeout waiting for peer %s: %w", peerAddr, last)
}

// Copyright (c) 2026 Konstantin Khait

package core

// NATProber discovers the client's external UDP endpoint by sending an
// encrypted reflection request to a control node's UDP port.
//
// The wire format is identical to the control's UDPReflector:
//
//	Request ciphertext decrypts to:  [8B timestamp_ms big-endian]
//	Response ciphertext decrypts to: [2B family][4/16B IP][2B port]
//
// The key is derived from a well-known constant (DPI obfuscation only).
// The UDP socket is bound to the physical NIC address so the datagram
// bypasses the TUN interface and reaches the control directly.

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"time"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	natNonceSize  = 12
	natTimeout    = 3 * time.Second
	natMaxRespPkt = 256
)

// natReflectorKey must match the server-side UDP reflector's key derivation.
var natReflectorKey = func() []byte {
	h, _ := blake2b.New256(nil)
	h.Write([]byte("snc-udp-reflect-v1"))
	return h.Sum(nil)
}()

// ExternalEndpoint holds the observed external UDP address of this client.
type ExternalEndpoint struct {
	IP   net.IP
	Port int
}

func (e ExternalEndpoint) String() string {
	return fmt.Sprintf("%s:%d", e.IP, e.Port)
}

// ProbeExternalEndpoint sends a reflection request to controlAddr (host:port)
// and returns the observed external UDP endpoint.
//
// localIP should be the physical NIC address (from bypass manager) so the
// datagram leaves on the real interface, not the TUN.  Pass "" to let the OS
// pick the source address (works in non-TUN contexts such as tests).
func ProbeExternalEndpoint(controlAddr, localIP string) (ExternalEndpoint, error) {
	return probeExternalEndpoint(controlAddr, localIP, nil)
}

// ProbeExternalEndpointProtected is the Android variant: uses dialControl
// (VpnService.protect) instead of LocalAddr binding to bypass the TUN.
func ProbeExternalEndpointProtected(controlAddr string, dialControl func(string, string, syscall.RawConn) error) (ExternalEndpoint, error) {
	return probeExternalEndpoint(controlAddr, "", dialControl)
}

// probeExternalEndpoint is the internal variant that accepts an optional
// dialControl function for platforms where socket protection is required
// (e.g. Android VpnService.protect) rather than LocalAddr binding.
func probeExternalEndpoint(controlAddr, localIP string, dialControl func(string, string, syscall.RawConn) error) (ExternalEndpoint, error) {
	aead, err := chacha20poly1305.New(natReflectorKey)
	if err != nil {
		return ExternalEndpoint{}, fmt.Errorf("nat: aead: %w", err)
	}

	// Resolve control address.
	raddr, err := net.ResolveUDPAddr("udp", controlAddr)
	if err != nil {
		return ExternalEndpoint{}, fmt.Errorf("nat: resolve %s: %w", controlAddr, err)
	}

	var laddr net.Addr
	if localIP != "" {
		laddr = &net.UDPAddr{IP: net.ParseIP(localIP)}
	}
	d := net.Dialer{Timeout: natTimeout, LocalAddr: laddr, Control: dialControl}
	rawConn, err := d.DialContext(context.Background(), "udp", raddr.String())
	if err != nil {
		return ExternalEndpoint{}, fmt.Errorf("nat: dial %s: %w", controlAddr, err)
	}
	conn := rawConn.(*net.UDPConn)
	defer conn.Close()

	// Build request: encrypt 8B timestamp.
	plain := make([]byte, 8)
	binary.BigEndian.PutUint64(plain, uint64(time.Now().UnixMilli()))

	nonce := make([]byte, natNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return ExternalEndpoint{}, fmt.Errorf("nat: nonce: %w", err)
	}
	req := aead.Seal(nonce, nonce, plain, nil)

	Log.Printf("nat: probing %s (local=%q timeout=%s)", controlAddr, localIP, natTimeout)

	conn.SetDeadline(time.Now().Add(natTimeout)) //nolint:errcheck
	if _, err := conn.Write(req); err != nil {
		return ExternalEndpoint{}, fmt.Errorf("nat: send: %w", err)
	}
	Log.Printf("nat: request sent (%d bytes) → waiting for response", len(req))

	// Read response.
	buf := make([]byte, natMaxRespPkt)
	n, err := conn.Read(buf)
	if err != nil {
		return ExternalEndpoint{}, fmt.Errorf("nat: recv (timeout=%s): %w", natTimeout, err)
	}
	Log.Printf("nat: response received (%d bytes)", n)
	pkt := buf[:n]

	minLen := natNonceSize + 2 + 4 + 2 + aead.Overhead() // nonce + family + IPv4 + port + tag
	if len(pkt) < minLen {
		return ExternalEndpoint{}, fmt.Errorf("nat: response too short (%d bytes)", len(pkt))
	}

	resp, err := aead.Open(nil, pkt[:natNonceSize], pkt[natNonceSize:], nil)
	if err != nil {
		return ExternalEndpoint{}, fmt.Errorf("nat: decrypt response: %w", err)
	}

	// Parse: [2B family][IP bytes][2B port]
	if len(resp) < 4 {
		return ExternalEndpoint{}, fmt.Errorf("nat: response payload too short")
	}
	family := binary.BigEndian.Uint16(resp[0:2])
	var ipLen int
	switch family {
	case 4:
		ipLen = 4
	case 6:
		ipLen = 16
	default:
		return ExternalEndpoint{}, fmt.Errorf("nat: unknown addr family %d", family)
	}
	if len(resp) < 2+ipLen+2 {
		return ExternalEndpoint{}, fmt.Errorf("nat: response truncated")
	}
	ip := make(net.IP, ipLen)
	copy(ip, resp[2:2+ipLen])
	port := int(binary.BigEndian.Uint16(resp[2+ipLen:]))

	ep := ExternalEndpoint{IP: ip, Port: port}
	Log.Printf("nat: external endpoint %s (via %s)", ep, controlAddr)
	return ep, nil
}

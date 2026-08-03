// Copyright (c) 2026 Konstantin Khait

package core

// udp_control.go — direct client → control UDP transport.
//
// The control's udpTunnelHandler listens on the same UDP port as TCP (443) and
// accepts SNCU frames.  Frame format is identical to UDPRelayConn (udp_relay.go),
// so we reuse its codec and RoundTrip logic.
//
// Two entry points:
//   - probeControlUDP: one-shot ping to check UDP reachability (used by ProbeDataPlane)
//   - newUDPControlConn: creates a persistent UDPRelayConn dialed to the control

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"time"
)

const udpControlProbeReqID uint32 = 0xCAFEBABE

// ProbeControlUDP sends a single SNCU /p/v1/ping frame to addr over UDP and
// returns the round-trip time.  ok=false when the probe times out or fails.
// Use instead of ProbeControlE2E when the control is in UDP-only mode
// (TCP probe failed but UDP is alive per ProbeDataPlane).
// addr is host or host:port; defaults to port 443 if no port given.
func ProbeControlUDP(addr string, timeout time.Duration) (rtt time.Duration, ok bool) {
	return probeControlUDP(addr, timeout)
}

// probeControlUDP is the unexported implementation shared by ProbeControlUDP
// and ProbeDataPlane.
func probeControlUDP(addr string, timeout time.Duration) (rtt time.Duration, ok bool) {
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = addr + ":443"
	}
	d := net.Dialer{Control: dialControl}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	c, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		return 0, false
	}
	uc, isUDP := c.(*net.UDPConn)
	if !isUDP {
		c.Close()
		return 0, false
	}
	defer uc.Close()

	frame := udpEncodeRequest(udpControlProbeReqID, "/p/v1/ping", "", nil)
	uc.SetDeadline(time.Now().Add(timeout)) //nolint:errcheck

	start := time.Now()
	if _, err := uc.Write(frame); err != nil {
		return 0, false
	}

	buf := make([]byte, 512)
	n, err := uc.Read(buf)
	if err != nil {
		return 0, false
	}
	elapsed := time.Since(start)

	// Validate: SNCU magic + matching reqID + response type + status 200.
	data := buf[:n]
	if len(data) < 15 { // 4+4+1+2+4 minimum
		return 0, false
	}
	if binary.BigEndian.Uint32(data) != udpRelayMagic {
		return 0, false
	}
	if binary.BigEndian.Uint32(data[4:]) != udpControlProbeReqID {
		return 0, false
	}
	if data[8] != udpRelayTypeResponse {
		return 0, false
	}
	if int(binary.BigEndian.Uint16(data[9:])) != 200 {
		return 0, false
	}
	// Parse body JSON to verify exits are alive, same check as ProbeControlE2E.
	bLen := int(binary.BigEndian.Uint32(data[11:]))
	if 15+bLen > len(data) {
		return 0, false
	}
	var body struct {
		OK    bool    `json:"ok"`
		RTTMs float64 `json:"rtt_ms"`
	}
	if err := json.Unmarshal(data[15:15+bLen], &body); err != nil || !body.OK {
		return 0, false
	}
	if body.RTTMs > 0 {
		return time.Duration(body.RTTMs * float64(time.Millisecond)), true
	}
	return elapsed, true
}

// NewUDPControlConn dials a connected UDP socket to controlAddr and wraps it
// in a UDPRelayConn for use as a client-only transport (server mode disabled).
// The caller is responsible for closing the returned conn when done.
// controlAddr is host or host:port; defaults to port 443 if no port given.
func NewUDPControlConn(controlAddr string) (*UDPRelayConn, error) {
	return newUDPControlConn(controlAddr)
}

func newUDPControlConn(controlAddr string) (*UDPRelayConn, error) {
	if _, _, err := net.SplitHostPort(controlAddr); err != nil {
		controlAddr = controlAddr + ":443"
	}
	d := net.Dialer{Control: dialControl}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := d.DialContext(ctx, "udp", controlAddr)
	if err != nil {
		return nil, fmt.Errorf("udp-control: dial %s: %w", controlAddr, err)
	}
	uc, isUDP := c.(*net.UDPConn)
	if !isUDP {
		c.Close()
		return nil, fmt.Errorf("udp-control: unexpected conn type %T", c)
	}
	// controlURL="" disables server mode; we only use RoundTrip (client direction).
	return NewUDPRelayConn(uc, ""), nil
}

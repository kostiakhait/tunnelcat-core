// Copyright (c) 2026 Konstantin Khait

package core

import (
	"sync"
	"time"
)

// TunnelTrafficMonitor tracks payload throughput in both directions so the
// watchdog can detect a one-sided outage: data sent but nothing received.
// Zero-payload frames and bypass-routed traffic are excluded by the callers.
type TunnelTrafficMonitor struct {
	mu             sync.Mutex
	firstSentAt    time.Time // time of the first send since last Reset
	lastSentAt     time.Time
	lastGoodRecvAt time.Time
}

// TunnelMonitor is the package-level instance shared between tunnel.go and the tray watchdog.
var TunnelMonitor TunnelTrafficMonitor

// RecordTunnelSent notes that n bytes of application payload were sent through
// the tunnel.  n == 0 is ignored (padding / header-only frames).
func (m *TunnelTrafficMonitor) RecordTunnelSent(n int) {
	if n == 0 {
		return
	}
	m.mu.Lock()
	if m.firstSentAt.IsZero() {
		m.firstSentAt = time.Now()
	}
	m.lastSentAt = time.Now()
	m.mu.Unlock()
}

// RecordTunnelRecv notes that n bytes of real data arrived from the tunnel.
// n == 0 is ignored (padding-only responses where dlen == 0).
func (m *TunnelTrafficMonitor) RecordTunnelRecv(n int) {
	if n == 0 {
		return
	}
	m.mu.Lock()
	m.lastGoodRecvAt = time.Now()
	m.mu.Unlock()
}

// tunnelStuckTimeout is how long outbound traffic can go unanswered before
// the watchdog declares the tunnel stuck and requests a reconnect.
const tunnelStuckTimeout = 10 * time.Second

// IsStuck returns true when the tunnel appears one-sided: real outbound
// payload was sent recently but no real inbound data has arrived within the
// stuck-timeout window.  Returns false when idle (no recent outbound traffic).
//
// When recv has never been observed (recv.IsZero), the tunnel is considered
// stuck only after a full tunnelStuckTimeout has elapsed since the very first
// send.  This prevents false positives during the cold-start period where the
// first round-trip is still in flight.
func (m *TunnelTrafficMonitor) IsStuck() bool {
	m.mu.Lock()
	firstSent := m.firstSentAt
	sent := m.lastSentAt
	recv := m.lastGoodRecvAt
	m.mu.Unlock()
	if sent.IsZero() {
		return false // idle — no outbound activity to watch
	}
	now := time.Now()
	if now.Sub(sent) > tunnelStuckTimeout {
		return false // last send was long ago — consider idle
	}
	// Recent outbound exists. If we have never received anything, only declare
	// stuck after a full timeout window from the very first send — the tunnel
	// may still be warming up (e.g. first round-trip latency > 2 s check interval).
	if recv.IsZero() {
		return now.Sub(firstSent) > tunnelStuckTimeout
	}
	return now.Sub(recv) > tunnelStuckTimeout
}

// Reset clears the traffic timestamps.  Call on each successful reconnect so
// stale pre-reconnect timestamps don't suppress the first watchdog cycle.
func (m *TunnelTrafficMonitor) Reset() {
	m.mu.Lock()
	m.firstSentAt = time.Time{}
	m.lastSentAt = time.Time{}
	m.lastGoodRecvAt = time.Time{}
	m.mu.Unlock()
}

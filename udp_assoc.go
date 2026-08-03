// Copyright (c) 2026 Konstantin Khait

package core

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

const (
	socks5UDPFallbackSent    = 3
	socks5UDPFallbackTimeout = 3 * time.Second

	tunnelCBThreshold  = 5               // consecutive failures before circuit opens
	tunnelCBCooldown   = 5 * time.Second // how long to suppress sends after circuit opens
	tunnelWorkerQDepth = 64              // per-dst send queue depth
)

// dstStats tracks per-destination probe counters for Variant C fallback and
// tunnel circuit-breaker state.
type dstStats struct {
	sentCount   int
	recvCount   int
	firstSentAt time.Time
	useTunnel   bool

	// Circuit breaker: after tunnelCBThreshold consecutive tunnel send failures
	// the circuit opens and sends to this dst are suppressed for tunnelCBCooldown.
	tunnelErrStreak    int
	tunnelBlockedUntil time.Time
}

// udpAssocSession handles one SOCKS5 UDP ASSOCIATE control connection.
type udpAssocSession struct {
	ctrl       net.Conn     // TCP control connection (kept alive per RFC 1928)
	bypassConn *net.UDPConn // relay socket: physical NIC (Variant C) or loopback (tunnel-only)
	// pick returns the current best dialer from the pool on each call.
	// Evaluated per-send so the session automatically follows pool evictions
	// without holding a stale reference to a dead control.
	pick          func() *TunnelDialer
	bypass        *BypassManager // nil on Android; used to determine if dst should bypass tunnel
	connID        string         // for tunnel frames
	tunnelOnly    bool           // if true, skip Variant C direct send and always use HTTP tunnel
	altDNSRouting bool           // if true, DNS goes via the protected bypass socket (not the configured relay)

	mu            sync.Mutex
	stats         map[string]*dstStats // keyed by dst "ip:port"
	clientUDPAddr *net.UDPAddr         // set on first datagram from client

	blockQUIC     bool     // when true, datagrams to UDP:443 are dropped so apps fall back to TCP
	drainActive   sync.Map // string(dst) → struct{}: guards per-dst drain goroutine
	tunnelWorkers sync.Map // string(dst) → chan []byte: per-dst send queue
	stopCh        chan struct{}
}

func newUDPAssocSession(ctrl net.Conn, bypass *BypassManager, pick func() *TunnelDialer, altDNSRouting bool, blockQUIC bool) (*udpAssocSession, error) {
	var conn *net.UDPConn
	var err error
	tunnelOnly := false
	if bypass != nil {
		// Windows: socket bound to the physical NIC IP (HasLocalIP=true).
		// Android: socket protected via VpnService.protect() (HasLocalIP=false, but
		//   dialControl calls protect() so the socket bypasses the TUN).
		// In both cases Variant C can send directly to bypass destinations (in-country
		// IPs). Non-bypass destinations still go through the HTTP tunnel via forwardOutbound.
		// This fixes large UDP uploads (WhatsApp QUIC) for users in the same country as
		// the bypass CIDRs — previously tunnelOnly=true forced every datagram through HTTP.
		conn, err = bypass.DialUDP()
	} else {
		// No bypass manager at all: loopback relay, tunnel-only.
		conn, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		tunnelOnly = true
	}
	if err != nil {
		return nil, err
	}
	return &udpAssocSession{
		ctrl:          ctrl,
		bypassConn:    conn,
		pick:          pick,
		bypass:        bypass,
		connID:        newConnID(),
		tunnelOnly:    tunnelOnly,
		altDNSRouting: altDNSRouting,
		blockQUIC:     blockQUIC,
		stats:         make(map[string]*dstStats),
		stopCh:        make(chan struct{}),
	}, nil
}

// watchCtrl blocks until the TCP control connection closes, then signals stop.
func (s *udpAssocSession) watchCtrl() {
	buf := make([]byte, 1)
	s.ctrl.Read(buf) //nolint:errcheck
	close(s.stopCh)
}

// relayLoop is the main datagram relay loop. Runs until stopCh is closed.
func (s *udpAssocSession) relayLoop() {
	defer s.bypassConn.Close()
	buf := make([]byte, 65536)

	for {
		select {
		case <-s.stopCh:
			return
		default:
		}
		s.bypassConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond)) //nolint:errcheck
		n, srcAddr, err := s.bypassConn.ReadFrom(buf)
		if err != nil {
			if isNetTimeout(err) {
				continue
			}
			return
		}
		udpSrc := srcAddr.(*net.UDPAddr)
		data := make([]byte, n)
		copy(data, buf[:n])

		// Distinguish outbound (tun2socks → relay) from inbound (server → relay)
		// by protocol: RFC 1928 §7 datagrams from tun2socks always carry a SOCKS5
		// UDP header; raw datagrams from real servers never do.
		// IP-based discrimination fails on Windows because tun2socks sends UDP from
		// the physical NIC address, not from the loopback address used for TCP control.
		if dst, payload, frag, err := parseSOCKS5UDPHeader(data); err == nil && frag == 0 {
			// Outbound: datagram from tun2socks → forward to real destination.
			if s.blockQUIC && dst.Port == 443 {
				// QUIC (UDP:443) over a TCP-based tunnel causes head-of-line blocking
				// and poor media quality. Drop the datagram — the OS will retransmit and
				// eventually the app (browser, Facebook) falls back to TLS/TCP:443.
				continue
			}
			s.mu.Lock()
			s.clientUDPAddr = udpSrc
			s.mu.Unlock()
			s.forwardOutbound(dst, payload)
		} else {
			// Inbound: response from real destination → wrap and send back to client.
			s.recordRecv(udpSrc)
			if udpSrc.Port == 53 {
				GlobalDNSCache.ParseAndLearn(data)
			}
			s.mu.Lock()
			clientAddr := s.clientUDPAddr
			s.mu.Unlock()
			if clientAddr == nil {
				continue
			}
			wrapped := buildSOCKS5UDPHeader(udpSrc, data)
			s.bypassConn.WriteTo(wrapped, clientAddr) //nolint:errcheck
		}
	}
}

func (s *udpAssocSession) forwardOutbound(dst *net.UDPAddr, payload []byte) {
	// IPv6 datagrams (including link-local fe80:: SNMP probes from Windows) are
	// dropped here: the tunnel relay only speaks IPv4, and link-local addresses
	// are unreachable beyond the local segment regardless.  Without this guard
	// Variant C times out, marks them useTunnel=true, and the resulting 404s
	// from /api/udp/relay trigger spurious token re-authentication every ~10 s.
	if dst.IP.To4() == nil {
		return
	}

	// DNS (port 53): routing depends on mode.
	// Some configured relays add noticeable per-query latency, which causes
	// browser timeouts. The bypass socket is protected
	// (bypasses TUN), so DNS goes directly to the server and back in ~50ms.
	// In normal tunnel mode DNS still goes through the tunnel to avoid leaking
	// queries to the ISP from the client's real IP.
	if dst.Port == 53 {
		if s.altDNSRouting && !s.tunnelOnly {
			Log.Printf("udp-dns: %s → direct (altDNSRouting=true)", dst.IP)
			s.bypassConn.WriteTo(payload, dst) //nolint:errcheck
		} else {
			Log.Printf("udp-dns: %s → tunnel (altDNSRouting=%v tunnelOnly=%v)", dst.IP, s.altDNSRouting, s.tunnelOnly)
			s.goSendViaTunnel(dst, payload)
		}
		return
	}

	key := dst.String()
	s.mu.Lock()
	st := s.stats[key]
	if st == nil {
		st = &dstStats{}
		s.stats[key] = st
	}
	useTunnel := st.useTunnel
	if !useTunnel {
		if st.sentCount == 0 {
			st.firstSentAt = time.Now()
		}
		st.sentCount++
	}
	cnt := st.sentCount
	s.mu.Unlock()

	// Foreign (non-bypass) destinations must go through the tunnel immediately.
	// Sending them directly via the physical NIC would expose them to ISP blocking
	// (e.g. Meta/WhatsApp QUIC from Russia) before the Variant C fallback fires.
	dstStr := dst.String()
	isBypassDst := isLANAddress(dstStr) || (s.bypass != nil && s.bypass.ShouldBypass(dstStr))

	if useTunnel || s.tunnelOnly || !isBypassDst {
		// tunnelOnly: no bypass manager, relay socket is loopback-only.
		// !isBypassDst: foreign IPs go through tunnel to avoid ISP blocking.
		// useTunnel: Variant C gave up after no direct response.
		s.goSendViaTunnel(dst, payload)
		return
	}
	// Variant C (Windows, bypass destinations only): try sending direct via the
	// physical NIC first so LAN/in-country UDP (e.g. local printers, Russian sites)
	// doesn't have to go through the tunnel. Falls back after no response.
	s.bypassConn.WriteTo(payload, dst) //nolint:errcheck

	// After threshold, start a fallback probe goroutine.
	if cnt == socks5UDPFallbackSent {
		go s.checkFallback(key)
	}
}

func (s *udpAssocSession) checkFallback(key string) {
	time.Sleep(socks5UDPFallbackTimeout)
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.stats[key]
	if st == nil || st.useTunnel || st.recvCount > 0 {
		return
	}
	Log.Printf("udp-assoc: no response from %s after %d datagrams — switching to tunnel", key, st.sentCount)
	st.useTunnel = true
}

func (s *udpAssocSession) recordRecv(src *net.UDPAddr) {
	key := src.String()
	s.mu.Lock()
	if st := s.stats[key]; st != nil {
		st.recvCount++
	}
	s.mu.Unlock()
}

// goSendViaTunnel enqueues payload for delivery to dst via the tunnel.
// Each unique dst gets one worker goroutine and a send queue of tunnelWorkerQDepth
// packets — one goroutine per destination instead of one per packet, preventing
// goroutine explosion under high-rate UDP (e.g. QUIC).
// The circuit breaker (per dstStats) suppresses sends after tunnelCBThreshold
// consecutive failures for tunnelCBCooldown, then resets automatically.
func (s *udpAssocSession) goSendViaTunnel(dst *net.UDPAddr, payload []byte) {
	key := dst.String()

	// Circuit breaker check — only for destinations that have a stats entry.
	s.mu.Lock()
	if st := s.stats[key]; st != nil && time.Now().Before(st.tunnelBlockedUntil) {
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()

	// Get or create the per-dst send queue and its worker goroutine.
	q := make(chan []byte, tunnelWorkerQDepth)
	actual, loaded := s.tunnelWorkers.LoadOrStore(key, q)
	if loaded {
		q = actual.(chan []byte)
	} else {
		go s.runTunnelWorker(dst, q)
	}

	select {
	case q <- payload:
	case <-s.stopCh:
	}
}

// runTunnelWorker is the per-dst send goroutine. It drains the send queue
// sequentially, updating the circuit breaker after each attempt.
func (s *udpAssocSession) runTunnelWorker(dst *net.UDPAddr, q <-chan []byte) {
	key := dst.String()
	for {
		select {
		case <-s.stopCh:
			return
		case payload := <-q:
			ok := s.sendViaTunnel(dst, payload)

			s.mu.Lock()
			if st := s.stats[key]; st != nil {
				if ok {
					st.tunnelErrStreak = 0
				} else {
					st.tunnelErrStreak++
					if st.tunnelErrStreak >= tunnelCBThreshold {
						st.tunnelBlockedUntil = time.Now().Add(tunnelCBCooldown)
						st.tunnelErrStreak = 0
						Log.Printf("udp-assoc: circuit open for %s (%s cooldown)", dst, tunnelCBCooldown)
					}
				}
			}
			s.mu.Unlock()
		}
	}
}

// sendViaTunnel sends payload to dst via HTTP tunnel and delivers any
// immediately available inbound frames back to tun2socks. It also ensures
// the per-dst drain goroutine is running for server-initiated datagrams.
// Returns true on success, false on error.
func (s *udpAssocSession) sendViaTunnel(dst *net.UDPAddr, payload []byte) bool {
	d := s.pick()
	if d == nil {
		if dst.Port == 53 {
			Log.Printf("udp-dns: no dialer available for %s", dst.IP)
		} else {
			Log.Printf("udp-assoc: no dialer available for %s", dst)
		}
		return false
	}
	frames, err := d.PostUDPFrame(s.connID, dst, payload)
	if err != nil {
		if dst.Port == 53 {
			Log.Printf("udp-dns: tunnel send to %s FAILED: %v", dst.IP, err)
		} else {
			Log.Printf("udp-assoc: tunnel send to %s failed: %v", dst, err)
		}
		return false
	}
	s.deliverFrames(dst, frames)
	s.startTunnelDrain(dst)
	return true
}

// startTunnelDrain ensures one drain goroutine is running for dst.
func (s *udpAssocSession) startTunnelDrain(dst *net.UDPAddr) {
	if _, loaded := s.drainActive.LoadOrStore(dst.String(), struct{}{}); loaded {
		return
	}
	go s.drainLoop(dst)
}

// drainLoop long-polls /api/udp/drain for server-initiated inbound datagrams.
func (s *udpAssocSession) drainLoop(dst *net.UDPAddr) {
	for {
		select {
		case <-s.stopCh:
			return
		default:
		}
		d := s.pick()
		if d == nil {
			select {
			case <-s.stopCh:
				return
			case <-time.After(100 * time.Millisecond):
			}
			continue
		}
		frames, err := d.DrainUDPFrames(s.connID, dst)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				// Underlying transport is gone (e.g. mux pool closed after
				// reconnect). Stop immediately — retrying will never succeed.
				return
			}
			Log.Printf("udp-assoc: drain %s failed: %v", dst, err)
			select {
			case <-s.stopCh:
				return
			case <-time.After(100 * time.Millisecond):
			}
			continue
		}
		s.deliverFrames(dst, frames)
	}
}

// deliverFrames wraps each frame in a SOCKS5 UDP header and writes it to the
// relay socket so tun2socks delivers it to the originating application.
func (s *udpAssocSession) deliverFrames(src *net.UDPAddr, frames [][]byte) {
	if len(frames) == 0 {
		return
	}
	s.mu.Lock()
	clientAddr := s.clientUDPAddr
	s.mu.Unlock()
	if clientAddr == nil {
		return
	}
	for _, frame := range frames {
		select {
		case <-s.stopCh:
			return
		default:
		}
		if src.Port == 53 {
			GlobalDNSCache.ParseAndLearn(frame)
		}
		wrapped := buildSOCKS5UDPHeader(src, frame)
		s.bypassConn.WriteTo(wrapped, clientAddr) //nolint:errcheck
	}
}

// ── RFC 1928 §7 UDP header codec ─────────────────────────────────────────────

// parseSOCKS5UDPHeader parses the RFC 1928 §7 UDP request header.
// Returns the destination address, payload after the header, and the FRAG byte.
func parseSOCKS5UDPHeader(pkt []byte) (dst *net.UDPAddr, payload []byte, frag byte, err error) {
	// RSV(2) + FRAG(1) + ATYP(1) = 4 bytes minimum before addr
	if len(pkt) < 4 {
		return nil, nil, 0, fmt.Errorf("udp header too short")
	}
	// RSV = pkt[0:2] (ignored)
	frag = pkt[2]
	atyp := pkt[3]
	o := 4
	var ip net.IP
	switch atyp {
	case atypIPv4:
		if o+4 > len(pkt) {
			return nil, nil, 0, fmt.Errorf("truncated IPv4")
		}
		ip = make(net.IP, 4)
		copy(ip, pkt[o:o+4])
		o += 4
	case atypIPv6:
		if o+16 > len(pkt) {
			return nil, nil, 0, fmt.Errorf("truncated IPv6")
		}
		ip = make(net.IP, 16)
		copy(ip, pkt[o:o+16])
		o += 16
	case atypDomain:
		if o+1 > len(pkt) {
			return nil, nil, 0, fmt.Errorf("truncated domain length")
		}
		dlen := int(pkt[o])
		o++
		if o+dlen > len(pkt) {
			return nil, nil, 0, fmt.Errorf("truncated domain")
		}
		host := string(pkt[o : o+dlen])
		o += dlen
		addrs, rerr := net.LookupHost(host)
		if rerr != nil || len(addrs) == 0 {
			return nil, nil, 0, fmt.Errorf("resolve %s: %v", host, rerr)
		}
		ip = net.ParseIP(addrs[0])
	default:
		return nil, nil, 0, fmt.Errorf("unknown atyp 0x%02x", atyp)
	}
	if o+2 > len(pkt) {
		return nil, nil, 0, fmt.Errorf("truncated port")
	}
	port := int(binary.BigEndian.Uint16(pkt[o:]))
	o += 2
	dst = &net.UDPAddr{IP: ip, Port: port}
	payload = pkt[o:]
	return
}

// buildSOCKS5UDPHeader wraps payload in an RFC 1928 §7 UDP response header.
func buildSOCKS5UDPHeader(src *net.UDPAddr, payload []byte) []byte {
	ip4 := src.IP.To4()
	var hdr []byte
	if ip4 != nil {
		hdr = make([]byte, 4+4+2)
		// RSV(2)=0, FRAG=0, ATYP=IPv4
		hdr[3] = atypIPv4
		copy(hdr[4:8], ip4)
		binary.BigEndian.PutUint16(hdr[8:], uint16(src.Port))
	} else {
		hdr = make([]byte, 4+16+2)
		hdr[3] = atypIPv6
		copy(hdr[4:20], src.IP.To16())
		binary.BigEndian.PutUint16(hdr[20:], uint16(src.Port))
	}
	return append(hdr, payload...)
}

// ── helpers ───────────────────────────────────────────────────────────────────

func hostOnly(addr string) string {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return h
}

func isNetTimeout(err error) bool {
	if ne, ok := err.(net.Error); ok {
		return ne.Timeout()
	}
	return false
}

// buildUDPRelayPlain builds the plaintext for a /api/udp/relay or /api/udp/drain request.
// Format: [16B conn_id_raw][1B family][4/16B ip][2B port][4B body_len][body]
// body may be nil for drain-only requests (body_len=0).
func buildUDPRelayPlain(connIDHex string, dst *net.UDPAddr, body []byte) ([]byte, error) {
	raw, err := hex.DecodeString(connIDHex)
	if err != nil || len(raw) != 16 {
		return nil, fmt.Errorf("invalid connID")
	}
	ip4 := dst.IP.To4()
	var family byte
	var ipBytes []byte
	if ip4 != nil {
		family = 0x04
		ipBytes = ip4
	} else {
		family = 0x06
		ipBytes = dst.IP.To16()
	}
	plain := make([]byte, 16+1+len(ipBytes)+2+4+len(body))
	o := 0
	copy(plain[o:], raw)
	o += 16
	plain[o] = family
	o++
	copy(plain[o:], ipBytes)
	o += len(ipBytes)
	binary.BigEndian.PutUint16(plain[o:], uint16(dst.Port))
	o += 2
	binary.BigEndian.PutUint32(plain[o:], uint32(len(body)))
	o += 4
	copy(plain[o:], body)
	return plain, nil
}

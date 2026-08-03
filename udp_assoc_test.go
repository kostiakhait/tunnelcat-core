// Copyright (c) 2026 Konstantin Khait

package core

import (
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

// ── codec tests ───────────────────────────────────────────────────────────────

func TestParseSOCKS5UDPHeader_IPv4(t *testing.T) {
	// RSV(2)=0, FRAG=0, ATYP=IPv4, ip=1.2.3.4, port=80, payload="hello"
	pkt := []byte{0, 0, 0, atypIPv4, 1, 2, 3, 4, 0, 80}
	pkt = append(pkt, []byte("hello")...)

	dst, payload, frag, err := parseSOCKS5UDPHeader(pkt)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if frag != 0 {
		t.Errorf("expected frag=0, got %d", frag)
	}
	if dst.IP.String() != "1.2.3.4" {
		t.Errorf("unexpected IP: %s", dst.IP)
	}
	if dst.Port != 80 {
		t.Errorf("unexpected port: %d", dst.Port)
	}
	if string(payload) != "hello" {
		t.Errorf("unexpected payload: %q", payload)
	}
}

func TestParseSOCKS5UDPHeader_IPv6(t *testing.T) {
	ip := net.ParseIP("2001:db8::1")
	pkt := []byte{0, 0, 0, atypIPv6}
	pkt = append(pkt, ip.To16()...)
	pkt = append(pkt, 0x01, 0xBB) // port 443
	pkt = append(pkt, []byte("data")...)

	dst, payload, _, err := parseSOCKS5UDPHeader(pkt)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if !dst.IP.Equal(ip) {
		t.Errorf("unexpected IP: %s", dst.IP)
	}
	if dst.Port != 443 {
		t.Errorf("unexpected port: %d", dst.Port)
	}
	if string(payload) != "data" {
		t.Errorf("unexpected payload: %q", payload)
	}
}

func TestParseSOCKS5UDPHeader_FragNonZero(t *testing.T) {
	pkt := []byte{0, 0, 1, atypIPv4, 1, 2, 3, 4, 0, 80}
	_, _, frag, err := parseSOCKS5UDPHeader(pkt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if frag != 1 {
		t.Errorf("expected frag=1, got %d", frag)
	}
}

func TestBuildSOCKS5UDPHeader_RoundTrip(t *testing.T) {
	src := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1234}
	payload := []byte("response")
	pkt := buildSOCKS5UDPHeader(src, payload)

	dst, got, frag, err := parseSOCKS5UDPHeader(pkt)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if frag != 0 {
		t.Errorf("expected frag=0, got %d", frag)
	}
	if dst.IP.String() != "10.0.0.1" || dst.Port != 1234 {
		t.Errorf("unexpected addr: %v", dst)
	}
	if string(got) != "response" {
		t.Errorf("unexpected payload: %q", got)
	}
}

func TestBuildUDPRelayPlain_RoundTrip(t *testing.T) {
	connID := newConnID()
	dst := &net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 53}
	body := []byte("query")

	plain, err := buildUDPRelayPlain(connID, dst, body)
	if err != nil {
		t.Fatalf("build error: %v", err)
	}
	// Parse manually: [16B connID][1B family][4B ip][2B port][4B bLen][body]
	if len(plain) < 16+1+4+2+4+len(body) {
		t.Fatalf("plain too short: %d", len(plain))
	}
	family := plain[16]
	if family != 0x04 {
		t.Errorf("expected IPv4 family, got 0x%02x", family)
	}
	ip := net.IP(plain[17:21])
	if ip.String() != "8.8.8.8" {
		t.Errorf("unexpected ip: %s", ip)
	}
	port := binary.BigEndian.Uint16(plain[21:23])
	if port != 53 {
		t.Errorf("unexpected port: %d", port)
	}
	bLen := binary.BigEndian.Uint32(plain[23:27])
	if int(bLen) != len(body) {
		t.Errorf("unexpected bLen: %d", bLen)
	}
	if string(plain[27:27+bLen]) != "query" {
		t.Errorf("unexpected body: %q", plain[27:27+bLen])
	}
}

// ── SOCKS5 UDP ASSOCIATE handshake test ───────────────────────────────────────

func TestSOCKS5UDPAssocNoBypass_TunnelMode(t *testing.T) {
	// Without bypass manager: UDP ASSOCIATE now succeeds in tunnel-only mode
	// using a loopback socket. The reply must be success (0x00) with a valid
	// 127.0.0.1 bind address so tun2socks can send datagrams to us.
	srv := minimalTunnelStub(t)
	defer srv.Close()

	auth := NewAuthenticator(srv.URL, "", "", "")
	auth.token = "tok"
	dialer := NewTunnelDialer(auth)

	socks := NewSOCKS5Server("127.0.0.1:0", dialer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go socks.Serve(ln) //nolint:errcheck

	c, _ := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
	defer c.Close()
	c.Write([]byte{0x05, 0x01, 0x00})                         //nolint:errcheck
	io.ReadFull(c, make([]byte, 2))                           //nolint:errcheck
	c.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) //nolint:errcheck
	reply := make([]byte, 10)
	io.ReadFull(c, reply) //nolint:errcheck
	if reply[1] != repSuccess {
		t.Errorf("expected repSuccess (0x00) for tunnel-only UDP ASSOCIATE, got 0x%02x", reply[1])
	}
	// BND.ADDR must be 127.0.0.1 (loopback socket)
	if reply[3] != atypIPv4 || reply[4] != 127 || reply[5] != 0 || reply[6] != 0 || reply[7] != 1 {
		t.Errorf("expected loopback bind addr 127.0.0.1, got reply %v", reply)
	}
}

func TestSOCKS5UDPAssocWithBypass_ReturnsSuccess(t *testing.T) {
	// With bypass manager: UDP ASSOCIATE must succeed and return a bound UDP addr.
	bm, err := NewBypassManager([]string{"http://127.0.0.1:1"}, "", "")
	if err != nil {
		t.Skip("bypass manager unavailable:", err)
	}
	bm.SetLocalIP("127.0.0.1")

	srv := minimalTunnelStub(t)
	defer srv.Close()

	auth := NewAuthenticator(srv.URL, "", "", "")
	auth.token = "tok"
	dialer := NewTunnelDialer(auth)

	socks := NewSOCKS5ServerWithBypass("127.0.0.1:0", dialer, bm)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go socks.Serve(ln) //nolint:errcheck

	c, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second)) //nolint:errcheck

	// Handshake
	c.Write([]byte{0x05, 0x01, 0x00}) //nolint:errcheck
	hs := make([]byte, 2)
	io.ReadFull(c, hs) //nolint:errcheck

	// UDP ASSOCIATE request (DST = 0.0.0.0:0)
	c.Write([]byte{0x05, 0x03, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0}) //nolint:errcheck

	// Read reply: ver(1) rep(1) rsv(1) atyp(1) ip(4) port(2) = 10 bytes
	reply := make([]byte, 10)
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if reply[1] != repSuccess {
		t.Fatalf("expected repSuccess (0x00), got 0x%02x", reply[1])
	}
	if reply[3] != atypIPv4 {
		t.Errorf("expected IPv4 atyp in reply, got 0x%02x", reply[3])
	}
	port := binary.BigEndian.Uint16(reply[8:10])
	if port == 0 {
		t.Error("expected non-zero relay port in reply")
	}
	t.Logf("relay bound at port %d", port)
}

// ── relay loop end-to-end test ────────────────────────────────────────────────

// TestUDPAssocForwardOutbound verifies that forwardOutbound delivers a datagram
// to the echo server via the bypass socket.
//
// The relay loop end-to-end test is intentionally omitted: on loopback both the
// tun2socks "client" and real destination servers share 127.0.0.1, making it
// impossible to distinguish inbound from outbound datagrams by IP address alone.
// Production traffic uses TUN IPs (198.18.x.x) for the client side, which never
// collide with real destination IPs.
func TestUDPAssocForwardOutbound(t *testing.T) {
	// Start a UDP receiver that records incoming datagrams.
	rxConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer rxConn.Close()
	rxAddr := rxConn.LocalAddr().(*net.UDPAddr)

	received := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 1024)
		rxConn.SetDeadline(time.Now().Add(2 * time.Second)) //nolint:errcheck
		n, _, err := rxConn.ReadFromUDP(buf)
		if err == nil {
			data := make([]byte, n)
			copy(data, buf[:n])
			received <- data
		} else {
			close(received)
		}
	}()

	// Build a minimal session (ctrl conn not used by forwardOutbound).
	tcpSrv, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpSrv.Close()
	cConn, err := net.Dial("tcp", tcpSrv.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer cConn.Close()
	sConn, _ := tcpSrv.Accept()
	defer sConn.Close()

	bm, err := NewBypassManager([]string{"http://127.0.0.1:1"}, "", "")
	if err != nil {
		t.Skip("bypass manager unavailable:", err)
	}
	bm.SetLocalIP("127.0.0.1")

	srv := minimalTunnelStub(t)
	defer srv.Close()
	auth := NewAuthenticator(srv.URL, "", "", "")
	auth.token = "tok"
	dialer := NewTunnelDialer(auth)

	sess, err := newUDPAssocSession(sConn, bm, func() *TunnelDialer { return dialer }, false, false)
	if err != nil {
		t.Fatal(err)
	}
	// Don't start relayLoop — we call forwardOutbound directly.
	defer sess.bypassConn.Close()

	payload := []byte("hello-udp")
	sess.forwardOutbound(rxAddr, payload)

	select {
	case data, ok := <-received:
		if !ok {
			t.Fatal("no datagram received before timeout")
		}
		if string(data) != "hello-udp" {
			t.Errorf("expected 'hello-udp', got %q", data)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for datagram")
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

// Satisfy the compiler: repSuccess is defined in socks5.go.
var _ = http.StatusOK // keep net/http import used

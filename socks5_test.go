// Copyright (c) 2026 Konstantin Khait

package core

import (
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// dialSOCKS5 performs a SOCKS5 CONNECT handshake and returns the raw conn.
func dialSOCKS5(t *testing.T, socksAddr, target string) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", socksAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial socks5: %v", err)
	}

	// Handshake: no auth
	c.Write([]byte{0x05, 0x01, 0x00}) //nolint:errcheck
	resp := make([]byte, 2)
	if _, err := io.ReadFull(c, resp); err != nil {
		t.Fatal("handshake read:", err)
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		t.Fatalf("unexpected handshake response: %v", resp)
	}

	// CONNECT request with domain name
	host, portStr, _ := net.SplitHostPort(target)
	port, _ := net.LookupPort("tcp", portStr)
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, []byte(host)...)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))
	req = append(req, portBytes...)
	c.Write(req) //nolint:errcheck

	reply := make([]byte, 10)
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatal("connect reply read:", err)
	}
	if reply[1] != 0x00 {
		t.Fatalf("CONNECT failed with rep=%02x", reply[1])
	}
	return c
}

// minimalTunnelStub is a stub tunnel server using the new encrypted protocol.
// Supports both upload (polling) and streaming frame types.
func minimalTunnelStub(t *testing.T) *httptest.Server {
	t.Helper()
	pool := map[string]net.Conn{}
	var mu sync.Mutex

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("X-Session")
		key := sessionKey(token)

		body, _ := io.ReadAll(r.Body)
		plain, err := openFrame(key, body)
		if err != nil || len(plain) < 1 {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		switch plain[0] {

		case frameTypeStreamOpen:
			if len(plain) < 1+16 {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			connID := string(plain[1:17]) // raw bytes as map key
			mu.Lock()
			conn := pool[connID]
			mu.Unlock()
			if conn == nil {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			flusher, ok := w.(http.Flusher)
			if !ok {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			w.WriteHeader(http.StatusOK)
			buf := make([]byte, 65536)
			var lenBuf [4]byte
			for {
				conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond)) //nolint:errcheck
				n, err := conn.Read(buf)
				if n > 0 {
					ct, cerr := sealFrame(key, buf[:n])
					if cerr != nil {
						return
					}
					binary.BigEndian.PutUint32(lenBuf[:], uint32(len(ct)))
					w.Write(lenBuf[:]) //nolint:errcheck
					w.Write(ct)        //nolint:errcheck
					flusher.Flush()
				}
				if err != nil {
					break
				}
			}

		case frameTypeUpload:
			connID, seq, target, payload, err := parseUploadFrame(plain)
			if err != nil {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			// use raw 16 bytes as pool key for streaming lookup above
			rawKey := string(plain[1:17])

			mu.Lock()
			conn := pool[connID]
			mu.Unlock()

			if seq == 0 {
				conn, err = net.DialTimeout("tcp", target, time.Second)
				if err != nil {
					w.WriteHeader(http.StatusBadGateway)
					return
				}
				mu.Lock()
				pool[connID] = conn
				pool[rawKey] = conn
				mu.Unlock()
			} else if conn == nil {
				w.WriteHeader(http.StatusNotFound)
				return
			}

			if len(payload) > 0 {
				conn.SetWriteDeadline(time.Now().Add(200 * time.Millisecond)) //nolint:errcheck
				conn.Write(payload)                                           //nolint:errcheck
			}

			resp, _ := buildUploadResponse(key, nil)
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Write(resp) //nolint:errcheck

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

// ── tests ─────────────────────────────────────────────────────────────────────

func TestSOCKS5ConnectAndEcho(t *testing.T) {
	echoAddr, stop := echoTCP(t)
	defer stop()

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
	socksAddr := ln.Addr().String()
	go socks.Serve(ln)

	c := dialSOCKS5(t, socksAddr, echoAddr)
	defer c.Close()

	msg := []byte("socks5-echo-test")
	c.Write(msg) //nolint:errcheck

	c.SetReadDeadline(time.Now().Add(3 * time.Second)) //nolint:errcheck
	buf := make([]byte, 256)
	n, err := c.Read(buf)
	if err != nil && n == 0 {
		t.Fatalf("Read: %v", err)
	}
	if string(buf[:len(msg)]) != string(msg) {
		t.Errorf("echo mismatch: got %q want %q", buf[:n], msg)
	}
}

func TestSOCKS5NoAuthRequired(t *testing.T) {
	srv := minimalTunnelStub(t)
	defer srv.Close()

	auth := NewAuthenticator(srv.URL, "", "", "")
	auth.token = "tok"
	socks := NewSOCKS5Server("127.0.0.1:0", NewTunnelDialer(auth))
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	go socks.Serve(ln)

	c, _ := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
	defer c.Close()

	c.Write([]byte{0x05, 0x01, 0x02}) //nolint:errcheck
	resp := make([]byte, 2)
	io.ReadFull(c, resp) //nolint:errcheck
	if resp[1] != authNoAccept {
		t.Errorf("expected authNoAccept (0xFF), got 0x%02x", resp[1])
	}
}

func TestSOCKS5IPv4Connect(t *testing.T) {
	echoAddr, stop := echoTCP(t)
	defer stop()

	srv := minimalTunnelStub(t)
	defer srv.Close()

	auth := NewAuthenticator(srv.URL, "", "", "")
	auth.token = "tok"
	socks := NewSOCKS5Server("127.0.0.1:0", NewTunnelDialer(auth))
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	go socks.Serve(ln)

	c, _ := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
	defer c.Close()

	c.Write([]byte{0x05, 0x01, 0x00}) //nolint:errcheck
	io.ReadFull(c, make([]byte, 2))   //nolint:errcheck

	host, portStr, _ := net.SplitHostPort(echoAddr)
	port, _ := net.LookupPort("tcp", portStr)
	ip := net.ParseIP(host).To4()

	req := []byte{0x05, 0x01, 0x00, 0x01}
	req = append(req, ip...)
	pb := make([]byte, 2)
	binary.BigEndian.PutUint16(pb, uint16(port))
	req = append(req, pb...)
	c.Write(req) //nolint:errcheck

	reply := make([]byte, 10)
	io.ReadFull(c, reply) //nolint:errcheck
	if reply[1] != repSuccess {
		t.Errorf("expected success, got 0x%02x", reply[1])
	}
}

// Copyright (c) 2026 Konstantin Khait

package core

import (
	"context"
	"crypto/tls"
	"math/rand"
	"net"
	"net/http"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

// ControlSNILookup, if set, is called with a control node addr (host:port) to
// obtain the SNI hostname to use for that TLS connection. Returns "" when no
// SNI is configured for that addr, preserving the current empty-SNI behaviour.
// Set once at startup via Discoverer.UseAsSNIProvider().
var ControlSNILookup func(addr string) string

// sniFor extracts the SNI for the given addr, handling the nil guard.
func sniFor(addr string) string {
	if ControlSNILookup == nil {
		return ""
	}
	return ControlSNILookup(addr)
}

// Channel type constants embedded in ClientHello Session ID for server-side
// demultiplexing. The two-byte marker {chMagic, channelType} at sid[0:2]
// identifies a tunnel connection; standard TLS 1.3 clients send a random 32-byte
// session ID so accidental collisions are negligible (p ≈ 1/256 per connection).
const (
	chMagic    byte = 0xA7
	ChTunnel   byte = 0x00 // raw TCP proxy to exit; no TLS termination on control
	ChRelayAPI byte = 0x01 // relay tracker HTTP API
	ChSignal   byte = 0x02 // NAT relay reverse-tunnel (yamux)
	ChNATRelay byte = 0x03 // sender routing through a NAT relay node
	ChParaExit byte = 0x04 // para-exit yamux reverse-tunnel (on exit)
)

// utlsPresets is the set of browser fingerprints we rotate between.
// Chrome and Firefox are by far the most common in the wild.
var utlsPresets = []utls.ClientHelloID{
	utls.HelloChrome_Auto,
	utls.HelloChrome_Auto, // 2× weight — Chrome is dominant
	utls.HelloFirefox_Auto,
	utls.HelloEdge_Auto,
	utls.HelloSafari_Auto,
}

func pickPreset() utls.ClientHelloID {
	return utlsPresets[rand.Intn(len(utlsPresets))]
}

// AllUTLSPresets returns the distinct browser presets used by the tunnel transport.
// Useful for diagnostic tools that want to test each preset independently.
func AllUTLSPresets() []utls.ClientHelloID {
	return []utls.ClientHelloID{
		utls.HelloChrome_Auto,
		utls.HelloFirefox_Auto,
		utls.HelloEdge_Auto,
		utls.HelloSafari_Auto,
	}
}

// PresetName returns a short human-readable name for a uTLS preset.
func PresetName(p utls.ClientHelloID) string {
	switch p {
	case utls.HelloChrome_Auto:
		return "Chrome"
	case utls.HelloFirefox_Auto:
		return "Firefox"
	case utls.HelloEdge_Auto:
		return "Edge"
	case utls.HelloSafari_Auto:
		return "Safari"
	default:
		return p.Client + "/" + p.Version
	}
}

// NewUTLSClientWithPreset returns an *http.Client whose TLS connections use the
// given uTLS browser preset. Used by diagnostic tools to test preset compatibility.
func NewUTLSClientWithPreset(preset utls.ClientHelloID) *http.Client {
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: newUTLSTransport(ChTunnel, preset),
	}
}

// wrapUTLS wraps an already-dialled TCP connection with a uTLS ClientHello.
// serverName sets the TLS SNI; pass "" to omit SNI (RFC 6066 requires this for
// bare-IP servers). The channel type is encoded in Session ID bytes [0:2].
func wrapUTLS(rawConn net.Conn, channelType byte, serverName string) (net.Conn, error) {
	uconn := utls.UClient(rawConn, &utls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true, //nolint:gosec // fingerprint verified via manifest
	}, pickPreset())
	if err := uconn.BuildHandshakeState(); err != nil {
		rawConn.Close()
		return nil, err
	}
	if sid := uconn.HandshakeState.Hello.SessionId; len(sid) >= 2 {
		sid[0] = chMagic
		sid[1] = channelType
	}
	if err := uconn.Handshake(); err != nil {
		rawConn.Close()
		return nil, err
	}
	return uconn, nil
}

// utlsRoundTripper routes HTTPS requests through an http2.Transport backed by
// a uTLS dialer, and plain HTTP requests through a plain http.Transport.
type utlsRoundTripper struct {
	h1 *http.Transport
	h2 *http2.Transport
}

func (rt *utlsRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme == "https" {
		return rt.h2.RoundTrip(req)
	}
	return rt.h1.RoundTrip(req)
}

// newUTLSTransport returns an http.RoundTripper whose TLS handshakes use the
// given browser fingerprint and embed channelType in the Session ID for
// server-side demultiplexing. SNI is empty (RFC 6066, IP-addressed servers).
//
// HTTPS requests use http2.Transport (h2 over uTLS).
// Plain HTTP requests use a standard http.Transport (used by test servers).
func newUTLSTransport(channelType byte, preset utls.ClientHelloID) http.RoundTripper {
	return newUTLSTransportRaw(channelType, preset, nil)
}

// newUTLSTransportRaw is the internal implementation.
// rawDial, if non-nil, is called instead of net.Dialer to obtain the TCP
// connection.
func newUTLSTransportRaw(channelType byte, preset utls.ClientHelloID,
	rawDial func(ctx context.Context, addr string) (net.Conn, error)) http.RoundTripper {

	dialUTLS := func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
		var rawConn net.Conn
		var err error
		if rawDial != nil {
			rawConn, err = rawDial(ctx, addr)
		} else {
			d := &net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
				Control:   dialControl,
			}
			rawConn, err = d.DialContext(ctx, network, addr)
		}
		if err != nil {
			return nil, err
		}
		uconn := utls.UClient(rawConn, &utls.Config{
			ServerName:         sniFor(addr),
			InsecureSkipVerify: true, //nolint:gosec
		}, preset)
		if err := uconn.BuildHandshakeState(); err != nil {
			rawConn.Close()
			return nil, err
		}
		if sid := uconn.HandshakeState.Hello.SessionId; len(sid) >= 2 {
			sid[0] = chMagic
			sid[1] = channelType
		}
		if err := uconn.HandshakeContext(ctx); err != nil {
			rawConn.Close()
			return nil, err
		}
		return uconn, nil
	}

	h2t := &http2.Transport{
		DialTLSContext: dialUTLS,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec
		},
		// Detect dead h2 connections: send a PING if idle, kill if no pong.
		// Without this, stale connections silently absorb new requests until
		// client.Timeout (30s) fires on every stream — the "all controls timeout"
		// pattern seen after long uptime or a brief control restart.
		ReadIdleTimeout: 30 * time.Second,
		PingTimeout:     15 * time.Second,
	}

	h1t := &http.Transport{
		MaxIdleConns:        64,
		MaxIdleConnsPerHost: 64,
		IdleConnTimeout:     90 * time.Second,
	}

	return &utlsRoundTripper{h1: h1t, h2: h2t}
}

// NewRelayAPIH1Client returns an *http.Client that uses uTLS (browser fingerprint +
// ChRelayAPI channel ID in Session ID) but HTTP/1.1 only — no h2.
// Use for control-node /p/v1/* endpoints that don't support HTTP/2.
// dialControl is applied so connections bypass the VPN TUN on Android.
func NewRelayAPIH1Client() *http.Client { return newUTLSH1Client() }

// newUTLSH1Client is the internal implementation used by NewRelayAPIH1Client and
// newRelayAPIHTTPClient.
func newUTLSH1Client() *http.Client {
	preset := pickPreset()
	t := &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialer := &net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
				Control:   dialControl,
			}
			rawConn, err := dialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			uconn := utls.UClient(rawConn, &utls.Config{
				ServerName:         sniFor(addr),
				InsecureSkipVerify: true, //nolint:gosec
				// Force HTTP/1.1 in ALPN — server speaks h1 only for this channel.
				// Without this, Chrome preset offers h2; if the server agrees,
				// http.Transport silently switches to h2 and gets framing errors.
				NextProtos: []string{"http/1.1"},
			}, preset)
			if err := uconn.BuildHandshakeState(); err != nil {
				rawConn.Close()
				return nil, err
			}
			if sid := uconn.HandshakeState.Hello.SessionId; len(sid) >= 2 {
				sid[0] = chMagic
				sid[1] = ChRelayAPI
			}
			if err := uconn.HandshakeContext(ctx); err != nil {
				rawConn.Close()
				return nil, err
			}
			return uconn, nil
		},
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		MaxIdleConns:        4,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     60 * time.Second,
	}
	return &http.Client{Timeout: 30 * time.Second, Transport: t}
}

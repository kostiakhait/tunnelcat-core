# tunnelcat-core

A Go library for SOCKS5/TUN tunnel clients: session auth, a self-healing
multi-node dialer pool, SOCKS5 (TCP + UDP ASSOCIATE) and TUN bridging, DHT
peer discovery, NAT hole-punching, and a uTLS transport that disguises
tunnel traffic as ordinary HTTPS uploads.

An open implementation of the Tunnel Cat tunnel architecture, released as a
standalone client/library. There's no tooling here to deploy your own
control/exit nodes, and no public control/exit network attached to this
repo — you point it at a server you run yourself, speaking the login
protocol described below.

## Quickstart

```sh
go build ./...
go test ./...
```

Run the reference CLI against a control server you operate:

```sh
go run ./cmd/demo -server https://your-control-server:443 -user U -pass P
# starts a local SOCKS5 proxy at 127.0.0.1:1080 — point any SOCKS5 client at it
# (add -tun for a TUN interface too, -apikey/-socks also available)
```

...or use it directly as a library:

```go
auth := core.NewAuthenticator(serverURL, apiKey, username, password)
if err := auth.Login(); err != nil {
    log.Fatal(err)
}

dialer := core.NewTunnelDialer(auth)
socks := core.NewSOCKS5Server("127.0.0.1:1080", dialer)
log.Fatal(socks.ListenAndServe())
```

`serverURL` must point at a server that speaks this library's login/tunnel
protocol: `POST <server>/` with `{".command": "verifyPassword", ...}`,
response `{"session": "<token>"}`, then encrypted data-plane frames over
`X-Session`-authenticated POSTs. `key.go`'s exported `VerifySignedPayload`
plus `SessionKey`/`SealFrame`/`OpenFrame`/`ParseUploadFrame`/
`BuildUploadResponse` give you everything needed to implement a compatible
server without reverse-engineering the wire format from this client.

## What's inside

- **Session & transport** (`tunnel.go`) — `Authenticator` (login, session
  token, key- or password-based auth), `TunnelDialer` (creates tunnel
  connections disguised as HTTPS media uploads via uTLS browser fingerprints).
- **SOCKS5** (`socks5.go`, `udp_assoc.go`) — TCP CONNECT and UDP ASSOCIATE
  (RFC 1928 §4/§7), per-IP connection limiting, an optional bypass manager for
  LAN/in-country direct routing.
- **TUN bridging** (`tun.go`, `tun_darwin.go`, `tun_linux.go`) — brings up a
  TUN interface backed by [`tun2socks`](https://github.com/xjasonlyu/tun2socks)
  routed through the local SOCKS5 proxy. Windows uses the
  [Wintun](https://www.wintun.net/) driver (see licensing note below).
- **Dialer pool & routing** (`dialer_pool.go`, `router.go`) — multi-node
  failover: RTT-based scoring, reliability-weighted picking, liveness
  tracking.
- **Discovery** (`discovery.go`, `dht/`) — Ed25519-signed manifest fetch/verify
  plus a Kademlia-style DHT for decentralized peer discovery.
- **NAT/hole-punching** (`nat.go`, `holepunch.go`) and **relay** (`relay.go`,
  `mirror.go`) — UDP hole-punch coordination and a relay fallback path for
  peers that can't punch through.
- **`cmd/demo`** — the minimal CLI shown above.
- **`tools/fetch_wintun`** — pre-fetches the Wintun driver DLL into the
  source tree, if you'd rather not rely on the runtime auto-download.

## Wintun licensing note

Windows TUN support uses the [Wintun](https://www.wintun.net/) driver, which
is not part of this repository — `internal/wintun` downloads the official
build directly from wintun.net the first time it's needed. Wintun is
distributed by WireGuard under its own license terms (GPLv2 / LGPLv2.1 / a
commercial license, at the distributor's choice) — review those terms before
redistributing a binary that bundles the driver.

## License

MIT — see [LICENSE](LICENSE). Third-party dependencies keep their own
licenses (all permissive: BSD-3, MIT, MPL-2.0); see `go.mod`.

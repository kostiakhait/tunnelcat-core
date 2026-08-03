// Copyright (c) 2026 Konstantin Khait

package core

import "syscall"

// dialControl, when non-nil, is called for every new outbound TCP/UDP socket
// before it is connected. On Android, set this to protect sockets from VPN
// routing via VpnService.protect(fd).
var dialControl func(network, address string, c syscall.RawConn) error

// SetDialControl installs a per-socket hook called before each outbound
// connection. Safe to call before any goroutine starts dialling.
func SetDialControl(fn func(network, address string, c syscall.RawConn) error) {
	dialControl = fn
}

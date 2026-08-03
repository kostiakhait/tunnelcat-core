// Copyright (c) 2026 Konstantin Khait

//go:build !windows

package core

import "net"

// WrapWithTorrentFilter is a no-op on non-Windows platforms.
func WrapWithTorrentFilter(ln net.Listener) net.Listener { return ln }

// Copyright (c) 2026 Konstantin Khait

package core

// procfilter_windows.go — torrent-process blocking at the SOCKS5 listener level.
//
// This is a workaround: torrent clients open hundreds of short-lived connections
// through the SOCKS5 proxy, flooding the control nodes with P2P dial attempts.
// Even with neutral timeout/404 accounting in the rolling window, the raw
// connection volume degrades throughput for other apps.  Blocking at accept()
// time is the simplest surgical fix.
//
// Implementation: when the listener accepts a TCP connection from localhost,
// we look up the client's local port in the OS TCP table (GetExtendedTcpTable),
// resolve the owning PID, then map it to a process name via
// QueryFullProcessImageNameW.  Known torrent executable names trigger a
// silent close before the SOCKS5 handshake.

import (
	"net"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

// torrentExeNames is the set of lower-case executable names to block.
// Deliberately narrow — only dedicated BitTorrent clients, not generic
// download managers that might also do legitimate HTTP traffic.
var torrentExeNames = map[string]bool{
	"qbittorrent.exe":     true,
	"utorrent.exe":        true,
	"bittorrent.exe":      true,
	"transmission.exe":    true,
	"transmission-qt.exe": true,
	"deluge.exe":          true,
	"vuze.exe":            true,
	"tixati.exe":          true,
	"bitcomet.exe":        true,
	"biglybt.exe":         true,
	"webtorrent.exe":      true,
	"frostwire.exe":       true,
}

// WrapWithTorrentFilter wraps ln so that incoming SOCKS5 connections from known
// torrent clients are silently dropped before the handshake.
func WrapWithTorrentFilter(ln net.Listener) net.Listener {
	return &torrentFilterListener{Listener: ln}
}

type torrentFilterListener struct{ net.Listener }

func (f *torrentFilterListener) Accept() (net.Conn, error) {
	for {
		conn, err := f.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if isTorrentConn(conn) {
			conn.Close()
			continue
		}
		return conn, nil
	}
}

// isTorrentConn returns true when the connecting process is a known torrent client.
func isTorrentConn(conn net.Conn) bool {
	ta, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok || ta.Port == 0 {
		return false
	}
	pid, err := pidForLocalPort(uint16(ta.Port))
	if err != nil || pid == 0 {
		return false
	}
	name, err := exeNameForPID(pid)
	if err != nil {
		return false
	}
	blocked := torrentExeNames[strings.ToLower(filepath.Base(name))]
	if blocked {
		Log.Printf("procfilter: blocking torrent process %s (pid=%d) from %s", name, pid, conn.RemoteAddr())
	}
	return blocked
}

// ── Windows API plumbing ──────────────────────────────────────────────────────

var (
	iphlpapi                = syscall.NewLazyDLL("iphlpapi.dll")
	procGetExtendedTcpTable = iphlpapi.NewProc("GetExtendedTcpTable")

	kernel32                      = syscall.NewLazyDLL("kernel32.dll")
	procOpenProcess               = kernel32.NewProc("OpenProcess")
	procQueryFullProcessImageName = kernel32.NewProc("QueryFullProcessImageNameW")
	procCloseHandle               = kernel32.NewProc("CloseHandle")
)

// TCP_TABLE_OWNER_PID_ALL enumerates all TCP connections with owning PIDs.
const tcpTableOwnerPidAll = 5

// mibTcpRowOwnerPid mirrors MIB_TCPROW_OWNER_PID.
type mibTcpRowOwnerPid struct {
	state      uint32
	localAddr  uint32
	localPort  uint32 // port in network byte order in low 16 bits
	remoteAddr uint32
	remotePort uint32
	owningPid  uint32
}

// pidForLocalPort queries the TCP connection table for the process that owns
// the given local port on 127.0.0.1.
func pidForLocalPort(port uint16) (uint32, error) {
	if err := procGetExtendedTcpTable.Find(); err != nil {
		return 0, err
	}
	// First call: get required buffer size.
	var size uint32
	procGetExtendedTcpTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, syscall.AF_INET, tcpTableOwnerPidAll, 0) //nolint:errcheck

	buf := make([]byte, size)
	ret, _, _ := procGetExtendedTcpTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		0,
		syscall.AF_INET,
		tcpTableOwnerPidAll,
		0,
	)
	if ret != 0 {
		return 0, syscall.Errno(ret)
	}

	// buf layout: [numEntries uint32][rows...]
	numEntries := *(*uint32)(unsafe.Pointer(&buf[0]))
	rowSize := unsafe.Sizeof(mibTcpRowOwnerPid{})
	base := uintptr(unsafe.Pointer(&buf[4])) // skip numEntries field

	// netPort: port in network byte order stored in low 16 bits
	netPort := uint32(port>>8) | uint32(port&0xff)<<8

	for i := uint32(0); i < numEntries; i++ {
		row := (*mibTcpRowOwnerPid)(unsafe.Pointer(base + uintptr(i)*rowSize))
		if uint16(row.localPort) == uint16(netPort) {
			return row.owningPid, nil
		}
	}
	return 0, nil
}

const processQueryLimitedInformation = 0x1000

// exeNameForPID returns the base executable name for the given process ID.
func exeNameForPID(pid uint32) (string, error) {
	if err := procOpenProcess.Find(); err != nil {
		return "", err
	}
	handle, _, err := procOpenProcess.Call(processQueryLimitedInformation, 0, uintptr(pid))
	if handle == 0 {
		return "", err
	}
	defer procCloseHandle.Call(handle) //nolint:errcheck

	var buf [syscall.MAX_PATH]uint16
	size := uint32(len(buf))
	ret, _, err := procQueryFullProcessImageName.Call(
		handle,
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
	)
	if ret == 0 {
		return "", err
	}
	return syscall.UTF16ToString(buf[:size]), nil
}

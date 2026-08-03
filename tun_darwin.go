// Copyright (c) 2026 Konstantin Khait

//go:build darwin

package core

import (
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/xjasonlyu/tun2socks/v2/engine"
)

const (
	TUNDeviceName = "utun" // logical name; kernel assigns utunN at runtime
	TUNMTU        = 1500
	TUNAddr       = "198.18.0.1"
	TUNMask       = "255.255.0.0"
	TUNIPv6Addr   = "fd00::2"
)

// safeEngineStart wraps engine.Start() recovering any panic (tun2socks uses
// WriteThenPanic in debug mode instead of os.Exit).
func safeEngineStart() (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%v", r)
		}
	}()
	engine.Start()
	return nil
}

// safeEngineStop wraps engine.Stop() with panic recovery.
func safeEngineStop() {
	defer func() {
		if r := recover(); r != nil {
			Log.Printf("TUN: engine.Stop() panic (recovered): %v", r)
		}
	}()
	engine.Stop()
}

// hiddenCmd is a no-op wrapper on macOS (no hidden-window flag needed).
func hiddenCmd(name string, args ...string) *exec.Cmd {
	return exec.Command(name, args...)
}

// TUNBridge bridges a macOS utun interface to a local SOCKS5 server via
// tun2socks / gVisor netstack. All IP traffic entering the utun device is
// transparently proxied through the SOCKS5 server.
type TUNBridge struct {
	socksAddr string
	running   bool
	ifaceName string // actual utunN name assigned by the kernel (e.g. "utun3")
}

// NewTUNBridge returns a bridge that will forward TUN traffic to socksAddr.
func NewTUNBridge(socksAddr string) *TUNBridge {
	return &TUNBridge{socksAddr: socksAddr}
}

// IfaceName returns the actual utunN interface name after a successful Start.
func (b *TUNBridge) IfaceName() string { return b.ifaceName }

// Start creates the utun interface and launches the gVisor netstack.
// Retries up to 3 times because the kernel occasionally fails on first attempt.
func (b *TUNBridge) Start() error {
	const maxAttempts = 3
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		lastErr = b.startOnce()
		if lastErr == nil {
			return nil
		}
		Log.Printf("TUN: start attempt %d/%d failed: %v", attempt, maxAttempts, lastErr)
		if attempt < maxAttempts {
			safeEngineStop()
			time.Sleep(time.Duration(attempt) * 3 * time.Second)
		}
	}
	return lastErr
}

func (b *TUNBridge) startOnce() error {
	Log.Printf("TUN: starting bridge → SOCKS5 %s", b.socksAddr)

	// Snapshot existing utun interfaces so we can detect the new one below.
	before := listUtunInterfaces()

	// tun2socks on macOS creates the next available utunN when Device is "tun://utun".
	engine.Insert(&engine.Key{
		Device:   "tun://utun",
		Proxy:    "socks5://" + b.socksAddr,
		MTU:      TUNMTU,
		LogLevel: "debug",
	})
	if err := safeEngineStart(); err != nil {
		return fmt.Errorf("engine start: %w", err)
	}

	// Give the kernel a moment to register the new interface.
	time.Sleep(300 * time.Millisecond)

	after := listUtunInterfaces()
	iface := findNewUtun(before, after)
	if iface == "" {
		safeEngineStop()
		return fmt.Errorf("could not detect new utun interface (before=%v after=%v)", before, after)
	}
	b.ifaceName = iface
	Log.Printf("TUN: using interface %s", iface)

	// Assign the TUN address. utun is point-to-point: both local and peer are
	// set to TUNAddr so the kernel treats the entire /16 as on-link.
	if out, err := exec.Command("ifconfig", iface, "inet",
		TUNAddr, TUNAddr, "up").CombinedOutput(); err != nil {
		safeEngineStop()
		return fmt.Errorf("configure TUN IP: %w (ifconfig: %s)", err, strings.TrimSpace(string(out)))
	}
	Log.Printf("TUN: interface %s configured at %s", iface, TUNAddr)

	// Cap MTU to 1280 — leaves headroom for tunnel framing on any physical link.
	if out, err := exec.Command("ifconfig", iface, "mtu", "1280").CombinedOutput(); err != nil {
		Log.Printf("TUN: WARN set MTU: %v (%s)", err, strings.TrimSpace(string(out)))
	} else {
		Log.Printf("TUN: MTU set to 1280 on %s", iface)
	}

	// Assign a ULA IPv6 address so split routes cover ::/0.
	if out, err := exec.Command("ifconfig", iface, "inet6", TUNIPv6Addr+"/128").CombinedOutput(); err != nil {
		Log.Printf("TUN: WARN assign IPv6: %v (%s)", err, strings.TrimSpace(string(out)))
	} else {
		Log.Printf("TUN: IPv6 address %s/128 assigned to %s", TUNIPv6Addr, iface)
	}

	b.running = true
	return nil
}

// Stop tears down the gVisor netstack and releases the utun interface.
func (b *TUNBridge) Stop() {
	if b.running {
		Log.Println("TUN: stopping")
		done := make(chan struct{})
		go func() { engine.Stop(); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			Log.Println("TUN: engine.Stop() timeout — continuing")
		}
		b.running = false
		b.ifaceName = ""
		Log.Println("TUN: stopped")
	}
}

// listUtunInterfaces returns the set of utunN interface names currently visible
// in the OS via "ifconfig -l".
func listUtunInterfaces() map[string]bool {
	out, err := exec.Command("ifconfig", "-l").Output()
	if err != nil {
		return nil
	}
	result := make(map[string]bool)
	for _, iface := range strings.Fields(string(out)) {
		if strings.HasPrefix(iface, "utun") {
			result[iface] = true
		}
	}
	return result
}

// findNewUtun returns the first interface that appears in after but not in before.
func findNewUtun(before, after map[string]bool) string {
	for iface := range after {
		if !before[iface] {
			return iface
		}
	}
	return ""
}

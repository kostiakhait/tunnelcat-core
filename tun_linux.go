// Copyright (c) 2026 Konstantin Khait

//go:build linux

package core

import (
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/xjasonlyu/tun2socks/v2/engine"
)

const (
	TUNDeviceName = "snc0"
	TUNMTU        = 1500
	TUNAddr       = "198.18.0.1"
	TUNMask       = "255.255.0.0"
	TUNIPv6Addr   = "fd00::2"
)

// hiddenCmd is a no-op wrapper on Linux (no hidden-window flag needed).
func hiddenCmd(name string, args ...string) *exec.Cmd {
	return exec.Command(name, args...)
}

// safeEngineStart wraps engine.Start() recovering any panic.
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

// TUNBridge bridges a Linux TUN interface to a local SOCKS5 server via
// tun2socks / gVisor netstack. All IP traffic entering snc0 is transparently
// proxied through the SOCKS5 server.
type TUNBridge struct {
	socksAddr string
	running   bool
	ifaceName string
}

// NewTUNBridge returns a bridge that will forward TUN traffic to socksAddr.
func NewTUNBridge(socksAddr string) *TUNBridge {
	return &TUNBridge{socksAddr: socksAddr}
}

// IfaceName returns the TUN interface name after a successful Start.
func (b *TUNBridge) IfaceName() string { return b.ifaceName }

// Start creates the snc0 TUN interface and launches the gVisor netstack.
// Retries up to 3 times with back-off.
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

	// tun2socks on Linux creates /dev/net/tun device with the given name.
	engine.Insert(&engine.Key{
		Device:   "tun://snc0",
		Proxy:    "socks5://" + b.socksAddr,
		MTU:      TUNMTU,
		LogLevel: "debug",
	})
	if err := safeEngineStart(); err != nil {
		return fmt.Errorf("engine start: %w", err)
	}

	// Give the kernel a moment to register the new interface.
	time.Sleep(300 * time.Millisecond)

	// Assign the TUN address and bring the interface up.
	if out, err := exec.Command("ip", "addr", "add",
		TUNAddr+"/16", "dev", TUNDeviceName).CombinedOutput(); err != nil {
		safeEngineStop()
		return fmt.Errorf("configure TUN IP: %w (ip: %s)", err, strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("ip", "link", "set", TUNDeviceName, "up").CombinedOutput(); err != nil {
		safeEngineStop()
		return fmt.Errorf("bring up TUN: %w (ip: %s)", err, strings.TrimSpace(string(out)))
	}

	// Cap MTU to 1280.
	if out, err := exec.Command("ip", "link", "set", TUNDeviceName, "mtu", "1280").CombinedOutput(); err != nil {
		Log.Printf("TUN: WARN set MTU: %v (%s)", err, strings.TrimSpace(string(out)))
	} else {
		Log.Printf("TUN: MTU set to 1280 on %s", TUNDeviceName)
	}

	// Assign ULA IPv6 address.
	if out, err := exec.Command("ip", "-6", "addr", "add",
		TUNIPv6Addr+"/128", "dev", TUNDeviceName).CombinedOutput(); err != nil {
		Log.Printf("TUN: WARN assign IPv6: %v (%s)", err, strings.TrimSpace(string(out)))
	} else {
		Log.Printf("TUN: IPv6 address %s/128 assigned to %s", TUNIPv6Addr, TUNDeviceName)
	}

	b.ifaceName = TUNDeviceName
	b.running = true
	Log.Printf("TUN: interface %s configured at %s", TUNDeviceName, TUNAddr)
	return nil
}

// Stop tears down the gVisor netstack and brings down the TUN interface.
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
		exec.Command("ip", "link", "set", TUNDeviceName, "down").Run() //nolint:errcheck
		b.running = false
		b.ifaceName = ""
		Log.Println("TUN: stopped")
	}
}

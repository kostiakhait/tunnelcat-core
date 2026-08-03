// Copyright (c) 2026 Konstantin Khait

//go:build windows

package core

import (
	"fmt"
	"os/exec"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/kostiakhait/tunnelcat-core/internal/wintun"
	"github.com/xjasonlyu/tun2socks/v2/engine"
	gowintun "golang.zx2c4.com/wintun"
)

// tunPNPSettleDelay is how long we wait after closing a wintun adapter before
// creating a new one. Windows PnP processes device removals asynchronously; if
// we call CreateAdapter while the previous removal is still in flight we get
// "Timed out waiting for device query" and the process crashes.
// 25 s gives comfortable headroom; 15 s proved insufficient in practice.
const tunPNPSettleDelay = 25 * time.Second

// lastTUNStopNano stores the UnixNano time of the most recent TUNBridge.Stop()
// call. Accessed via atomic load/store (stored as int64 via unsafe).
var lastTUNStopNano int64

func hiddenCmd(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x08000000} // CREATE_NO_WINDOW
	return cmd
}

const (
	TUNDeviceName = "TunnelCatCore"
	TUNMTU        = 1500
	TUNAddr       = "198.18.0.1"
	TUNMask       = "255.255.0.0"
	TUNIPv6Addr   = "fd00::2" // ULA address assigned to the TUN adapter; split routes cover ::/0
)

// safeEngineStart wraps engine.Start() so that the zap Fatal panic
// (tun2socks debug mode uses WriteThenPanic instead of os.Exit) is caught
// and returned as a Go error rather than killing the process.
func safeEngineStart() (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%v", r)
		}
	}()
	engine.Start()
	return nil
}

// safeEngineStop wraps engine.Stop() with panic recovery. Called between
// retry attempts so that any partial engine state (goroutines, descriptors)
// left by a failed engine.Start() is cleaned up before the next attempt.
func safeEngineStop() {
	defer func() {
		if r := recover(); r != nil {
			Log.Printf("TUN: engine.Stop() panic (recovered): %v", r)
		}
	}()
	engine.Stop()
}

// TUNBridge bridges the WinTun network interface to a local SOCKS5 server
// using tun2socks / gVisor netstack. All IP traffic entering the TUN device
// is transparently proxied through the SOCKS5 server.
type TUNBridge struct {
	socksAddr string
	running   bool
}

// NewTUNBridge returns a bridge that will forward TUN traffic to socksAddr (host:port).
func NewTUNBridge(socksAddr string) *TUNBridge {
	return &TUNBridge{socksAddr: socksAddr}
}

// Start creates the WinTun interface and launches the gVisor netstack.
// It then assigns TUNAddr/TUNMask to the interface via netsh.
// Requires administrator privileges (WinTun driver).
// Retries up to 3 times with a short back-off because the WinTun driver
// occasionally fails on first attempt (driver store settling, prior adapter
// not yet released, etc.).
func (b *TUNBridge) Start() error {
	// Extract wintun.dll next to the executable.
	if err := wintun.Extract(); err != nil {
		return fmt.Errorf("wintun DLL: %w", err)
	}

	// Remove orphaned adapters from previous crashed sessions before creating
	// a new one — prevents "adapter already exists" failures and stale interfaces.
	cleanupOrphanedAdapters()

	// Wait for Windows PnP to finish processing the previous adapter removal.
	// CreateAdapter fails with "Timed out waiting for device query" if called
	// while PnP is still removing the old device (problem code 0x1F / STATUS_PNP_REBOOT_REQUIRED).
	if t := atomic.LoadInt64(&lastTUNStopNano); t != 0 {
		elapsed := time.Since(time.Unix(0, t))
		if elapsed < tunPNPSettleDelay {
			wait := tunPNPSettleDelay - elapsed
			Log.Printf("TUN: waiting %v for Windows PnP to settle after last adapter close", wait.Round(time.Millisecond))
			time.Sleep(wait)
		}
	}

	// Pre-flight: verify the wintun driver can create an adapter before we
	// call engine.Start(), which spawns goroutines that cannot be recovered.
	// On the first launch after a system boot the driver may need up to 15 s
	// to initialise; this check surfaces that as a normal error (not a crash).
	if err := wintunPreflightCheck(); err != nil {
		Log.Printf("TUN: driver preflight failed: %v — aborting to avoid unrecoverable crash", err)
		return fmt.Errorf("wintun driver not ready: %w", err)
	}
	// Preflight creates and removes _snc_preflight; Windows PnP processes that
	// removal asynchronously. Without a brief pause the very next CreateAdapter
	// call races the in-flight PnP work and times out (problem code 0x1F).
	time.Sleep(2 * time.Second)

	const maxAttempts = 3
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		lastErr = b.startOnce()
		if lastErr == nil {
			return nil
		}
		Log.Printf("TUN: start attempt %d/%d failed: %v", attempt, maxAttempts, lastErr)
		if attempt < maxAttempts {
			// Shut down any partial engine state (goroutines, descriptors) left
			// by the failed attempt before retrying. Use a recovering wrapper
			// because engine.Stop() can itself panic on partially-initialised state.
			safeEngineStop()
			time.Sleep(time.Duration(attempt) * 3 * time.Second)
		}
	}
	return lastErr
}

func (b *TUNBridge) startOnce() error {
	Log.Printf("TUN: starting bridge → SOCKS5 %s", b.socksAddr)

	engine.Insert(&engine.Key{
		Device: "tun://" + TUNDeviceName,
		Proxy:  "socks5://" + b.socksAddr,
		MTU:    TUNMTU,
		// "debug" makes tun2socks use zap.NewDevelopment(), which panics on
		// Fatal instead of calling os.Exit(1) — safeEngineStart() can then
		// recover() and return the error rather than killing the process.
		LogLevel: "debug",
	})
	if err := safeEngineStart(); err != nil {
		return fmt.Errorf("engine start: %w", err)
	}

	// Assign a static IP to the TUN interface so the OS can route into it.
	cmd := hiddenCmd("netsh", "interface", "ip", "set", "address",
		"name="+TUNDeviceName, "source=static",
		"address="+TUNAddr, "mask="+TUNMask, "gateway=none")
	if out, err := cmd.CombinedOutput(); err != nil {
		// "The object already exists" means Windows has already restored the IP from
		// WinTUN's registry-backed adapter GUID (persistent across sessions).
		// The address is 198.18.0.1 — same value we would have set — so accept it.
		if strings.Contains(string(out), "already exists") || strings.Contains(string(out), "уже существует") {
			Log.Printf("TUN: IP already configured on %s (accepted)", TUNDeviceName)
		} else {
			engine.Stop()
			return fmt.Errorf("configure TUN IP: %w (netsh: %s)", err, out)
		}
	}
	Log.Printf("TUN: interface %s configured at %s/%s", TUNDeviceName, TUNAddr, TUNMask)

	// Set MTU explicitly — tun2socks/wintun ignores the engine.Key MTU field and
	// defaults to 65535, which causes large TCP segments to exceed the physical
	// NIC MTU (1500) once tunnel headers are added.  1280 leaves enough headroom
	// for IP+TCP+HTTP framing on any underlying link.
	if out, err := hiddenCmd("netsh", "interface", "ipv4", "set", "subinterface",
		TUNDeviceName, "mtu=1280", "store=active").CombinedOutput(); err != nil {
		Log.Printf("TUN: WARN set MTU: %v (netsh: %s)", err, out)
	} else {
		Log.Printf("TUN: MTU set to 1280 on %s", TUNDeviceName)
	}

	// Assign a static IPv6 address to the TUN adapter so that all IPv6 traffic
	// is routed through the tunnel (matches Android addAddress("fd00::2", 128)).
	if out, err := hiddenCmd("netsh", "interface", "ipv6", "add", "address",
		TUNDeviceName, TUNIPv6Addr+"/128", "store=active").CombinedOutput(); err != nil {
		Log.Printf("TUN: WARN assign IPv6 address: %v (netsh: %s)", err, out)
	} else {
		Log.Printf("TUN: IPv6 address %s/128 assigned to %s", TUNIPv6Addr, TUNDeviceName)
	}

	b.running = true
	return nil
}

// knownOrphanAdapters lists WinTun adapter names left by crashed/older
// sessions that Windows never removes automatically.
var knownOrphanAdapters = []string{
	TUNDeviceName,
	"_snc_preflight",
	"tun2socks Tunnel",
	"Wintun Userspace Tunnel",
}

// wintunPreflightCheck creates and immediately destroys a dummy adapter to
// verify the WinTun kernel driver is loaded and ready before engine.Start()
// launches goroutines that we cannot recover() from.  Runs in a goroutine with
// a 12-second timeout; if wintun is not ready we return an error so the caller
// can retry without reaching engine.Start().
func wintunPreflightCheck() error {
	type res struct {
		a   *gowintun.Adapter
		err error
	}
	ch := make(chan res, 1)
	go func() {
		a, err := gowintun.CreateAdapter("_snc_preflight", "WireGuard", nil)
		ch <- res{a, err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			return r.err
		}
		if err := r.a.Close(); err != nil {
			Log.Printf("TUN: preflight: close test adapter: %v", err)
		}
		return nil
	case <-time.After(12 * time.Second):
		return fmt.Errorf("device query timed out — wintun driver not ready")
	}
}

// cleanupOrphanedAdapters opens and deletes each known orphan adapter name.
// Must be called after wintun.Extract() so the DLL is already in place.
func cleanupOrphanedAdapters() {
	for _, name := range knownOrphanAdapters {
		a, err := gowintun.OpenAdapter(name)
		if err != nil {
			continue // not present — normal case
		}
		if err := a.Close(); err != nil {
			Log.Printf("TUN: cleanup orphan %q: %v", name, err)
		} else {
			Log.Printf("TUN: removed orphaned adapter %q", name)
		}
	}
}

// Stop tears down the gVisor netstack and releases the WinTun interface.
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
		// Explicitly delete the adapter after engine stop so it does not linger
		// as an orphan if the process later crashes before the next startup cleanup.
		if a, err := gowintun.OpenAdapter(TUNDeviceName); err == nil {
			if err := a.Close(); err != nil {
				Log.Printf("TUN: stop: delete adapter %q: %v", TUNDeviceName, err)
			} else {
				Log.Printf("TUN: adapter %q deleted on stop", TUNDeviceName)
			}
		}
		// Record stop time AFTER adapter deletion so the PnP settle timer in
		// the next Start() measures from when removal actually completed, not
		// from when engine.Stop() returned.
		atomic.StoreInt64(&lastTUNStopNano, time.Now().UnixNano())
	}
}

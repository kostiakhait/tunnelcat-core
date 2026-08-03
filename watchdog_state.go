// Copyright (c) 2026 Konstantin Khait

package core

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// WatchdogState is persisted on disk so the watchdog process can clean up
// networking state after an unclean main-process exit (crash, hard reboot, kill).
type WatchdogState struct {
	Connected     bool   `json:"connected"`
	OrigGW        string `json:"orig_gw,omitempty"`
	MainPID       int    `json:"main_pid,omitempty"`
	LastAlive     int64  `json:"last_alive,omitempty"`     // Unix seconds; written periodically by main
	LastWake      int64  `json:"last_wake,omitempty"`      // Unix seconds; written by main on each system wake
	TunnelHealthy bool   `json:"tunnel_healthy,omitempty"` // true when tunnel is up and not recovering
}

var wdStateMu sync.Mutex

// WatchdogStatePath returns the path to the watchdog state file.
func WatchdogStatePath() string {
	return filepath.Join(os.Getenv("APPDATA"), "TunnelCatCore", "watchdog-state.json")
}

// WriteWatchdogState persists the current watchdog state to disk.
func WriteWatchdogState(s WatchdogState) error {
	wdStateMu.Lock()
	defer wdStateMu.Unlock()
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	p := WatchdogStatePath()
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		return err
	}
	return os.WriteFile(p, data, 0600)
}

// ReadWatchdogState reads the persisted state.
// Returns a zero-value WatchdogState if the file is absent or unreadable.
func ReadWatchdogState() WatchdogState {
	wdStateMu.Lock()
	defer wdStateMu.Unlock()
	data, err := os.ReadFile(WatchdogStatePath())
	if err != nil {
		return WatchdogState{}
	}
	var s WatchdogState
	json.Unmarshal(data, &s) //nolint:errcheck
	return s
}

// TouchAlive updates the LastAlive timestamp in the persisted watchdog state.
// Call periodically from the main process so the watchdog can detect hangs.
func TouchAlive() {
	wdStateMu.Lock()
	defer wdStateMu.Unlock()
	data, _ := os.ReadFile(WatchdogStatePath())
	var s WatchdogState
	json.Unmarshal(data, &s) //nolint:errcheck
	s.LastAlive = time.Now().Unix()
	if b, err := json.Marshal(s); err == nil {
		os.WriteFile(WatchdogStatePath(), b, 0600) //nolint:errcheck
	}
}

// TouchLastWake updates the LastWake timestamp so the watchdog can suppress
// connectivity probes during the network-recovery window after system resume.
func TouchLastWake() {
	wdStateMu.Lock()
	defer wdStateMu.Unlock()
	data, _ := os.ReadFile(WatchdogStatePath())
	var s WatchdogState
	json.Unmarshal(data, &s) //nolint:errcheck
	s.LastWake = time.Now().Unix()
	if b, err := json.Marshal(s); err == nil {
		os.WriteFile(WatchdogStatePath(), b, 0600) //nolint:errcheck
	}
}

// SetTunnelHealthy updates only the TunnelHealthy flag in the persisted state.
// Call with true when the tunnel pool is up and not recovering; false when
// entering any recovery path (data-fail, silent refresh, reconnect).
func SetTunnelHealthy(healthy bool) {
	wdStateMu.Lock()
	defer wdStateMu.Unlock()
	data, _ := os.ReadFile(WatchdogStatePath())
	var s WatchdogState
	json.Unmarshal(data, &s) //nolint:errcheck
	s.TunnelHealthy = healthy
	if b, err := json.Marshal(s); err == nil {
		os.WriteFile(WatchdogStatePath(), b, 0600) //nolint:errcheck
	}
}

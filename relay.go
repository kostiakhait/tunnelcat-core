// Copyright (c) 2026 Konstantin Khait

package core

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// newRelayAPIHTTPClient returns an http.Client that connects to control:443
// with a uTLS handshake encoding ChRelayAPI in the Session ID so the control
// routes the connection to the relay API handler instead of the TCP proxy.
// HTTP/1.1 only — the relay API server (serveRelayAPI) is h1; using h2.Transport
// causes "frame too large" because it sends H2 frames regardless of what the
// server negotiated in ALPN.
func newRelayAPIHTTPClient() *http.Client {
	return newUTLSH1Client()
}

// FetchMyIP asks the control server what IP it sees for this connection.
// Uses a randomly chosen relay-API SNI so control routes the request to the
// relay API handler (not the TCP proxy to exit).
// apiURL must be the control's HTTPS base URL (e.g. "https://1.2.3.4:443").
func FetchMyIP(apiURL string) (string, error) {
	client := newUTLSH1Client()
	resp, err := client.Get(strings.TrimRight(apiURL, "/") + "/p/v1/myip")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var result struct {
		IP string `json:"ip"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("parse myip response: %w", err)
	}
	if result.IP == "" {
		return "", fmt.Errorf("empty IP in response")
	}
	return result.IP, nil
}

// FetchRelayList fetches the current relay list from the control's relay API.
// Expects format version 2: {"version":2,"relays":[{"id","address","country","expires_at"}]}.
// Old-format responses (version<2 or missing version) are rejected so stale clients
// that don't understand TTL/country filtering cannot accidentally propagate zombies.
func FetchRelayList(apiURL string) ([]RelayEntry, error) {
	client := newUTLSH1Client()
	Log.Printf("relay: GET %s/p/v1/relay/list", apiURL)
	resp, err := client.Get(strings.TrimRight(apiURL, "/") + "/p/v1/relay/list")
	if err != nil {
		Log.Printf("relay: GET failed: %v", err)
		return nil, err
	}
	Log.Printf("relay: GET status=%d", resp.StatusCode)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	Log.Printf("relay: body len=%d", len(body))

	var result struct {
		Version int          `json:"version"`
		Relays  []RelayEntry `json:"relays"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		Log.Printf("relay: unmarshal failed: %v", err)
		return nil, err
	}
	Log.Printf("relay: parsed version=%d relays=%d", result.Version, len(result.Relays))
	if result.Version < 2 {
		return nil, fmt.Errorf("relay list: unsupported version %d (need ≥2)", result.Version)
	}
	now := time.Now().Unix()
	out := result.Relays[:0]
	for _, e := range result.Relays {
		if e.NodeID != "" && e.Addr != "" && e.ExpiresAt > now {
			out = append(out, e)
		}
	}
	return out, nil
}

// RelayEntry is a single entry from the relay list (format version 2).
type RelayEntry struct {
	NodeID      string `json:"id"`
	Addr        string `json:"address"`
	CountryCode string `json:"country,omitempty"`
	ExpiresAt   int64  `json:"expires_at"` // unix timestamp; 0 = unknown
}

// SaveRelayList persists relays to path as JSON so they survive restarts.
func SaveRelayList(path string, relays []RelayEntry) error {
	data, err := json.Marshal(relays)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// LoadRelayList reads a relay list saved by SaveRelayList.
// Returns nil, nil when the file does not exist.
func LoadRelayList(path string) ([]RelayEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var relays []RelayEntry
	if err := json.Unmarshal(data, &relays); err != nil {
		return nil, err
	}
	return relays, nil
}

// RelaysByCountry returns a copy of relays with entries matching preferCC
// sorted first.  If preferCC is empty, the original order is preserved.
func RelaysByCountry(relays []RelayEntry, preferCC string) []RelayEntry {
	if preferCC == "" || len(relays) == 0 {
		return relays
	}
	same := make([]RelayEntry, 0, len(relays))
	other := make([]RelayEntry, 0, len(relays))
	for _, r := range relays {
		if r.CountryCode == preferCC {
			same = append(same, r)
		} else {
			other = append(other, r)
		}
	}
	return append(same, other...)
}

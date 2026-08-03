// Copyright (c) 2026 Konstantin Khait

package core

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDiscoverer_FetchUsesRelayAPIPath(t *testing.T) {
	var requestedPath string
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestedPath = r.URL.Path
		// Return a minimal valid-looking manifest (signature not checked; pubkey is nil).
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"type":"manifest","ts":1,"nodes":[{"addr":"1.2.3.4:443"}],"sig":"x"}`)) //nolint:errcheck
	}))
	defer ts.Close()

	d := &Discoverer{
		serverURLs: []string{ts.URL},
		httpClientFactory: func() *http.Client {
			return ts.Client() // accepts the test server's self-signed cert
		},
	}

	_, _ = d.fetch() // error is fine — no pubkey means sig check is skipped, nodes are parsed

	if requestedPath != "/p/v1/manifest" {
		t.Errorf("fetch() requested %q, want /p/v1/manifest", requestedPath)
	}
}

func TestDiscoverer_FetchRejectsEmptyResponse(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK) // 200, empty body
	}))
	defer ts.Close()

	d := &Discoverer{
		serverURLs:        []string{ts.URL},
		httpClientFactory: func() *http.Client { return ts.Client() },
	}

	data, err := d.fetch()
	if err == nil {
		t.Errorf("expected error for empty response, got nil (data len=%d)", len(data))
	}
}

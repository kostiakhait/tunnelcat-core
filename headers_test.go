// Copyright (c) 2026 Konstantin Khait

package core

import (
	"math/rand"
	"strings"
	"testing"
)

func TestNewSessionReturnsNonEmpty(t *testing.T) {
	s := NewSession(nil)
	if s.UA() == "" {
		t.Fatal("UA is empty")
	}
}

func TestSessionHeadersContainRequired(t *testing.T) {
	s := NewSession(rand.New(rand.NewSource(42)))
	h := s.Headers("example.com")

	required := []string{"User-Agent", "Accept", "Accept-Language", "Accept-Encoding", "Referer", "Origin"}
	for _, k := range required {
		if h[k] == "" {
			t.Errorf("missing header %q", k)
		}
	}
}

func TestSessionRefererContainsHost(t *testing.T) {
	s := NewSession(rand.New(rand.NewSource(1)))
	h := s.Headers("upload.example.com")
	if !strings.Contains(h["Referer"], "upload.example.com") {
		t.Errorf("Referer %q does not contain host", h["Referer"])
	}
}

func TestSessionUAIsStableAcrossCalls(t *testing.T) {
	s := NewSession(rand.New(rand.NewSource(99)))
	ua1 := s.UA()
	ua2 := s.UA()
	if ua1 != ua2 {
		t.Error("UA changed between calls")
	}
}

func TestDifferentSessionsDifferentUAs(t *testing.T) {
	// With 20 UAs and 100 trials we'll almost certainly get at least 2 distinct ones.
	seen := map[string]bool{}
	for i := int64(0); i < 100; i++ {
		s := NewSession(rand.New(rand.NewSource(i)))
		seen[s.UA()] = true
	}
	if len(seen) < 5 {
		t.Errorf("expected diverse UAs, got only %d distinct", len(seen))
	}
}

func TestFirefoxSessionHasFirefoxAccept(t *testing.T) {
	// Firefox Accept should NOT contain "signed-exchange" (Chrome-only).
	for seed := int64(0); seed < 1000; seed++ {
		s := NewSession(rand.New(rand.NewSource(seed)))
		if strings.Contains(s.UA(), "Firefox") {
			h := s.Headers("x.com")
			if strings.Contains(h["Accept"], "signed-exchange") {
				t.Errorf("Firefox session has Chrome-style Accept: %s", h["Accept"])
			}
			return
		}
	}
	t.Skip("no Firefox UA found in 1000 seeds")
}

func TestRandomRefererIsInPool(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	ref := RandomReferer(rng)
	found := false
	for _, r := range refererPool {
		if r == ref {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("RandomReferer returned unknown value %q", ref)
	}
}

func TestAllUAsHaveNonEmptyUA(t *testing.T) {
	for _, ua := range userAgents {
		if ua == "" {
			t.Error("empty UA in pool")
		}
	}
}

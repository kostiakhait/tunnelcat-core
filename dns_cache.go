// Copyright (c) 2026 Konstantin Khait

package core

import (
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// GlobalDNSCache maps resolved IP addresses to their FQDN so ShouldBypass can
// apply TLD-based routing overrides (e.g. .ru → always tunnel for non-RU users).
var GlobalDNSCache = &dnsCache{m: make(map[string]dnsCacheEntry)}

type dnsCache struct {
	mu       sync.RWMutex
	m        map[string]dnsCacheEntry
	initOnce sync.Once
}

type dnsCacheEntry struct {
	fqdn    string
	expires time.Time
}

func (c *dnsCache) startCleanup() {
	go func() {
		t := time.NewTicker(5 * time.Minute)
		defer t.Stop()
		for range t.C {
			now := time.Now()
			c.mu.Lock()
			for ip, e := range c.m {
				if now.After(e.expires) {
					delete(c.m, ip)
				}
			}
			c.mu.Unlock()
		}
	}()
}

// Set stores an IP→FQDN mapping, capping TTL between 5 min and 24 h.
func (c *dnsCache) Set(ip, fqdn string, ttl time.Duration) {
	c.initOnce.Do(c.startCleanup)
	if ttl < 5*time.Minute {
		ttl = 5 * time.Minute
	}
	if ttl > 24*time.Hour {
		ttl = 24 * time.Hour
	}
	c.mu.Lock()
	c.m[ip] = dnsCacheEntry{fqdn: strings.ToLower(fqdn), expires: time.Now().Add(ttl)}
	c.mu.Unlock()
}

// Get returns the FQDN for ip, or "" if not cached or expired.
func (c *dnsCache) Get(ip string) string {
	c.mu.RLock()
	e, ok := c.m[ip]
	c.mu.RUnlock()
	if !ok || time.Now().After(e.expires) {
		return ""
	}
	return e.fqdn
}

// ParseAndLearn extracts A/AAAA records from a DNS wire-format response and
// populates the cache. Silently ignores malformed messages.
func (c *dnsCache) ParseAndLearn(msg []byte) {
	var p dnsmessage.Parser
	if _, err := p.Start(msg); err != nil {
		return
	}
	if err := p.SkipAllQuestions(); err != nil {
		return
	}
	for {
		h, err := p.AnswerHeader()
		if err != nil {
			break
		}
		ttl := time.Duration(h.TTL) * time.Second
		fqdn := h.Name.String()
		switch h.Type {
		case dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				return
			}
			c.Set(net.IP(r.A[:]).String(), fqdn, ttl)
		case dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				return
			}
			c.Set(net.IP(r.AAAA[:]).String(), fqdn, ttl)
		default:
			if err := p.SkipAnswer(); err != nil {
				return
			}
		}
	}
}

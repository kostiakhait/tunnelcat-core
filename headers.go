// Copyright (c) 2026 Konstantin Khait

package core

import (
	"fmt"
	"math/rand"
)

// userAgents is a pool of realistic browser UA strings.
var userAgents = []string{
	// Chrome Windows
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
	// Chrome macOS
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
	// Chrome Linux
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	// Firefox Windows
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
	// Firefox macOS
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:125.0) Gecko/20100101 Firefox/125.0",
	// Firefox Linux
	"Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
	// Safari macOS
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
	// Safari iOS
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
	// Edge Windows
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0",
	// Chrome Android
	"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
	// Samsung Browser
	"Mozilla/5.0 (Linux; Android 14; SAMSUNG SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/24.0 Chrome/117.0.0.0 Mobile Safari/537.36",
	// Opera
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 OPR/110.0.0.0",
}

// refererPool is a list of popular sites used as realistic Referer values.
var refererPool = []string{
	"https://www.google.com/", "https://www.youtube.com/", "https://www.facebook.com/",
	"https://www.instagram.com/", "https://twitter.com/", "https://www.reddit.com/",
	"https://www.wikipedia.org/", "https://www.amazon.com/", "https://www.linkedin.com/",
	"https://www.netflix.com/", "https://www.twitch.tv/", "https://www.tiktok.com/",
	"https://www.pinterest.com/", "https://www.ebay.com/", "https://www.bing.com/",
	"https://www.yahoo.com/", "https://www.whatsapp.com/", "https://www.telegram.org/",
	"https://www.apple.com/", "https://www.microsoft.com/", "https://github.com/",
	"https://stackoverflow.com/", "https://www.nytimes.com/", "https://www.bbc.com/",
	"https://www.cnn.com/", "https://www.theguardian.com/", "https://www.forbes.com/",
	"https://www.medium.com/", "https://www.spotify.com/", "https://www.dropbox.com/",
	"https://drive.google.com/", "https://docs.google.com/", "https://mail.google.com/",
	"https://www.paypal.com/", "https://www.zoom.us/", "https://slack.com/",
	"https://www.notion.so/", "https://www.figma.com/", "https://trello.com/",
	"https://www.shopify.com/", "https://www.wordpress.com/", "https://www.wix.com/",
	"https://www.cloudflare.com/", "https://www.adobe.com/", "https://www.salesforce.com/",
	"https://www.coursera.org/", "https://www.udemy.com/", "https://www.airbnb.com/",
	"https://www.booking.com/", "https://www.aliexpress.com/",
}

// acceptHeaders maps UA family → realistic Accept / Accept-Language / Accept-Encoding.
// We key by a simple family tag derived from the UA string.
type headerSet struct {
	accept         string
	acceptLanguage string
	acceptEncoding string
	secFetchSite   string
	secFetchMode   string
	secFetchDest   string
}

var chromeHeaders = headerSet{
	accept:         "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
	acceptLanguage: "en-US,en;q=0.9",
	acceptEncoding: "gzip, deflate, br",
	secFetchSite:   "none",
	secFetchMode:   "navigate",
	secFetchDest:   "document",
}

var firefoxHeaders = headerSet{
	accept:         "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
	acceptLanguage: "en-US,en;q=0.5",
	acceptEncoding: "gzip, deflate, br",
	secFetchSite:   "none",
	secFetchMode:   "navigate",
	secFetchDest:   "document",
}

var safariHeaders = headerSet{
	accept:         "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
	acceptLanguage: "en-US,en;q=0.9",
	acceptEncoding: "gzip, deflate, br",
	secFetchSite:   "",
	secFetchMode:   "",
	secFetchDest:   "",
}

// Session holds per-session header parameters (UA, referer) fixed for
// the lifetime of one tunnel connection.
type Session struct {
	ua      string
	referer string
	hs      headerSet
}

// NewSession picks a random UA and referer and returns a Session.
func NewSession(rng *rand.Rand) *Session {
	if rng == nil {
		rng = rand.New(rand.NewSource(rand.Int63()))
	}
	ua := userAgents[rng.Intn(len(userAgents))]
	ref := refererPool[rng.Intn(len(refererPool))]
	hs := pickHeaderSet(ua)
	return &Session{ua: ua, referer: ref, hs: hs}
}

func pickHeaderSet(ua string) headerSet {
	switch {
	case containsAny(ua, "Firefox"):
		return firefoxHeaders
	case containsAny(ua, "Safari") && !containsAny(ua, "Chrome", "Chromium", "CriOS"):
		return safariHeaders
	default:
		return chromeHeaders
	}
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if len(s) >= len(sub) {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}

// Headers returns the HTTP headers for a POST upload request in this session.
// The caller must also set Content-Type and Content-Length.
func (s *Session) Headers(host string) map[string]string {
	h := map[string]string{
		"User-Agent":      s.ua,
		"Accept":          s.hs.accept,
		"Accept-Language": s.hs.acceptLanguage,
		"Accept-Encoding": s.hs.acceptEncoding,
		"Referer":         fmt.Sprintf("https://%s/", host),
		"Origin":          fmt.Sprintf("https://%s", host),
		"Connection":      "keep-alive",
	}
	if s.hs.secFetchSite != "" {
		h["Sec-Fetch-Site"] = s.hs.secFetchSite
		h["Sec-Fetch-Mode"] = s.hs.secFetchMode
		h["Sec-Fetch-Dest"] = s.hs.secFetchDest
	}
	return h
}

// RandomReferer returns a random referer from the pool (different each call).
func RandomReferer(rng *rand.Rand) string {
	if rng == nil {
		rng = rand.New(rand.NewSource(rand.Int63()))
	}
	return refererPool[rng.Intn(len(refererPool))]
}

// UA returns the User-Agent string for this session.
func (s *Session) UA() string { return s.ua }

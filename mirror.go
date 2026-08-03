// Copyright (c) 2026 Konstantin Khait

package core

// mirror.go — MirrorManager: torrent-like content mirroring.
//
// Receives the signed content manifest via DHT gossip (never polls the
// server — see the design discussion this implements), verifies it,
// downloads missing/changed files chunk-by-chunk (peer-to-peer first via a
// hole-punched MirrorConn, control relay-API as fallback when no peer has
// the chunk), writes them into a hidden per-platform data directory, and
// deletes files no longer listed in the manifest.
//
// Every chunk is verified against its SHA-256 hash from the signed manifest
// regardless of source — a peer is never trusted because of who it is, only
// because what it sent hashes correctly.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// ── Wire types ──────────────────────────────────────────────────────────────
//
// Must stay byte-identical to the server-side signing implementation's ContentFileEntry /
// SignedContentManifest for canonical-JSON signature verification — same
// convention as manifestNode/signedManifest in discovery.go mirroring the
// arbiter's NodeEntry/SignedList.

type contentFile struct {
	Path        string   `json:"path"`
	Size        int64    `json:"size"`
	ChunkSize   int      `json:"chunk_size"`
	ChunkHashes []string `json:"chunk_hashes"`
}

type signedContentManifest struct {
	Type  string        `json:"type"`
	TS    int64         `json:"ts"`
	Files []contentFile `json:"files"`
	Sig   string        `json:"sig"`
}

// MirrorManager receives the content-manifest via DHT gossip, verifies it,
// downloads missing/changed files, writes them into dataDir, and deletes
// files no longer listed.
type MirrorManager struct {
	pubkey  ed25519.PublicKey // arbiter pubkey; nil = skip verification (dev)
	dataDir string            // hidden per-platform storage dir for mirrored files

	// punchFn establishes a hole-punched, ready-to-use chunk-transfer
	// connection to peerAddr — the caller is expected to have already sent
	// the DHT mirror-punch invitation (dht.Node.SendMirrorPunch) as part of
	// this closure, mirroring how the existing tunnel-relay client role
	// combines SendHolePunch + core.Punch in each platform's main.
	punchFn func(peerAddr string) (*net.UDPConn, error)

	// completePeersFn/setContentFn/setCompleteFn are dht.Node's
	// CompletePeers/SetContent/SetContentComplete, passed as plain function
	// values so this package does not need to import dht.
	completePeersFn func(ts int64) []string
	setContentFn    func(raw []byte, ts int64)
	setCompleteFn   func(ts int64, complete bool)

	// relayFetch is the control relay-API fallback for a single chunk (GET
	// /p/v1/content/chunk?hash=...). Pass DefaultRelayChunkFetcher(discoverer)
	// unless a test needs something else.
	relayFetch func(hash string) ([]byte, error)

	mu       sync.Mutex
	ts       int64
	gen      int64               // sync generation; bumped on every accepted manifest so a stale in-flight sync can bail early
	chunkIdx map[string]chunkLoc // hash -> local file location; only populated once fully synced

	connMu    sync.Mutex
	peerConns map[string]*MirrorConn // pooled outbound chunk-fetch connections, keyed by peer addr
}

// chunkLoc locates one chunk's bytes within a local file already on disk.
type chunkLoc struct {
	path   string
	offset int64
	size   int
}

// NewMirrorManager creates a MirrorManager and ensures dataDir exists.
//
// pubkeyHex is the arbiter's Ed25519 public key in hex; pass "" to skip
// signature verification (development only).
func NewMirrorManager(
	pubkeyHex, dataDir string,
	punchFn func(peerAddr string) (*net.UDPConn, error),
	completePeersFn func(ts int64) []string,
	setContentFn func(raw []byte, ts int64),
	setCompleteFn func(ts int64, complete bool),
	relayFetch func(hash string) ([]byte, error),
) (*MirrorManager, error) {
	m := &MirrorManager{
		dataDir:         dataDir,
		punchFn:         punchFn,
		completePeersFn: completePeersFn,
		setContentFn:    setContentFn,
		setCompleteFn:   setCompleteFn,
		relayFetch:      relayFetch,
		peerConns:       make(map[string]*MirrorConn),
	}
	if pubkeyHex != "" {
		b, err := hex.DecodeString(pubkeyHex)
		if err != nil || len(b) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("mirror: invalid arbiter pubkey hex")
		}
		m.pubkey = ed25519.PublicKey(b)
	}
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, fmt.Errorf("mirror: mkdir %s: %w", dataDir, err)
	}
	return m, nil
}

func (m *MirrorManager) statePath() string { return filepath.Join(m.dataDir, ".manifest.json") }

// LoadCached loads the last successfully-applied manifest's timestamp from
// disk so a restarted process doesn't re-announce completeness for a
// version it hasn't re-verified this run (OnContentManifest still requires
// a newer ts to accept a fresh gossip, so this just prevents accidentally
// treating an old ts as "not yet seen").
func (m *MirrorManager) LoadCached() {
	data, err := os.ReadFile(m.statePath())
	if err != nil {
		Log.Printf("mirror: no cached state: %v", err)
		return
	}
	var sm signedContentManifest
	if err := json.Unmarshal(data, &sm); err != nil {
		Log.Printf("mirror: cached state corrupt, ignoring: %v", err)
		return
	}
	m.mu.Lock()
	m.ts = sm.TS
	m.mu.Unlock()
	Log.Printf("mirror: loaded cached state ts=%d (%d files)", sm.TS, len(sm.Files))
}

// Close tears down all pooled peer connections. Safe to call at shutdown.
func (m *MirrorManager) Close() {
	m.connMu.Lock()
	defer m.connMu.Unlock()
	for addr, mc := range m.peerConns {
		mc.Close()
		delete(m.peerConns, addr)
	}
}

// OnContentManifest is the callback to register with dht.Node.SetContentHandler.
// It verifies the manifest, immediately re-gossips it (so this node keeps the
// epidemic spread going even before its own download finishes — the same
// reason a torrent peer announces metadata before it finishes seeding),
// then downloads/deletes files in the background.
func (m *MirrorManager) OnContentManifest(raw []byte) {
	sm, err := m.verify(raw)
	if err != nil {
		Log.Printf("mirror: rejected manifest: %v", err)
		return
	}

	m.mu.Lock()
	if sm.TS <= m.ts {
		m.mu.Unlock()
		Log.Printf("mirror: manifest ts=%d not newer than ours=%d — drop", sm.TS, m.ts)
		return
	}
	m.ts = sm.TS
	m.gen++
	gen := m.gen
	m.mu.Unlock()

	Log.Printf("mirror: accepted manifest ts=%d (%d files) — re-gossiping and starting sync", sm.TS, len(sm.Files))
	if m.setContentFn != nil {
		m.setContentFn(raw, sm.TS)
	}
	if m.setCompleteFn != nil {
		m.setCompleteFn(sm.TS, false) // new version — completeness must be re-earned
	}

	go m.sync(raw, sm, gen)
}

// verify parses and checks the Ed25519 signature on a raw content manifest.
func (m *MirrorManager) verify(data []byte) (signedContentManifest, error) {
	var sm signedContentManifest
	if err := json.Unmarshal(data, &sm); err != nil {
		return sm, fmt.Errorf("parse: %w", err)
	}
	if sm.Type != "content" {
		return sm, fmt.Errorf("unexpected manifest type %q", sm.Type)
	}
	if m.pubkey != nil {
		payload := struct {
			Type  string        `json:"type"`
			TS    int64         `json:"ts"`
			Files []contentFile `json:"files"`
		}{Type: sm.Type, TS: sm.TS, Files: sm.Files}
		canonical, _ := json.Marshal(payload)
		sigBytes, err := base64.RawURLEncoding.DecodeString(sm.Sig)
		if err != nil || !ed25519.Verify(m.pubkey, canonical, sigBytes) {
			return sm, fmt.Errorf("signature verification failed")
		}
	} else {
		Log.Printf("mirror: WARNING — arbiter pubkey not set, skipping signature verification")
	}
	return sm, nil
}

// sync downloads every file in sm that changed since the last applied
// manifest, deletes files no longer listed, and — only if everything
// succeeded — persists state and announces completeness.
func (m *MirrorManager) sync(raw []byte, sm signedContentManifest, gen int64) {
	prevFiles := m.loadPrevFileList()

	wanted := make(map[string]contentFile, len(sm.Files))
	for _, f := range sm.Files {
		wanted[f.Path] = f
	}

	// Deletion: the manifest is the sole source of truth for what should
	// exist locally.
	for path := range prevFiles {
		if _, ok := wanted[path]; ok {
			continue
		}
		abs := filepath.Join(m.dataDir, filepath.FromSlash(path))
		if err := os.Remove(abs); err != nil && !os.IsNotExist(err) {
			Log.Printf("mirror: delete %s: %v", path, err)
		} else {
			Log.Printf("mirror: deleted %s (no longer in manifest)", path)
		}
	}

	ok := true
	for _, f := range sm.Files {
		if m.superseded(gen) {
			Log.Printf("mirror: sync ts=%d superseded — aborting", sm.TS)
			return
		}
		if prev, exists := prevFiles[f.Path]; exists && sameChunks(prev.ChunkHashes, f.ChunkHashes) {
			continue // unchanged, nothing to do
		}
		if err := m.syncFile(f, gen); err != nil {
			Log.Printf("mirror: sync %s failed: %v", f.Path, err)
			ok = false
			continue
		}
		Log.Printf("mirror: synced %s (%d bytes, %d chunks)", f.Path, f.Size, len(f.ChunkHashes))
	}

	if m.superseded(gen) {
		return
	}

	// Persist state regardless of full success — partial progress still
	// avoids re-fetching files that DID succeed on the next attempt. Only
	// announce "complete" when every file actually synced.
	if err := os.WriteFile(m.statePath(), raw, 0600); err != nil {
		Log.Printf("mirror: persist state: %v", err)
	}

	if ok {
		idx := buildChunkIndex(m.dataDir, sm.Files)
		m.mu.Lock()
		m.chunkIdx = idx
		m.mu.Unlock()
		Log.Printf("mirror: fully synced ts=%d (%d files, %d chunks indexed for serving)", sm.TS, len(sm.Files), len(idx))
		if m.setCompleteFn != nil {
			m.setCompleteFn(sm.TS, true)
		}
	} else {
		Log.Printf("mirror: sync ts=%d finished with errors — not announcing complete", sm.TS)
	}
}

// buildChunkIndex maps every chunk hash in files to its (path, offset, size)
// on disk, so ServeChunk can answer peer requests without re-scanning.
func buildChunkIndex(dataDir string, files []contentFile) map[string]chunkLoc {
	idx := make(map[string]chunkLoc)
	for _, f := range files {
		abs := filepath.Join(dataDir, filepath.FromSlash(f.Path))
		var offset int64
		for _, hash := range f.ChunkHashes {
			size := f.ChunkSize
			if remaining := f.Size - offset; remaining < int64(size) {
				size = int(remaining)
			}
			idx[hash] = chunkLoc{path: abs, offset: offset, size: size}
			offset += int64(size)
		}
	}
	return idx
}

// ServeChunk returns the bytes for hash if this node currently has it (i.e.
// is fully synced to the manifest version that included it). Wire this into
// NewMirrorConn's getChunk parameter for connections accepted via the
// platform's mirror-punch handler (SetMirrorPunchHandler) — the serving
// side, symmetric to the fetch-only connections peerConn creates.
func (m *MirrorManager) ServeChunk(hash string) ([]byte, bool) {
	m.mu.Lock()
	loc, ok := m.chunkIdx[hash]
	m.mu.Unlock()
	if !ok {
		return nil, false
	}
	f, err := os.Open(loc.path)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	if _, err := f.Seek(loc.offset, io.SeekStart); err != nil {
		return nil, false
	}
	buf := make([]byte, loc.size)
	if _, err := io.ReadFull(f, buf); err != nil {
		return nil, false
	}
	return buf, true
}

func (m *MirrorManager) superseded(gen int64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return gen != m.gen
}

func (m *MirrorManager) loadPrevFileList() map[string]contentFile {
	data, err := os.ReadFile(m.statePath())
	if err != nil {
		return nil
	}
	var sm signedContentManifest
	if err := json.Unmarshal(data, &sm); err != nil {
		return nil
	}
	out := make(map[string]contentFile, len(sm.Files))
	for _, f := range sm.Files {
		out[f.Path] = f
	}
	return out
}

func sameChunks(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// syncFile downloads every chunk of f (peer-to-peer first, relay-API
// fallback) and writes the result atomically into dataDir.
func (m *MirrorManager) syncFile(f contentFile, gen int64) error {
	abs := filepath.Join(m.dataDir, filepath.FromSlash(f.Path))
	if err := os.MkdirAll(filepath.Dir(abs), 0700); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}

	tmp := abs + ".part"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	defer os.Remove(tmp) // no-op once renamed below

	for i, hash := range f.ChunkHashes {
		if m.superseded(gen) {
			out.Close()
			return fmt.Errorf("superseded")
		}
		data, err := m.fetchChunk(hash)
		if err != nil {
			out.Close()
			return fmt.Errorf("chunk %d/%d (%.12s…): %w", i+1, len(f.ChunkHashes), hash, err)
		}
		if _, err := out.Write(data); err != nil {
			out.Close()
			return fmt.Errorf("write chunk %d: %w", i, err)
		}
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmp, abs); err != nil {
		return fmt.Errorf("rename into place: %w", err)
	}
	return nil
}

// fetchChunk tries known-complete peers (P2P, hole-punched) before falling
// back to the control relay-API. Verifies the returned bytes against hash
// regardless of source.
func (m *MirrorManager) fetchChunk(hash string) ([]byte, error) {
	for _, addr := range m.peerCandidates() {
		data, ok, err := m.fetchChunkFromPeer(addr, hash)
		if err != nil {
			Log.Printf("mirror: peer %s unreachable for chunk %.12s…: %v", addr, hash, err)
			continue
		}
		if !ok {
			Log.Printf("mirror: peer %s reports no chunk %.12s…", addr, hash)
			continue
		}
		if !chunkHashMatches(data, hash) {
			Log.Printf("mirror: peer %s sent chunk %.12s… with wrong hash — discarding, trying another source", addr, hash)
			continue
		}
		return data, nil
	}

	if m.relayFetch == nil {
		return nil, fmt.Errorf("no P2P peers and no relay fallback configured")
	}
	data, err := m.relayFetch(hash)
	if err != nil {
		return nil, fmt.Errorf("relay fallback: %w", err)
	}
	if !chunkHashMatches(data, hash) {
		return nil, fmt.Errorf("relay fallback returned chunk with wrong hash")
	}
	return data, nil
}

func chunkHashMatches(data []byte, hash string) bool {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]) == strings.ToLower(hash)
}

func (m *MirrorManager) peerCandidates() []string {
	if m.completePeersFn == nil {
		return nil
	}
	m.mu.Lock()
	ts := m.ts
	m.mu.Unlock()
	return m.completePeersFn(ts)
}

// fetchChunkFromPeer reuses a pooled MirrorConn for addr when one already
// exists (hole-punching is expensive — up to PunchTimeout per attempt — so
// it must not be redone per chunk), and drops it on failure so the next
// attempt re-punches instead of retrying a dead connection forever.
func (m *MirrorManager) fetchChunkFromPeer(addr, hash string) ([]byte, bool, error) {
	mc, err := m.peerConn(addr)
	if err != nil {
		return nil, false, err
	}
	data, ok, err := mc.RequestChunk(hash)
	if err != nil {
		m.connMu.Lock()
		if m.peerConns[addr] == mc {
			delete(m.peerConns, addr)
		}
		m.connMu.Unlock()
		mc.Close()
	}
	return data, ok, err
}

func (m *MirrorManager) peerConn(addr string) (*MirrorConn, error) {
	m.connMu.Lock()
	if mc, ok := m.peerConns[addr]; ok {
		m.connMu.Unlock()
		return mc, nil
	}
	m.connMu.Unlock()

	if m.punchFn == nil {
		return nil, fmt.Errorf("no punch function configured")
	}
	conn, err := m.punchFn(addr)
	if err != nil {
		return nil, err
	}
	// getChunk=nil: this is a fetch-only connection. Serving chunks TO peers
	// that punch to US is a separate, symmetric connection created by the
	// platform main's mirror-punch handler (SetMirrorPunchHandler).
	mc := NewMirrorConn(conn, nil)

	m.connMu.Lock()
	if existing, ok := m.peerConns[addr]; ok {
		// Lost a race with a concurrent fetch to the same peer — keep the
		// existing connection, discard ours.
		m.connMu.Unlock()
		mc.Close()
		return existing, nil
	}
	m.peerConns[addr] = mc
	m.connMu.Unlock()
	return mc, nil
}

// ── Relay-API fallback helper ──────────────────────────────────────────────

// DefaultRelayChunkFetcher returns a MirrorManager relayFetch function that
// asks a random known control (from d's current control list) for a chunk
// over the relay API (/p/v1/content/chunk) — the fallback path used only
// when no P2P peer has the chunk.
func DefaultRelayChunkFetcher(d *Discoverer) func(hash string) ([]byte, error) {
	return func(hash string) ([]byte, error) {
		controls := d.Controls()
		if len(controls) == 0 {
			return nil, fmt.Errorf("mirror: no known controls for chunk fallback")
		}
		rand.Shuffle(len(controls), func(i, j int) { controls[i], controls[j] = controls[j], controls[i] })

		var lastErr error
		for _, addr := range controls {
			url := addr
			if !strings.HasPrefix(url, "http") {
				url = "https://" + url
			}
			url += "/p/v1/content/chunk?hash=" + hash

			data, err := func() ([]byte, error) {
				client := NewRelayAPIH1Client()
				req, err := http.NewRequest(http.MethodGet, url, nil)
				if err != nil {
					return nil, err
				}
				resp, err := client.Do(req)
				if err != nil {
					return nil, err
				}
				defer resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
				}
				return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			}()
			if err != nil {
				lastErr = err
				continue
			}
			return data, nil
		}
		return nil, fmt.Errorf("mirror: chunk fallback exhausted controls: %w", lastErr)
	}
}

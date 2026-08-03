// Copyright (c) 2026 Konstantin Khait

package core

// Tests for content-manifest verification, chunking, sync (fetch, write,
// delete), and the chunk-transfer frame codec/connection.

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func genTestSigningKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// chunkTestFile splits data into chunkSize pieces and returns the manifest
// entry plus a hash->bytes map usable as a fake chunk source.
func chunkTestFile(path string, data []byte, chunkSize int) (contentFile, map[string][]byte) {
	chunks := make(map[string][]byte)
	var hashes []string
	for off := 0; off < len(data); off += chunkSize {
		end := off + chunkSize
		if end > len(data) {
			end = len(data)
		}
		piece := data[off:end]
		sum := sha256.Sum256(piece)
		h := hex.EncodeToString(sum[:])
		chunks[h] = piece
		hashes = append(hashes, h)
	}
	return contentFile{Path: path, Size: int64(len(data)), ChunkSize: chunkSize, ChunkHashes: hashes}, chunks
}

func signTestManifest(t *testing.T, priv ed25519.PrivateKey, ts int64, files []contentFile) []byte {
	t.Helper()
	payload := struct {
		Type  string        `json:"type"`
		TS    int64         `json:"ts"`
		Files []contentFile `json:"files"`
	}{Type: "content", TS: ts, Files: files}
	canonical, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, canonical)
	out := signedContentManifest{Type: "content", TS: ts, Files: files, Sig: base64.RawURLEncoding.EncodeToString(sig)}
	raw, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// ── verify() ─────────────────────────────────────────────────────────────────

func TestMirrorVerifyAcceptsValidRejectsTampered(t *testing.T) {
	pub, priv := genTestSigningKey(t)
	dir := t.TempDir()
	m, err := NewMirrorManager(hex.EncodeToString(pub), dir, nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	f, _ := chunkTestFile("hello.txt", []byte("hello world"), 4)
	raw := signTestManifest(t, priv, time.Now().Unix(), []contentFile{f})

	sm, err := m.verify(raw)
	if err != nil {
		t.Fatalf("verify valid manifest: %v", err)
	}
	if sm.TS == 0 || len(sm.Files) != 1 {
		t.Fatalf("unexpected parsed manifest: %+v", sm)
	}

	// Tamper with the path without re-signing — same byte length so this
	// isn't accidentally caught by a length check, only by the signature.
	tampered := []byte(strings.Replace(string(raw), "hello.txt", "hellO.txt", 1))
	if _, err := m.verify(tampered); err == nil {
		t.Fatal("expected signature verification failure for tampered manifest")
	}

	// Wrong type must be rejected even with a valid signature.
	badType := signTestManifestWithType(t, priv, time.Now().Unix(), []contentFile{f}, "not-content")
	if _, err := m.verify(badType); err == nil {
		t.Fatal("expected rejection for wrong manifest type")
	}
}

func signTestManifestWithType(t *testing.T, priv ed25519.PrivateKey, ts int64, files []contentFile, typ string) []byte {
	t.Helper()
	payload := struct {
		Type  string        `json:"type"`
		TS    int64         `json:"ts"`
		Files []contentFile `json:"files"`
	}{Type: typ, TS: ts, Files: files}
	canonical, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, canonical)
	out := signedContentManifest{Type: typ, TS: ts, Files: files, Sig: base64.RawURLEncoding.EncodeToString(sig)}
	raw, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// ── sync(): fetch, write, delete ────────────────────────────────────────────

func TestMirrorSyncFetchesWritesAndDeletes(t *testing.T) {
	pub, priv := genTestSigningKey(t)
	dir := t.TempDir()

	var chunkMu sync.Mutex
	chunkStore := make(map[string][]byte)
	relayFetch := func(hash string) ([]byte, error) {
		chunkMu.Lock()
		defer chunkMu.Unlock()
		data, ok := chunkStore[hash]
		if !ok {
			return nil, fmt.Errorf("no such chunk")
		}
		return data, nil
	}

	completeCh := make(chan int64, 4)
	m, err := NewMirrorManager(
		hex.EncodeToString(pub), dir,
		nil, // no P2P peers — every chunk fetch falls through to relayFetch
		func(ts int64) []string { return nil },
		func(raw []byte, ts int64) {}, // ignore re-gossip
		func(ts int64, complete bool) {
			if complete {
				completeCh <- ts
			}
		},
		relayFetch,
	)
	if err != nil {
		t.Fatal(err)
	}

	// ── v1: one file ────────────────────────────────────────────────────────
	content := []byte("the quick brown fox jumps over the lazy dog")
	f, chunks := chunkTestFile("docs/fox.txt", content, 8)
	chunkMu.Lock()
	for h, b := range chunks {
		chunkStore[h] = b
	}
	chunkMu.Unlock()

	ts1 := time.Now().Unix()
	m.OnContentManifest(signTestManifest(t, priv, ts1, []contentFile{f}))

	select {
	case gotTS := <-completeCh:
		if gotTS != ts1 {
			t.Fatalf("complete ts=%d want=%d", gotTS, ts1)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for sync to complete")
	}

	got, err := os.ReadFile(filepath.Join(dir, "docs", "fox.txt"))
	if err != nil {
		t.Fatalf("read synced file: %v", err)
	}
	if string(got) != string(content) {
		t.Fatalf("synced content = %q, want %q", got, content)
	}

	// ServeChunk should now answer requests for chunks we just synced —
	// proves buildChunkIndex ran and located them correctly on disk.
	for h, want := range chunks {
		gotChunk, ok := m.ServeChunk(h)
		if !ok {
			t.Fatalf("ServeChunk(%s): not found after sync", h)
		}
		if string(gotChunk) != string(want) {
			t.Fatalf("ServeChunk(%s) = %q, want %q", h, gotChunk, want)
		}
	}

	// ── v2: file removed from manifest — must be deleted locally ─────────────
	ts2 := ts1 + 1
	m.OnContentManifest(signTestManifest(t, priv, ts2, nil))

	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(dir, "docs", "fox.txt")); os.IsNotExist(err) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("file was not deleted after removal from manifest")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// A chunk whose bytes don't hash to what the manifest promised must never be
// accepted, regardless of source — this is the whole trust model (verify
// content, not the sender).
func TestMirrorSyncRejectsWrongHashChunk(t *testing.T) {
	pub, priv := genTestSigningKey(t)
	dir := t.TempDir()

	relayFetch := func(hash string) ([]byte, error) {
		return []byte("not the right bytes at all"), nil // never matches any real hash
	}

	m, err := NewMirrorManager(
		hex.EncodeToString(pub), dir,
		nil,
		func(ts int64) []string { return nil },
		func(raw []byte, ts int64) {},
		func(ts int64, complete bool) {
			if complete {
				t.Error("must not announce complete when chunk hashes don't match")
			}
		},
		relayFetch,
	)
	if err != nil {
		t.Fatal(err)
	}

	f, _ := chunkTestFile("bad.txt", []byte("hello world"), 4)
	m.OnContentManifest(signTestManifest(t, priv, time.Now().Unix(), []contentFile{f}))

	// Give the background sync a moment to run and confirm it does NOT
	// write the file (since no source ever returns a hash-matching chunk).
	time.Sleep(500 * time.Millisecond)
	if _, err := os.Stat(filepath.Join(dir, "bad.txt")); err == nil {
		t.Fatal("file was written despite no chunk ever matching its hash")
	}
}

// ── frame codec ──────────────────────────────────────────────────────────────

func TestMirrorFrameCodecRoundTrip(t *testing.T) {
	var hash [32]byte
	for i := range hash {
		hash[i] = byte(i)
	}
	req := mirrorEncodeRequest(42, hash)
	gotHash, ok := mirrorDecodeRequest(req)
	if !ok || gotHash != hash {
		t.Fatalf("request round-trip failed: ok=%v hash=%x want=%x", ok, gotHash, hash)
	}

	body := []byte("chunk bytes here")
	found := mirrorEncodeFound(42, body)
	gotBody, ok := mirrorDecodeFound(found)
	if !ok || string(gotBody) != string(body) {
		t.Fatalf("found round-trip failed: ok=%v body=%q want=%q", ok, gotBody, body)
	}

	miss := mirrorEncodeMiss(42)
	if len(miss) != 9 || miss[8] != mirrorTypeChunkMiss {
		t.Fatalf("miss encoding unexpected: %x", miss)
	}
}

// ── MirrorConn over loopback UDP ────────────────────────────────────────────

func mustFreeUDPAddr(t *testing.T) *net.UDPAddr {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	addr := conn.LocalAddr().(*net.UDPAddr)
	conn.Close()
	return addr
}

func TestMirrorConnRequestChunk(t *testing.T) {
	aAddr := mustFreeUDPAddr(t)
	bAddr := mustFreeUDPAddr(t)

	aConn, err := net.DialUDP("udp4", aAddr, bAddr)
	if err != nil {
		t.Fatal(err)
	}
	bConn, err := net.DialUDP("udp4", bAddr, aAddr)
	if err != nil {
		t.Fatal(err)
	}

	chunkData := []byte("chunk-payload")
	sum := sha256.Sum256(chunkData)
	hash := hex.EncodeToString(sum[:])

	server := NewMirrorConn(bConn, func(h string) ([]byte, bool) {
		if h == hash {
			return chunkData, true
		}
		return nil, false
	})
	defer server.Close()

	client := NewMirrorConn(aConn, nil)
	defer client.Close()

	data, ok, err := client.RequestChunk(hash)
	if err != nil {
		t.Fatalf("RequestChunk: %v", err)
	}
	if !ok {
		t.Fatal("expected a hit")
	}
	if string(data) != string(chunkData) {
		t.Fatalf("got %q want %q", data, chunkData)
	}

	missSum := sha256.Sum256([]byte("no such chunk"))
	_, ok, err = client.RequestChunk(hex.EncodeToString(missSum[:]))
	if err != nil {
		t.Fatalf("RequestChunk (miss case): %v", err)
	}
	if ok {
		t.Fatal("expected a miss, got a hit")
	}
}

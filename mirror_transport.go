// Copyright (c) 2026 Konstantin Khait

package core

// mirror_transport.go — point-to-point chunk request/response protocol for
// torrent-like content mirroring, carried over a hole-punched UDP connection
// (core.Punch). Same shape as udp_relay.go's UDPRelayConn (magic+reqID+type
// frame header, retry+backoff RoundTrip) but the payload is content-mirror
// chunk bytes, not forwarded tunnel HTTP requests — a separate connection
// serving a separate purpose, not a repurposing of UDPRelayConn.
//
// Frame layout:
//   Request:      [4B magic][4B req_id][1B=0x01][32B chunk hash]
//   Response(hit):[4B magic][4B req_id][1B=0x02][4B data_len][data]
//   Response(miss):[4B magic][4B req_id][1B=0x03]

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"math/rand"
)

const (
	mirrorMagic         = uint32(0x534E434D) // 'SNCM'
	mirrorTypeChunkReq  = byte(0x01)
	mirrorTypeChunkResp = byte(0x02)
	mirrorTypeChunkMiss = byte(0x03)
	mirrorRetries       = 3
	mirrorTimeout       = 700 * time.Millisecond
	// mirrorMaxFrame has headroom above the 16 KB chunk size the arbiter
	// uses (the server-side content-manifest chunk size) — the chunk
	// size lives server-side; this is just a receive-buffer ceiling.
	mirrorMaxFrame = 32 * 1024
	// mirrorIdleTimeout self-closes a connection nobody has used in a while —
	// unlike UDPRelayConn this has no keepalive loop (chunk transfer is a
	// finite, bursty operation, not a long-lived tunnel), so an idle timeout
	// is what actually frees the socket + goroutine instead of leaking them
	// for the lifetime of the process.
	mirrorIdleTimeout = 5 * time.Minute
)

type mirrorPendingResp struct {
	found bool
	data  []byte
}

// MirrorConn is a chunk-transfer channel over a hole-punched UDP connection.
// Create with NewMirrorConn; call Close when done.
type MirrorConn struct {
	conn *net.UDPConn

	// getChunk, if set, is consulted when a peer requests a chunk from us —
	// returns (data, true) if we have it locally. nil means we never serve
	// (fetch-only connection).
	getChunk func(hash string) (data []byte, ok bool)

	mu      sync.Mutex
	pending map[uint32]chan mirrorPendingResp
	rng     *rand.Rand

	successCount atomic.Int64 // total successful chunk fetches; for periodic "still alive" logging
	lastActivity atomic.Int64 // unix nano of the last frame sent or received; drives mirrorIdleTimeout

	once   sync.Once
	stopCh chan struct{}
}

// NewMirrorConn wraps conn as a bidirectional chunk-transfer transport.
func NewMirrorConn(conn *net.UDPConn, getChunk func(hash string) ([]byte, bool)) *MirrorConn {
	c := &MirrorConn{
		conn:     conn,
		getChunk: getChunk,
		pending:  make(map[uint32]chan mirrorPendingResp),
		rng:      rand.New(rand.NewSource(time.Now().UnixNano())),
		stopCh:   make(chan struct{}),
	}
	c.lastActivity.Store(time.Now().UnixNano())
	go c.readLoop()
	return c
}

func (c *MirrorConn) touch() { c.lastActivity.Store(time.Now().UnixNano()) }

func (c *MirrorConn) idleFor() time.Duration {
	return time.Since(time.Unix(0, c.lastActivity.Load()))
}

func (c *MirrorConn) readLoop() {
	buf := make([]byte, mirrorMaxFrame)
	for {
		c.conn.SetReadDeadline(time.Now().Add(2 * time.Second)) //nolint:errcheck
		n, err := c.conn.Read(buf)
		select {
		case <-c.stopCh:
			return
		default:
		}
		if err != nil {
			if c.idleFor() > mirrorIdleTimeout {
				Log.Printf("mirror-transport: idle for %s — closing", mirrorIdleTimeout)
				c.Close()
				return
			}
			continue
		}
		c.touch()
		data := make([]byte, n)
		copy(data, buf[:n])

		if len(data) < 9 || binary.BigEndian.Uint32(data) != mirrorMagic {
			Log.Printf("mirror-transport: dropped malformed frame (%d bytes)", n)
			continue
		}
		reqID := binary.BigEndian.Uint32(data[4:])
		typ := data[8]

		switch typ {
		case mirrorTypeChunkReq:
			hash, ok := mirrorDecodeRequest(data)
			if !ok {
				continue
			}
			go c.serveChunkRequest(reqID, hash)

		case mirrorTypeChunkResp:
			body, ok := mirrorDecodeFound(data)
			if !ok {
				continue
			}
			c.deliver(reqID, mirrorPendingResp{found: true, data: body})

		case mirrorTypeChunkMiss:
			c.deliver(reqID, mirrorPendingResp{found: false})

		default:
			Log.Printf("mirror-transport: unknown frame type=0x%02x reqID=%d", typ, reqID)
		}
	}
}

func (c *MirrorConn) deliver(reqID uint32, resp mirrorPendingResp) {
	c.mu.Lock()
	ch := c.pending[reqID]
	c.mu.Unlock()
	if ch != nil {
		select {
		case ch <- resp:
		default:
		}
	}
}

func (c *MirrorConn) serveChunkRequest(reqID uint32, hash [32]byte) {
	hexHash := hex.EncodeToString(hash[:])
	if c.getChunk == nil {
		c.conn.Write(mirrorEncodeMiss(reqID)) //nolint:errcheck
		return
	}
	data, ok := c.getChunk(hexHash)
	if !ok {
		c.conn.Write(mirrorEncodeMiss(reqID)) //nolint:errcheck
		return
	}
	if _, err := c.conn.Write(mirrorEncodeFound(reqID, data)); err != nil {
		Log.Printf("mirror-transport: send chunk hash=%.12s…: %v", hexHash, err)
	}
}

// RequestChunk fetches one chunk (hex SHA-256 hash) from the peer this
// connection is punched to.
//
// Returns (data, true, nil) on a hit, (nil, false, nil) if the peer
// explicitly reported it doesn't have the chunk (caller should try a
// different peer, not retry this one), or a non-nil error if the peer never
// responded at all (caller should treat the peer as unreachable).
func (c *MirrorConn) RequestChunk(hash string) ([]byte, bool, error) {
	hashBytes, err := hex.DecodeString(hash)
	if err != nil || len(hashBytes) != 32 {
		return nil, false, fmt.Errorf("mirror-transport: bad hash %q", hash)
	}
	var hashArr [32]byte
	copy(hashArr[:], hashBytes)

	c.mu.Lock()
	var reqID uint32
	for {
		reqID = c.rng.Uint32()
		if _, exists := c.pending[reqID]; !exists {
			break
		}
	}
	ch := make(chan mirrorPendingResp, 1)
	c.pending[reqID] = ch
	c.mu.Unlock()

	defer func() {
		c.mu.Lock()
		delete(c.pending, reqID)
		c.mu.Unlock()
	}()

	frame := mirrorEncodeRequest(reqID, hashArr)
	for attempt := 0; attempt < mirrorRetries; attempt++ {
		if _, err := c.conn.Write(frame); err != nil {
			return nil, false, fmt.Errorf("mirror-transport write: %w", err)
		}
		// Exponential backoff, same shape as UDPRelayConn.RoundTrip.
		timeout := mirrorTimeout << uint(attempt)
		select {
		case resp := <-ch:
			if resp.found {
				if n := c.successCount.Add(1); n == 1 || n%100 == 0 {
					Log.Printf("mirror-transport: chunk fetch ok hash=%.12s… success_count=%d", hash, n)
				}
				return resp.data, true, nil
			}
			Log.Printf("mirror-transport: peer reports miss for hash=%.12s…", hash)
			return nil, false, nil
		case <-time.After(timeout):
			Log.Printf("mirror-transport: timeout attempt=%d/%d hash=%.12s… timeout=%s", attempt+1, mirrorRetries, hash, timeout)
		case <-c.stopCh:
			return nil, false, fmt.Errorf("mirror-transport: closed")
		}
	}
	return nil, false, fmt.Errorf("mirror-transport: %d retries exhausted for hash=%.12s…", mirrorRetries, hash)
}

// StopCh returns a channel that is closed when the connection is shut down.
func (c *MirrorConn) StopCh() <-chan struct{} { return c.stopCh }

// Close tears down the connection.
func (c *MirrorConn) Close() {
	c.once.Do(func() {
		close(c.stopCh)
		c.conn.Close()
	})
}

// ── Frame codec ───────────────────────────────────────────────────────────────

func mirrorEncodeRequest(reqID uint32, hash [32]byte) []byte {
	buf := make([]byte, 4+4+1+32)
	o := 0
	binary.BigEndian.PutUint32(buf[o:], mirrorMagic)
	o += 4
	binary.BigEndian.PutUint32(buf[o:], reqID)
	o += 4
	buf[o] = mirrorTypeChunkReq
	o++
	copy(buf[o:], hash[:])
	return buf
}

func mirrorDecodeRequest(data []byte) (hash [32]byte, ok bool) {
	if len(data) < 4+4+1+32 {
		return
	}
	copy(hash[:], data[9:9+32])
	ok = true
	return
}

func mirrorEncodeFound(reqID uint32, data []byte) []byte {
	buf := make([]byte, 4+4+1+4+len(data))
	o := 0
	binary.BigEndian.PutUint32(buf[o:], mirrorMagic)
	o += 4
	binary.BigEndian.PutUint32(buf[o:], reqID)
	o += 4
	buf[o] = mirrorTypeChunkResp
	o++
	binary.BigEndian.PutUint32(buf[o:], uint32(len(data)))
	o += 4
	copy(buf[o:], data)
	return buf
}

func mirrorDecodeFound(data []byte) (body []byte, ok bool) {
	if len(data) < 4+4+1+4 {
		return
	}
	o := 9
	n := int(binary.BigEndian.Uint32(data[o:]))
	o += 4
	if n < 0 || o+n > len(data) {
		return
	}
	return data[o : o+n], true
}

func mirrorEncodeMiss(reqID uint32) []byte {
	buf := make([]byte, 4+4+1)
	binary.BigEndian.PutUint32(buf[0:], mirrorMagic)
	binary.BigEndian.PutUint32(buf[4:], reqID)
	buf[8] = mirrorTypeChunkMiss
	return buf
}

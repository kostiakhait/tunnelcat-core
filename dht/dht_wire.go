// Copyright (c) 2026 Konstantin Khait

package dht

// dht_wire.go — encrypted framing for DHT UDP messages.
//
// Every DHT datagram is a ChaCha20-Poly1305 ciphertext.  There is no
// recognisable protocol header; packets look like random noise to DPI.
//
// Wire layout:
//   [12B nonce][ciphertext + 16B AEAD tag]
//
// Plaintext layout:
//   [1B msg_type][1B ttl][1B pad_len][pad_len random bytes][N bytes JSON payload]
//
// pad_len is 0–15 (low 4 bits of a random byte).  Random padding eliminates
// fixed-size fingerprinting.
//
// Key: blake2b-256("snc-dht-v1") — deterministic, shared by all nodes.
// dhtKey is NOT a security secret — its purpose is DPI obfuscation only.

import (
	"crypto/rand"
	"encoding/json"
	"fmt"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	NonceSize = 12
	MaxTTL    = 8 // max hops a DHT message may traverse
)

var key = func() []byte {
	h, _ := blake2b.New256(nil)
	h.Write([]byte("snc-dht-v1"))
	return h.Sum(nil)
}()

// Seal encodes msgType + ttl + payload (as JSON) and returns an encrypted datagram.
// Pass ttl=0 to use MaxTTL (originating a new message).
func Seal(msgType byte, ttl uint8, payload interface{}) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("dht-wire: aead: %w", err)
	}

	if ttl == 0 {
		ttl = MaxTTL
	}

	var body []byte
	if payload != nil {
		body, err = json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("dht-wire: marshal: %w", err)
		}
	}

	var padByte [1]byte
	if _, err := rand.Read(padByte[:]); err != nil {
		return nil, fmt.Errorf("dht-wire: pad: %w", err)
	}
	padLen := int(padByte[0] & 0x0F)

	plain := make([]byte, 3+padLen+len(body))
	plain[0] = msgType
	plain[1] = ttl
	plain[2] = byte(padLen)
	if padLen > 0 {
		if _, err := rand.Read(plain[3 : 3+padLen]); err != nil {
			return nil, fmt.Errorf("dht-wire: pad fill: %w", err)
		}
	}
	copy(plain[3+padLen:], body)

	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("dht-wire: nonce: %w", err)
	}
	return aead.Seal(nonce, nonce, plain, nil), nil
}

// Open decrypts a datagram and returns the message type, remaining TTL,
// and raw JSON payload. Returns an error if authentication fails.
// The caller must drop the message if ttl == 0.
func Open(pkt []byte) (msgType byte, ttl uint8, rawJSON []byte, err error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return 0, 0, nil, fmt.Errorf("dht-wire: aead: %w", err)
	}

	minLen := NonceSize + 3 + aead.Overhead()
	if len(pkt) < minLen {
		return 0, 0, nil, fmt.Errorf("dht-wire: packet too short (%d < %d)", len(pkt), minLen)
	}

	plain, err := aead.Open(nil, pkt[:NonceSize], pkt[NonceSize:], nil)
	if err != nil {
		return 0, 0, nil, fmt.Errorf("dht-wire: auth failed: %w", err)
	}

	padLen := int(plain[2])
	if 3+padLen > len(plain) {
		return 0, 0, nil, fmt.Errorf("dht-wire: invalid pad_len %d", padLen)
	}
	return plain[0], plain[1], plain[3+padLen:], nil
}

// ── Typed message structs ─────────────────────────────────────────────────────

type FindNodePayload struct {
	From   ContactJSON `json:"from"`
	Target string      `json:"target"`
}

type NodesPayload struct {
	From  ContactJSON   `json:"from,omitempty"` // responder's own ID+addr; added to sender's routing table
	Nodes []ContactJSON `json:"nodes"`
}

type AnnouncePayload struct {
	Entry RelayEntry `json:"entry"`
}

type RelayListPayload struct {
	Entries []RelayEntry `json:"entries"`
}

type ManifestHavePayload struct {
	TS int64 `json:"ts"`
}

type ManifestPayload struct {
	TS  int64           `json:"ts"`
	Raw json.RawMessage `json:"raw"`
}

// HolePunchPayload is the body of MsgHolePunch when used as a punch invitation.
// The sender tells the recipient its external UDP address AND which control URL
// the relay should forward tunnel traffic to.
type HolePunchPayload struct {
	Peer    string `json:"peer"`              // sender's external UDP endpoint (ip:port)
	Control string `json:"control,omitempty"` // control URL relay should forward to (e.g. "https://1.2.3.4:443")
}

// ContentHavePayload is gossiped every announce tick to advertise the sender's
// known content-manifest version. Complete additionally tells the recipient
// whether the sender has fully downloaded+verified all chunks for that
// version — recipients use this to pick chunk-fetch candidates, entirely as
// a side effect of the same gossip that discovers manifest updates.
type ContentHavePayload struct {
	TS       int64 `json:"ts"`
	Complete bool  `json:"complete"`
}

// ContentPayload carries the full signed content manifest (file list +
// per-chunk hashes), same shape as ManifestPayload but on its own gossip
// channel — content-manifest churn (files added/removed) is unrelated to
// control-manifest churn (control nodes added/removed).
type ContentPayload struct {
	TS  int64           `json:"ts"`
	Raw json.RawMessage `json:"raw"`
}

// MirrorPunchPayload is the body of MsgMirrorPunch: a hole-punch invitation
// for content-chunk transfer, parallel to HolePunchPayload but without a
// Control field — chunk fetching has no forwarding target, just two peers
// exchanging chunk bytes directly.
type MirrorPunchPayload struct {
	Peer string `json:"peer"` // sender's external UDP endpoint (ip:port)
}

// Copyright (c) 2026 Konstantin Khait

package core

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kostiakhait/tunnelcat-core/dht"
)

// nodeKey is the loaded Ed25519 keypair for this node instance.
// Set by LoadOrGenNodeID; used by SignNodePayload.
var nodeKey struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

// LoadOrGenNodeID returns the persistent node ID for this client.
// NodeID = hex-encoded Ed25519 public key (64 hex chars / 32 bytes).
//
// The private key is stored encrypted (platform-specific) in appDataDir/nodeid.key.
// The public key is stored as plain hex in appDataDir/nodeid.
func LoadOrGenNodeID(appDataDir string) (string, error) {
	pubPath := filepath.Join(appDataDir, "nodeid")
	keyPath := filepath.Join(appDataDir, "nodeid.key")

	if pubHex, err := os.ReadFile(pubPath); err == nil {
		id := strings.TrimSpace(string(pubHex))
		if len(id) == hex.EncodedLen(ed25519.PublicKeySize) {
			if encPriv, err2 := os.ReadFile(keyPath); err2 == nil {
				if privBytes, err3 := nodeIDDecrypt(encPriv); err3 == nil {
					if len(privBytes) == ed25519.PrivateKeySize {
						nodeKey.priv = privBytes
						pubBytes, _ := hex.DecodeString(id)
						nodeKey.pub = pubBytes
						return id, nil
					}
				}
			}
		}
		// Old 32-char random-hex format or corrupt key → regenerate.
	}

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return "", fmt.Errorf("nodeid: generate: %w", err)
	}
	if err := os.MkdirAll(appDataDir, 0700); err != nil {
		return "", err
	}
	id := hex.EncodeToString(pub)
	if err := os.WriteFile(pubPath, []byte(id), 0600); err != nil {
		return "", fmt.Errorf("nodeid: write pubkey: %w", err)
	}
	encPriv, err := nodeIDEncrypt(priv)
	if err != nil {
		return "", fmt.Errorf("nodeid: encrypt privkey: %w", err)
	}
	if err := os.WriteFile(keyPath, encPriv, 0600); err != nil {
		return "", fmt.Errorf("nodeid: write privkey: %w", err)
	}
	nodeKey.pub = pub
	nodeKey.priv = priv
	Log.Printf("nodeid: generated new Ed25519 node identity id=%.16s…", id)
	return id, nil
}

// SignNodePayload signs payload with the node's Ed25519 private key and returns
// the raw 64-byte signature. LoadOrGenNodeID must have been called first.
func SignNodePayload(payload []byte) ([]byte, error) {
	if nodeKey.priv == nil {
		return nil, fmt.Errorf("nodeid: key not loaded; call LoadOrGenNodeID first")
	}
	return ed25519.Sign(nodeKey.priv, payload), nil
}

// BuildSignedRelayEntry creates a signed dht.RelayEntry for this node.
// addr is the external UDP endpoint (ip:port) from ProbeExternalEndpoint.
// LoadOrGenNodeID must have been called first.
func BuildSignedRelayEntry(nodeID, addr, countryCode string) (*dht.RelayEntry, error) {
	entry := &dht.RelayEntry{
		NodeID:      nodeID,
		Addr:        addr,
		CountryCode: countryCode,
		TS:          time.Now().Unix(),
	}
	sig, err := SignNodePayload(dht.RelayEntryPayload(entry))
	if err != nil {
		return nil, err
	}
	entry.Sig = base64.RawURLEncoding.EncodeToString(sig)
	return entry, nil
}

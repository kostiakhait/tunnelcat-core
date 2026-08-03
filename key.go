// Copyright (c) 2026 Konstantin Khait

package core

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
)

// VerifySignedPayload verifies an Ed25519 signature over payload.
//
// pubkeyHex is the signer's public key, hex-encoded. sigB64 is the
// signature, base64url-encoded (no padding). This is the primitive used
// throughout the package (discovery, bypass, mirror) to authenticate
// manifest data signed by a control-plane server — callers are responsible
// for building the exact canonical payload their own signing scheme uses.
func VerifySignedPayload(payload []byte, pubkeyHex, sigB64 string) error {
	if pubkeyHex == "" {
		return errors.New("verify: empty pubkey")
	}
	pubBytes, err := hex.DecodeString(pubkeyHex)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return errors.New("verify: invalid pubkey")
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("verify: invalid signature encoding")
	}
	if !ed25519.Verify(ed25519.PublicKey(pubBytes), payload, sig) {
		return errors.New("verify: signature verification failed")
	}
	return nil
}

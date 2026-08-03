// Copyright (c) 2026 Konstantin Khait

package core

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func encodeHex(b []byte) string {
	const hextable = "0123456789abcdef"
	dst := make([]byte, len(b)*2)
	for i, v := range b {
		dst[i*2] = hextable[v>>4]
		dst[i*2+1] = hextable[v&0x0f]
	}
	return string(dst)
}

func TestVerifySignedPayloadRoundtrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	payload := []byte(`{"control_nodes":["ctrl1.example.com:443"]}`)
	sig := ed25519.Sign(priv, payload)
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	if err := VerifySignedPayload(payload, encodeHex(pub), sigB64); err != nil {
		t.Fatalf("expected valid signature to verify, got: %v", err)
	}
}

func TestVerifySignedPayloadRejectsTampering(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	payload := []byte(`{"control_nodes":["ctrl1.example.com:443"]}`)
	sig := ed25519.Sign(priv, payload)
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	tampered := append([]byte(nil), payload...)
	tampered[0] ^= 0xFF

	if err := VerifySignedPayload(tampered, encodeHex(pub), sigB64); err == nil {
		t.Error("expected error for tampered payload")
	}
}

func TestVerifySignedPayloadRejectsWrongPubkey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	wrongPub, _, _ := ed25519.GenerateKey(rand.Reader)
	payload := []byte(`{"control_nodes":["ctrl1.example.com:443"]}`)
	sig := ed25519.Sign(priv, payload)
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	if err := VerifySignedPayload(payload, encodeHex(wrongPub), sigB64); err == nil {
		t.Error("expected signature verification failure with wrong pubkey")
	}
}

func TestVerifySignedPayloadRejectsGarbage(t *testing.T) {
	cases := []struct{ pubkeyHex, sigB64 string }{
		{"", ""},
		{"notHex", "AAAA"},
		{encodeHex(make([]byte, ed25519.PublicKeySize)), "!!!notbase64"},
	}
	for _, c := range cases {
		if err := VerifySignedPayload([]byte("payload"), c.pubkeyHex, c.sigB64); err == nil {
			t.Errorf("expected error for pubkeyHex=%q sigB64=%q", c.pubkeyHex, c.sigB64)
		}
	}
}

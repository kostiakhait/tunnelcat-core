// Copyright (c) 2026 Konstantin Khait

package core

// dht_wire.go — package-local aliases for dht.Seal/Open/Msg* used by holepunch.go.

import "github.com/kostiakhait/tunnelcat-core/dht"

const (
	dhtMsgHolePunch = dht.MsgHolePunch
	dhtMaxTTL       = dht.MaxTTL
)

func dhtSeal(msgType byte, ttl uint8, payload interface{}) ([]byte, error) {
	return dht.Seal(msgType, ttl, payload)
}

func dhtOpen(pkt []byte) (msgType byte, ttl uint8, rawJSON []byte, err error) {
	return dht.Open(pkt)
}

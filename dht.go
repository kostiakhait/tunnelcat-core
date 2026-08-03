// Copyright (c) 2026 Konstantin Khait

package core

// Thin adapter: re-exports DHT types from the shared github.com/kostiakhait/tunnelcat-core/dht package.
// win-client adds logger injection and DPAPI-backed peers.json encryption.

import (
	"net"

	"github.com/kostiakhait/tunnelcat-core/dht"
)

// Type aliases — core.DHTID and dht.ID are the same type.
type (
	DHTID         = dht.ID
	DHTContact    = dht.Contact
	DHTRelayEntry = dht.RelayEntry
	DHTNode       = dht.Node
)

// ParseDHTID decodes a 64-char hex string into a DHTID.
func ParseDHTID(s string) (DHTID, error) { return dht.ParseID(s) }

// NewDHTNode creates a DHT node wired to the win-client logger and DPAPI encryption.
func NewDHTNode(id DHTID, conn *net.UDPConn, peersPath string) *DHTNode {
	return dht.NewNode(id, conn, peersPath, Log, nodeIDEncrypt, nodeIDDecrypt)
}

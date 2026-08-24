package transport

import (
	"crypto/sha256"
	"fmt"
	"sync"
)

// MeshPacket wraps a Palagos protocol binary packet with store-and-forward routing metadata.
//
// Mesh Routing Concept (Alice -> Bob -> Charlie -> David):
// Intermediate nodes (Bob, Charlie) act strictly as transport relays:
// 1. Relays observe only PacketID, TTL, and Recipient Fingerprint.
// 2. Relays CANNOT decrypt the payload (they lack the Double Ratchet keys).
// 3. Relays CANNOT tamper with headers (AEAD AAD verification will fail on recipient node).
// 4. Duplicate suppression: Relays store seen PacketIDs in a cache to prevent broadcast loops.
type MeshPacket struct {
	TTL          uint8    // Time-To-Live hop limit (e.g. 7 hops)
	HopCount     uint8    // Current hop count
	PacketID     [32]byte // SHA-256 fingerprint of the inner encrypted packet
	InnerPayload []byte   // Serialized Palagos protocol binary packet
}

// MeshRelay manages store-and-forward mesh packet routing cache.
type MeshRelay struct {
	mu        sync.Mutex
	seenCache map[[32]byte]bool
}

// NewMeshRelay initializes a mesh routing relay instance.
func NewMeshRelay() *MeshRelay {
	return &MeshRelay{
		seenCache: make(map[[32]byte]bool),
	}
}

// ProcessAndRelay evaluates an incoming mesh packet for forwarding.
// Returns (shouldForward, updatedPacket, error).
func (mr *MeshRelay) ProcessAndRelay(mp *MeshPacket) (bool, *MeshPacket, error) {
	mr.mu.Lock()
	defer mr.mu.Unlock()

	// Compute unique packet ID if not set
	if mp.PacketID == [32]byte{} {
		mp.PacketID = sha256.Sum256(mp.InnerPayload)
	}

	// Duplicate Suppression: Ignore packet if already seen
	if mr.seenCache[mp.PacketID] {
		return false, nil, fmt.Errorf("mesh: packet %x already processed (duplicate dropped)", mp.PacketID[:8])
	}
	mr.seenCache[mp.PacketID] = true

	// TTL check
	if mp.TTL <= 1 {
		return false, nil, fmt.Errorf("mesh: packet %x TTL expired", mp.PacketID[:8])
	}

	// Update hop metadata
	forwarded := &MeshPacket{
		TTL:          mp.TTL - 1,
		HopCount:     mp.HopCount + 1,
		PacketID:     mp.PacketID,
		InnerPayload: make([]byte, len(mp.InnerPayload)),
	}
	copy(forwarded.InnerPayload, mp.InnerPayload)

	return true, forwarded, nil
}

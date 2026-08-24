package tests

import (
	"testing"

	"palagos/pkg/protocol"
)

func FuzzPacketUnmarshal(f *testing.F) {
	// Seed corpus with valid packet
	pkt := &protocol.Packet{
		Version:            protocol.CurrentProtocolVersion,
		Type:               protocol.MessageTypeData,
		Epoch:              1,
		Sequence:           10,
		SenderFingerprint:  [32]byte{0xAA},
		RecipientFingerprint: [32]byte{0xBB},
		EphemeralPublicKey: [32]byte{0xCC},
		Nonce:              [24]byte{0xDD},
		Payload:            []byte("Fuzz Seed Ciphertext Payload"),
		Signature:          [64]byte{0xEE},
	}
	validBytes, err := pkt.Marshal()
	if err == nil {
		f.Add(validBytes)
	}

	// Add random seeds
	f.Add([]byte{})
	f.Add([]byte("short junk"))
	f.Add(make([]byte, 203)) // MinHeaderSize

	f.Fuzz(func(t *testing.T, data []byte) {
		var p protocol.Packet
		// Unmarshal must never panic or crash on malformed/arbitrary input data
		_ = p.Unmarshal(data)
	})
}

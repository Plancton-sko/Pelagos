package protocol

import (
	"encoding/binary"
	"fmt"
)

// Protocol Version
const CurrentProtocolVersion uint16 = 0x0100 // Version 1.0

// Message Types
const (
	MessageTypeHandshakeInit uint8 = 0x01
	MessageTypeHandshakeResp uint8 = 0x02
	MessageTypeData          uint8 = 0x03
	MessageTypeAck           uint8 = 0x04
	MessageTypeHeartbeat     uint8 = 0x05
)

// MinHeaderSize calculation:
// Version (2) + Type (1) + Epoch (4) + Sequence (8) + SenderFP (32) + RecipientFP (32) + EphemeralPubKey (32) + Nonce (24) + PayloadLen (4) + Signature (64) = 203 bytes
const MinHeaderSize = 2 + 1 + 4 + 8 + 32 + 32 + 32 + 24 + 4 + 64

// Packet represents the wire format of a Palagos network frame.
type Packet struct {
	Version            uint16
	Type               uint8
	Epoch              uint32
	Sequence           uint64
	SenderFingerprint  [32]byte
	RecipientFingerprint [32]byte
	EphemeralPublicKey [32]byte
	Nonce              [24]byte
	Payload            []byte
	Signature          [64]byte // Ed25519 signature over header + payload
}

// Marshal encodes the Packet into a compact binary slice (big-endian integer encoding).
func (p *Packet) Marshal() ([]byte, error) {
	if len(p.Payload) > 10*1024*1024 { // 10 MB sanity limit
		return nil, fmt.Errorf("protocol: payload size exceeds 10MB limit")
	}

	buf := make([]byte, MinHeaderSize+len(p.Payload))
	binary.BigEndian.PutUint16(buf[0:2], p.Version)
	buf[2] = p.Type
	binary.BigEndian.PutUint32(buf[3:7], p.Epoch)
	binary.BigEndian.PutUint64(buf[7:15], p.Sequence)

	copy(buf[15:47], p.SenderFingerprint[:])
	copy(buf[47:79], p.RecipientFingerprint[:])
	copy(buf[79:111], p.EphemeralPublicKey[:])
	copy(buf[111:135], p.Nonce[:])

	binary.BigEndian.PutUint32(buf[135:139], uint32(len(p.Payload)))
	copy(buf[139:139+len(p.Payload)], p.Payload)

	sigOffset := 139 + len(p.Payload)
	copy(buf[sigOffset:sigOffset+64], p.Signature[:])

	return buf, nil
}

// Unmarshal decodes a binary slice into a Packet structure.
func (p *Packet) Unmarshal(b []byte) error {
	if len(b) < MinHeaderSize {
		return fmt.Errorf("protocol: buffer size %d is smaller than minimum header size %d", len(b), MinHeaderSize)
	}

	p.Version = binary.BigEndian.Uint16(b[0:2])
	if p.Version > CurrentProtocolVersion {
		return fmt.Errorf("protocol: unsupported version 0x%04x (current version 0x%04x)", p.Version, CurrentProtocolVersion)
	}

	p.Type = b[2]
	p.Epoch = binary.BigEndian.Uint32(b[3:7])
	p.Sequence = binary.BigEndian.Uint64(b[7:15])

	copy(p.SenderFingerprint[:], b[15:47])
	copy(p.RecipientFingerprint[:], b[47:79])
	copy(p.EphemeralPublicKey[:], b[79:111])
	copy(p.Nonce[:], b[111:135])

	payloadLen := binary.BigEndian.Uint32(b[135:139])
	expectedTotal := MinHeaderSize + int(payloadLen)
	if len(b) != expectedTotal {
		return fmt.Errorf("protocol: length mismatch: expected %d bytes, got %d bytes", expectedTotal, len(b))
	}

	p.Payload = make([]byte, payloadLen)
	copy(p.Payload, b[139:139+payloadLen])

	sigOffset := 139 + payloadLen
	copy(p.Signature[:], b[sigOffset:sigOffset+64])

	return nil
}

// ComputeAAD computes the Associated Authenticated Data (AAD) block binding packet headers to the AEAD decryption.
func (p *Packet) ComputeAAD() []byte {
	aad := make([]byte, 2+1+4+8+32+32+32)
	binary.BigEndian.PutUint16(aad[0:2], p.Version)
	aad[2] = p.Type
	binary.BigEndian.PutUint32(aad[3:7], p.Epoch)
	binary.BigEndian.PutUint64(aad[7:15], p.Sequence)
	copy(aad[15:47], p.SenderFingerprint[:])
	copy(aad[47:79], p.RecipientFingerprint[:])
	copy(aad[79:111], p.EphemeralPublicKey[:])
	return aad
}

// SignedBytes returns the slice over which the Ed25519 signature is evaluated (all fields except the signature itself).
func (p *Packet) SignedBytes() []byte {
	buf := make([]byte, 139+len(p.Payload))
	binary.BigEndian.PutUint16(buf[0:2], p.Version)
	buf[2] = p.Type
	binary.BigEndian.PutUint32(buf[3:7], p.Epoch)
	binary.BigEndian.PutUint64(buf[7:15], p.Sequence)
	copy(buf[15:47], p.SenderFingerprint[:])
	copy(buf[47:79], p.RecipientFingerprint[:])
	copy(buf[79:111], p.EphemeralPublicKey[:])
	copy(buf[111:135], p.Nonce[:])
	binary.BigEndian.PutUint32(buf[135:139], uint32(len(p.Payload)))
	copy(buf[139:], p.Payload)
	return buf
}

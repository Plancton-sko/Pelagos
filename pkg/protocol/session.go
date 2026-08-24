package protocol

import (
	"crypto/ecdh"
	"fmt"
	"sync"

	"palagos/pkg/crypto"
	"palagos/pkg/identity"
)

// Session represents an active secure communication channel between two Palagos peers.
type Session struct {
	mu           sync.Mutex
	LocalId      *identity.Identity
	PeerId       *identity.PeerIdentity
	Ratchet      *crypto.Ratchet
	ReplayWin    *ReplayWindow
	OutSequence  uint64
	Epoch        uint32
	IsEstablished bool
}

// NewSession creates an unestablished session between local identity and remote peer identity.
func NewSession(localId *identity.Identity, peerId *identity.PeerIdentity) *Session {
	return &Session{
		LocalId:   localId,
		PeerId:    peerId,
		ReplayWin: NewReplayWindow(),
		Epoch:     1,
	}
}

// CreateHandshakeInit constructs the initial handshake packet sent by Alice to Bob.
//
// Security Mechanics:
// 1. Generates ephemeral X25519 keypair (e_alice, E_alice).
// 2. Signs E_alice using Alice's long-term Ed25519 identity key.
// 3. Packs E_alice + signature into the payload of HandshakeInit packet.
func (s *Session) CreateHandshakeInit() (*Packet, *ecdh.PrivateKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ephemeralPriv, ephemeralPub, err := crypto.GenerateECDHKeyPair()
	if err != nil {
		return nil, nil, err
	}

	ePubBytes := ephemeralPub.Bytes()

	// Sign the ephemeral X25519 public key with Ed25519 identity private key to prevent MITM
	sig, err := s.LocalId.Sign(ePubBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("session: failed to sign handshake key: %w", err)
	}

	payload := append(ePubBytes, sig...)

	pkt := &Packet{
		Version:            CurrentProtocolVersion,
		Type:               MessageTypeHandshakeInit,
		Epoch:              s.Epoch,
		Sequence:           1,
		SenderFingerprint:  s.LocalId.Fingerprint(),
		RecipientFingerprint: s.PeerId.Fingerprint(),
		Payload:            payload,
	}
	copy(pkt.EphemeralPublicKey[:], ePubBytes)

	// Compute signature over packet signed bytes
	pktSig, err := s.LocalId.Sign(pkt.SignedBytes())
	if err != nil {
		return nil, nil, err
	}
	copy(pkt.Signature[:], pktSig)

	return pkt, ephemeralPriv, nil
}

// ProcessHandshakeInit processes an incoming HandshakeInit from Alice and establishes Bob's session.
func (s *Session) ProcessHandshakeInit(pkt *Packet) (*Packet, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if pkt.Type != MessageTypeHandshakeInit {
		return nil, fmt.Errorf("session: expected HandshakeInit message type, got 0x%02x", pkt.Type)
	}

	// 1. Verify packet signature under peer's identity key
	if !s.PeerId.VerifySignature(pkt.SignedBytes(), pkt.Signature[:]) {
		return nil, fmt.Errorf("session: handshake packet signature verification failed")
	}

	if len(pkt.Payload) < 32+64 {
		return nil, fmt.Errorf("session: handshake init payload too short")
	}

	remoteEphemeralPubBytes := pkt.Payload[:32]
	remoteEphemeralSig := pkt.Payload[32 : 32+64]

	// 2. Verify signature over remote ephemeral X25519 public key
	if !s.PeerId.VerifySignature(remoteEphemeralPubBytes, remoteEphemeralSig) {
		return nil, fmt.Errorf("session: ephemeral key signature verification failed")
	}

	remoteEphemeralPub, err := ecdh.X25519().NewPublicKey(remoteEphemeralPubBytes)
	if err != nil {
		return nil, fmt.Errorf("session: invalid remote ephemeral key: %w", err)
	}

	// 3. Generate Bob's local ephemeral keypair
	localEphemeralPriv, localEphemeralPub, err := crypto.GenerateECDHKeyPair()
	if err != nil {
		return nil, err
	}

	// 4. Perform ECDH scalar multiplication: S = b * A
	dhShared, err := crypto.ComputeECDHSharedSecret(localEphemeralPriv, remoteEphemeralPub)
	if err != nil {
		return nil, err
	}

	// Derive 32-byte initial root secret via HKDF
	masterSecret, err := crypto.HKDFExtractExpand(dhShared, nil, "palagos-v1-handshake-master", 32)
	crypto.Zeroize(dhShared)
	if err != nil {
		return nil, err
	}

	// Initialize Double Ratchet state as Responder
	ratchet, err := crypto.NewRatchet(masterSecret, false, localEphemeralPriv, remoteEphemeralPub)
	crypto.Zeroize(masterSecret)
	if err != nil {
		return nil, err
	}
	s.Ratchet = ratchet

	// Construct HandshakeResp packet
	lPubBytes := localEphemeralPub.Bytes()
	lSig, err := s.LocalId.Sign(lPubBytes)
	if err != nil {
		return nil, err
	}

	respPayload := append(lPubBytes, lSig...)

	respPkt := &Packet{
		Version:            CurrentProtocolVersion,
		Type:               MessageTypeHandshakeResp,
		Epoch:              s.Epoch,
		Sequence:           1,
		SenderFingerprint:  s.LocalId.Fingerprint(),
		RecipientFingerprint: s.PeerId.Fingerprint(),
		Payload:            respPayload,
	}
	copy(respPkt.EphemeralPublicKey[:], lPubBytes)

	rSig, err := s.LocalId.Sign(respPkt.SignedBytes())
	if err != nil {
		return nil, err
	}
	copy(respPkt.Signature[:], rSig)

	s.IsEstablished = true
	return respPkt, nil
}

// CompleteInitiatorHandshake completes Alice's handshake when receiving Bob's HandshakeResp.
func (s *Session) CompleteInitiatorHandshake(respPkt *Packet, initiatorEphemeralPriv *ecdh.PrivateKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if respPkt.Type != MessageTypeHandshakeResp {
		return fmt.Errorf("session: expected HandshakeResp message type, got 0x%02x", respPkt.Type)
	}

	if !s.PeerId.VerifySignature(respPkt.SignedBytes(), respPkt.Signature[:]) {
		return fmt.Errorf("session: handshake response signature verification failed")
	}

	if len(respPkt.Payload) < 32+64 {
		return fmt.Errorf("session: handshake resp payload too short")
	}

	remoteEphemeralPubBytes := respPkt.Payload[:32]
	remoteEphemeralSig := respPkt.Payload[32 : 32+64]

	if !s.PeerId.VerifySignature(remoteEphemeralPubBytes, remoteEphemeralSig) {
		return fmt.Errorf("session: remote ephemeral key signature verification failed")
	}

	remoteEphemeralPub, err := ecdh.X25519().NewPublicKey(remoteEphemeralPubBytes)
	if err != nil {
		return fmt.Errorf("session: invalid remote ephemeral key: %w", err)
	}

	dhShared, err := crypto.ComputeECDHSharedSecret(initiatorEphemeralPriv, remoteEphemeralPub)
	if err != nil {
		return err
	}

	masterSecret, err := crypto.HKDFExtractExpand(dhShared, nil, "palagos-v1-handshake-master", 32)
	crypto.Zeroize(dhShared)
	if err != nil {
		return err
	}

	ratchet, err := crypto.NewRatchet(masterSecret, true, initiatorEphemeralPriv, remoteEphemeralPub)
	crypto.Zeroize(masterSecret)
	if err != nil {
		return err
	}

	s.Ratchet = ratchet
	s.IsEstablished = true
	return nil
}

// EncryptMessage encrypts application data using the Double Ratchet and constructs a binary Packet.
func (s *Session) EncryptMessage(plaintext []byte) (*Packet, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.IsEstablished || s.Ratchet == nil {
		return nil, fmt.Errorf("session: cannot encrypt message on unestablished session")
	}

	s.OutSequence++

	pkt := &Packet{
		Version:            CurrentProtocolVersion,
		Type:               MessageTypeData,
		Epoch:              s.Epoch,
		Sequence:           s.OutSequence,
		SenderFingerprint:  s.LocalId.Fingerprint(),
		RecipientFingerprint: s.PeerId.Fingerprint(),
	}

	ePubBytes, ciphertext, _, err := s.Ratchet.RatchetEncrypt(plaintext, nil, func(ePub []byte) []byte {
		copy(pkt.EphemeralPublicKey[:], ePub)
		return pkt.ComputeAAD()
	})
	if err != nil {
		return nil, fmt.Errorf("session: ratchet encryption failed: %w", err)
	}

	copy(pkt.EphemeralPublicKey[:], ePubBytes)
	copy(pkt.Nonce[:], ciphertext[:24])
	pkt.Payload = ciphertext[24:]

	sig, err := s.LocalId.Sign(pkt.SignedBytes())
	if err != nil {
		return nil, err
	}
	copy(pkt.Signature[:], sig)

	return pkt, nil
}

// DecryptMessage verifies replay protection, packet signatures, AAD, AEAD tags, and decrypts the payload.
func (s *Session) DecryptMessage(pkt *Packet) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.IsEstablished || s.Ratchet == nil {
		return nil, fmt.Errorf("session: cannot decrypt message on unestablished session")
	}

	// 1. Verify replay window
	if err := s.ReplayWin.VerifyReplayWindow(pkt.Sequence); err != nil {
		return nil, err
	}

	// 2. Verify identity signature over header + payload
	if !s.PeerId.VerifySignature(pkt.SignedBytes(), pkt.Signature[:]) {
		return nil, fmt.Errorf("session: packet identity signature verification failed")
	}

	// Reconstruct nonce + payload slice for RatchetDecrypt
	fullCiphertext := append(pkt.Nonce[:], pkt.Payload...)
	aad := pkt.ComputeAAD()

	plaintext, err := s.Ratchet.RatchetDecrypt(pkt.EphemeralPublicKey[:], fullCiphertext, aad, 0)
	if err != nil {
		return nil, fmt.Errorf("session: ratchet decryption failed: %w", err)
	}

	return plaintext, nil
}

package identity

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"palagos/pkg/crypto"
)

// Identity represents a Palagos device's cryptographic identity.
//
// Role in System:
// 1. Long-term Authentication: Each physical device generates one long-term Ed25519 signing key.
// 2. Peer Identity Verification: Users verify peer identities out-of-band (e.g. scanning QR codes in person).
// 3. Handshake Signature: During key agreement, peers sign their ephemeral X25519 keys with their Ed25519 identity key
//    to prevent Man-in-the-Middle (MITM) attacks.
type Identity struct {
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
}

// GenerateIdentity creates a new long-term cryptographic identity keypair.
func GenerateIdentity() (*Identity, error) {
	pub, priv, err := crypto.GenerateEd25519KeyPair()
	if err != nil {
		return nil, fmt.Errorf("identity: failed to generate keypair: %w", err)
	}
	return &Identity{
		PrivateKey: priv,
		PublicKey:  pub,
	}, nil
}

// Fingerprint returns the SHA-256 hash (32 bytes) of the public key.
func (id *Identity) Fingerprint() [32]byte {
	return sha256.Sum256(id.PublicKey)
}

// FormattedFingerprint returns a colon-separated hex string for human/visual verification.
// Example: "A1:B2:C3:D4:..."
func (id *Identity) FormattedFingerprint() string {
	fp := id.Fingerprint()
	hexStr := strings.ToUpper(hex.EncodeToString(fp[:]))
	var parts []string
	for i := 0; i < len(hexStr); i += 2 {
		parts = append(parts, hexStr[i:i+2])
	}
	return strings.Join(parts, ":")
}

// Sign signs data using the long-term private identity key.
func (id *Identity) Sign(message []byte) ([]byte, error) {
	return crypto.SignMessage(id.PrivateKey, message)
}

// PeerIdentity represents a remote peer's public identity after out-of-band or protocol exchange.
type PeerIdentity struct {
	PublicKey ed25519.PublicKey
	Alias     string
}

// NewPeerIdentity creates a verified PeerIdentity from raw public key bytes.
func NewPeerIdentity(pubBytes []byte, alias string) (*PeerIdentity, error) {
	if len(pubBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("identity: invalid peer public key size %d, expected %d", len(pubBytes), ed25519.PublicKeySize)
	}
	pubCopy := make(ed25519.PublicKey, ed25519.PublicKeySize)
	copy(pubCopy, pubBytes)
	return &PeerIdentity{
		PublicKey: pubCopy,
		Alias:     alias,
	}, nil
}

// Fingerprint computes the SHA-256 fingerprint for a PeerIdentity.
func (p *PeerIdentity) Fingerprint() [32]byte {
	return sha256.Sum256(p.PublicKey)
}

// FormattedFingerprint returns a colon-separated hex string for human/visual verification.
func (p *PeerIdentity) FormattedFingerprint() string {
	fp := p.Fingerprint()
	hexStr := strings.ToUpper(hex.EncodeToString(fp[:]))
	var parts []string
	for i := 0; i < len(hexStr); i += 2 {
		parts = append(parts, hexStr[i:i+2])
	}
	return strings.Join(parts, ":")
}

// VerifySignature checks a signature against the peer's long-term public identity key.
func (p *PeerIdentity) VerifySignature(message, signature []byte) bool {
	return crypto.VerifySignature(p.PublicKey, message, signature)
}


package identity

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"

	"palagos/pkg/crypto"

	"golang.org/x/crypto/hkdf"
)

const (
	PairingDomainInfo = "palagos-v1-pin-pairing"
	SASDomainInfo     = "palagos-v1-sas-code"
)

// PairingPayload encapsulates the encrypted identity payload sent over an insecure
// out-of-band channel (e.g. Bluetooth BLE, local network broadcast, or NFC).
type PairingPayload struct {
	Salt       [16]byte // 16-byte random salt for PIN derivation
	Nonce      [12]byte // 12-byte ChaCha20-Poly1305 nonce
	Ciphertext []byte   // Encrypted payload containing (Ed25519 PublicKey || Alias)
}

// CreatePairingPayload encrypts the local user's Ed25519 Public Key and Alias using a user-agreed PIN.
//
// Cryptographic Process:
// 1. Generate 16-byte random salt and 12-byte random nonce using CSPRNG.
// 2. Derive 256-bit symmetric key: K_pin = HKDF-SHA256(secret=PIN, salt=Salt, info="palagos-v1-pin-pairing").
// 3. Encrypt (PublicKey || AliasBytes) using ChaCha20-Poly1305(key=K_pin, nonce=Nonce, aad=Salt).
func CreatePairingPayload(localId *Identity, alias string, pin string) (*PairingPayload, error) {
	if len(pin) < 4 {
		return nil, fmt.Errorf("pairing: PIN must be at least 4 characters long")
	}

	saltBytes, err := crypto.SecureRandom(16)
	if err != nil {
		return nil, fmt.Errorf("pairing: salt generation failed: %w", err)
	}

	nonceBytes, err := crypto.SecureRandom(12)
	if err != nil {
		return nil, fmt.Errorf("pairing: nonce generation failed: %w", err)
	}

	// 1. Derive symmetric key from PIN + Salt using HKDF
	pairingKey, err := derivePairingKey(pin, saltBytes)
	if err != nil {
		return nil, err
	}
	defer crypto.Zeroize(pairingKey)

	// 2. Pack plaintext: 32 bytes Public Key + Alias
	plaintext := append(localId.PublicKey, []byte(alias)...)

	// 3. Encrypt via ChaCha20-Poly1305 (key, nonce, plaintext, additionalData)
	ciphertext, err := crypto.EncryptAEAD(pairingKey, nonceBytes, plaintext, saltBytes)
	if err != nil {
		return nil, fmt.Errorf("pairing: encryption failed: %w", err)
	}

	payload := &PairingPayload{
		Ciphertext: ciphertext,
	}
	copy(payload.Salt[:], saltBytes)
	copy(payload.Nonce[:], nonceBytes)

	return payload, nil
}

// OpenPairingPayload decrypts a PairingPayload using the input PIN.
// On success, returns the extracted PeerIdentity and a 6-digit Short Authentication String (SAS)
// to visually confirm presential pairing correctness without camera access.
func OpenPairingPayload(payload *PairingPayload, localId *Identity, pin string) (*PeerIdentity, string, error) {
	if payload == nil {
		return nil, "", fmt.Errorf("pairing: nil payload")
	}

	pairingKey, err := derivePairingKey(pin, payload.Salt[:])
	if err != nil {
		return nil, "", err
	}
	defer crypto.Zeroize(pairingKey)

	// Decrypt payload (key, nonce, ciphertext, additionalData)
	plaintext, err := crypto.DecryptAEAD(pairingKey, payload.Nonce[:], payload.Ciphertext, payload.Salt[:])
	if err != nil {
		return nil, "", fmt.Errorf("pairing: incorrect PIN or corrupted payload (authentication failed)")
	}

	if len(plaintext) < 32 {
		return nil, "", fmt.Errorf("pairing: invalid payload length %d", len(plaintext))
	}

	peerPubBytes := plaintext[:32]
	alias := string(plaintext[32:])

	peerId, err := NewPeerIdentity(peerPubBytes, alias)
	if err != nil {
		return nil, "", err
	}

	// Calculate 6-digit Short Authentication String (SAS) based on this payload's salt & key
	sasCode, err := generateSAS(pairingKey, localId.PublicKey, peerPubBytes, payload.Salt[:])
	if err != nil {
		return nil, "", err
	}

	return peerId, sasCode, nil
}

// GenerateSAS calculates the 6-digit SAS code for an offer payload created by the local user.
func (p *PairingPayload) GenerateSAS(localId *Identity, peerPub []byte, pin string) (string, error) {
	pairingKey, err := derivePairingKey(pin, p.Salt[:])
	if err != nil {
		return "", err
	}
	defer crypto.Zeroize(pairingKey)

	return generateSAS(pairingKey, localId.PublicKey, peerPub, p.Salt[:])
}

// derivePairingKey derives a 256-bit symmetric key from a PIN string and Salt using HKDF-SHA256.
func derivePairingKey(pin string, salt []byte) ([]byte, error) {
	kdf := hkdf.New(sha256.New, []byte(pin), salt, []byte(PairingDomainInfo))
	key := make([]byte, 32)
	if _, err := io.ReadFull(kdf, key); err != nil {
		return nil, fmt.Errorf("pairing: HKDF key derivation failed: %w", err)
	}
	return key, nil
}

// generateSAS produces a deterministic, symmetric 6-digit SAS verification code (e.g. "482-901").
// Both devices will compute the EXACT same SAS code regardless of order by sorting public keys.
func generateSAS(pairingKey []byte, localPub []byte, peerPub []byte, salt []byte) (string, error) {
	var first, second []byte
	if bytes.Compare(localPub, peerPub) < 0 {
		first, second = localPub, peerPub
	} else {
		first, second = peerPub, localPub
	}

	ikm := append(append(pairingKey, first...), second...)
	kdf := hkdf.New(sha256.New, ikm, salt, []byte(SASDomainInfo))
	digest := make([]byte, 4)
	if _, err := io.ReadFull(kdf, digest); err != nil {
		return "", fmt.Errorf("pairing: SAS generation failed: %w", err)
	}

	// Convert 4 bytes to uint32 integer modulo 1,000,000 for a 6-digit number
	val := (uint32(digest[0])<<24 | uint32(digest[1])<<16 | uint32(digest[2])<<8 | uint32(digest[3])) % 1000000
	sasStr := fmt.Sprintf("%06d", val)
	return fmt.Sprintf("%s-%s", sasStr[:3], sasStr[3:]), nil
}

// Marshal serializes a PairingPayload into bytes for network/Bluetooth transmission.
func (p *PairingPayload) Marshal() []byte {
	buf := new(bytes.Buffer)
	buf.Write(p.Salt[:])
	buf.Write(p.Nonce[:])
	buf.Write(p.Ciphertext)
	return buf.Bytes()
}

// UnmarshalPairingPayload parses raw bytes into a PairingPayload structure.
func UnmarshalPairingPayload(data []byte) (*PairingPayload, error) {
	if len(data) < 28 { // 16 salt + 12 nonce = 28 bytes minimum header
		return nil, fmt.Errorf("pairing: payload data too short")
	}

	p := &PairingPayload{}
	copy(p.Salt[:], data[0:16])
	copy(p.Nonce[:], data[16:28])
	p.Ciphertext = make([]byte, len(data)-28)
	copy(p.Ciphertext, data[28:])

	return p, nil
}

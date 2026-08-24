package crypto

import (
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// NonceSizeXChaCha20Poly1305 defines 192-bit (24-byte) nonces for XChaCha20-Poly1305.
const NonceSizeXChaCha20Poly1305 = chacha20poly1305.NonceSizeX

// EncryptAEAD encrypts plaintext using ChaCha20-Poly1305 (or XChaCha20-Poly1305 if nonce is 24 bytes)
// and authenticates both the ciphertext and Additional Authenticated Data (AAD).
//
// Cryptographic Architecture of ChaCha20-Poly1305 (RFC 8439):
// 1. ChaCha20 Stream Cipher: Generates a pseudorandom keystream by running 20 rounds of quarter-round operations
//    over a 4x4 matrix of 32-bit words (4 constants, 8 key words, 2 counter words, 2 nonce words).
// 2. Poly1305 Authenticator: Evaluates a polynomial mod (2^130 - 5) using a 256-bit one-time key generated from
//    ChaCha20 block 0.
//
// Why AEAD is Required (Encryption Alone is Insufficient):
// Unauthenticated symmetric encryption (like raw AES-CTR or AES-CBC without MAC) provides confidentiality
// but ZERO integrity. An active attacker can modify bits in transit (bit-flipping attacks) or construct oracle attacks.
// AEAD guarantees that if any byte of the ciphertext OR Associated Data is modified, decryption immediately rejects
// the packet with an error before exposing unauthenticated plaintext to the application.
//
// Role of Nonce:
// The nonce (Number used ONCE) must NEVER be repeated under the same key.
// - Nonce Reuse Impact: Poly1305 one-time key reuse allows an attacker to calculate the Poly1305 key 'r' and forge
//   valid MAC tags for arbitrary ciphertexts. ChaCha20 keystream reuse yields C1 ^ C2 = P1 ^ P2, leaking plaintext.
func EncryptAEAD(key, nonce, plaintext, additionalData []byte) ([]byte, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("aead: invalid key size %d, expected %d", len(key), chacha20poly1305.KeySize)
	}

	aead, err := createAEAD(key, len(nonce))
	if err != nil {
		return nil, err
	}

	// Seals plaintext and appends the 16-byte Poly1305 authentication tag.
	ciphertext := aead.Seal(nil, nonce, plaintext, additionalData)
	return ciphertext, nil
}

// DecryptAEAD verifies the Poly1305 authentication tag against the ciphertext and Additional Authenticated Data (AAD),
// and decrypts the ciphertext if authentic.
//
// Failure Modes:
// If any of the following occur, DecryptAEAD returns a tag verification error:
// 1. Ciphertext bit flipped by adversary.
// 2. Nonce corrupted or modified.
// 3. Associated Data (e.g. sequence number, version, sender ID) modified.
// 4. Wrong message key supplied.
func DecryptAEAD(key, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("aead: invalid key size %d, expected %d", len(key), chacha20poly1305.KeySize)
	}

	aead, err := createAEAD(key, len(nonce))
	if err != nil {
		return nil, err
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, fmt.Errorf("aead: authentication tag verification failed (ciphertext or AAD modified): %w", err)
	}
	return plaintext, nil
}

func createAEAD(key []byte, nonceLen int) (cipherAEAD chacha20poly1305AEAD, err error) {
	if nonceLen == chacha20poly1305.NonceSizeX {
		return chacha20poly1305.NewX(key)
	} else if nonceLen == chacha20poly1305.NonceSize {
		return chacha20poly1305.New(key)
	}
	return nil, fmt.Errorf("aead: unsupported nonce length %d (must be %d or %d)", nonceLen, chacha20poly1305.NonceSize, chacha20poly1305.NonceSizeX)
}

type chacha20poly1305AEAD interface {
	Seal(dst, nonce, plaintext, additionalData []byte) []byte
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
}

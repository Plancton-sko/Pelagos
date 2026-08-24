package crypto

import (
	"crypto/ecdh"
	"fmt"
)

// GenerateECDHKeyPair generates a fresh X25519 private/public keypair using crypto/ecdh.
//
// Mathematical Foundation:
// Curve25519 is a Montgomery curve defined over the prime field GF(2^255 - 19) by the equation:
//
//	y^2 = x^3 + 486662 * x^2 + x  (mod 2^255 - 19)
//
// Key Generation process:
// 1. A 32-byte secret scalar 'a' is drawn from the system CSPRNG (crypto/rand).
// 2. The scalar is clamped (bits cleared/set for cofactor and subgroup safety).
// 3. The public key 'A' is computed via scalar multiplication of base point 'G':
//
//	A = a * G
func GenerateECDHKeyPair() (*ecdh.PrivateKey, *ecdh.PublicKey, error) {
	curve := ecdh.X25519()
	privKey, err := curve.GenerateKey(cryptoRandReader{})
	if err != nil {
		return nil, nil, fmt.Errorf("ecdh: failed to generate X25519 keypair: %w", err)
	}
	return privKey, privKey.PublicKey(), nil
}

// ComputeECDHSharedSecret performs X25519 Diffie-Hellman scalar multiplication between a local private key
// and a remote peer's public key.
//
// Mathematical Mechanics:
// Let Alice have private scalar 'a' and public point A = a * G.
// Let Bob have private scalar 'b' and public point B = b * G.
//
// Alice computes: S_alice = a * B = a * (b * G) = (a * b) * G
// Bob computes:   S_bob   = b * A = b * (a * G) = (b * a) * G
//
// Since scalar multiplication is commutative over the elliptic curve group, S_alice == S_bob == (a * b) * G.
//
// Security Assumptions (ECDLP):
// An active or passive adversary observing public points A and B cannot derive scalar 'a' or 'b' due to the
// Elliptic Curve Discrete Logarithm Problem (ECDLP), which requires ~2^128 operations for 256-bit Curve25519.
//
// Why KDF is Mandatory After ECDH:
// The resulting 32-byte shared point x-coordinate S is not uniformly distributed across the entire 256-bit bit space.
// Therefore, raw ECDH secrets MUST NEVER be used directly as symmetric encryption keys. They must pass through HKDF.
func ComputeECDHSharedSecret(priv *ecdh.PrivateKey, peerPub *ecdh.PublicKey) ([]byte, error) {
	if priv == nil || peerPub == nil {
		return nil, fmt.Errorf("ecdh: private key and peer public key must not be nil")
	}
	secret, err := priv.ECDH(peerPub)
	if err != nil {
		return nil, fmt.Errorf("ecdh: scalar multiplication failed: %w", err)
	}
	return secret, nil
}

// cryptoRandReader bridges crypto/rand reader to ecdh interface.
type cryptoRandReader struct{}

func (cryptoRandReader) Read(p []byte) (int, error) {
	b, err := SecureRandom(len(p))
	if err != nil {
		return 0, err
	}
	copy(p, b)
	return len(p), nil
}

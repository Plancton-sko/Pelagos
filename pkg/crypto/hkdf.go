package crypto

import (
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// Domain Separation Constants prevent cross-protocol and cross-context key substitution attacks.
const (
	DomainRootKey    = "palagos-v1-root-ratchet"
	DomainChainKey   = "palagos-v1-chain-step"
	DomainMessageKey = "palagos-v1-message-key"
	DomainAuthKey    = "palagos-v1-auth-key"
)

// HKDFExtractExpand executes HKDF-Extract and HKDF-Expand (RFC 5869) using SHA-256 to derive subkeys.
//
// Mathematical Foundation of HKDF:
// HKDF formalizes key derivation into a two-step process:
//
// 1. Extract Stage:
//
//	PRK = HMAC-SHA256(salt, IKM)
//	- Purpose: Extracts a uniformly distributed Pseudorandom Key (PRK) from non-uniform Input Keying Material (IKM),
//	  such as an ECDH shared secret point.
//
// 2. Expand Stage:
//
//	OKM = HKDF-Expand(PRK, info, L)
//	- Computes output blocks T(i):
//	  T(0) = empty slice
//	  T(1) = HMAC-SHA256(PRK, info || 0x01)
//	  T(2) = HMAC-SHA256(PRK, T(1) || info || 0x02)
//	  ...
//	  OKM = T(1) || T(2) || ... truncated to L bytes.
func HKDFExtractExpand(secret, salt []byte, info string, length int) ([]byte, error) {
	if len(secret) == 0 {
		return nil, fmt.Errorf("hkdf: secret cannot be empty")
	}
	kdf := hkdf.New(sha256.New, secret, salt, []byte(info))
	derived := make([]byte, length)
	if _, err := io.ReadFull(kdf, derived); err != nil {
		return nil, fmt.Errorf("hkdf: expansion failed: %w", err)
	}
	return derived, nil
}

// DeriveRatchetedKeys performs a symmetric chain step:
// Given a chain key CK, it derives the next chain key CK' and a message key MK using domain separation.
//
// Symmetric Ratchet Formula:
//
//	CK_next     = HKDF-Expand(CK, "palagos-v1-chain-step", 32)
//	MessageKey  = HKDF-Expand(CK, "palagos-v1-message-key", 32)
//
// Crucial Forward Secrecy Property:
// After deriving (CK_next, MessageKey), the old CK MUST be immediately zeroized. Because HKDF is one-way
// (based on SHA-256 preimage resistance), an attacker who steals CK_next cannot mathematically reverse the
// hash computation to recover previous chain keys or past message keys.
func DeriveRatchetedKeys(chainKey []byte) (nextChainKey []byte, messageKey []byte, err error) {
	if len(chainKey) != 32 {
		return nil, nil, fmt.Errorf("hkdf: invalid chain key size %d, expected 32", len(chainKey))
	}
	nextCK, err := HKDFExtractExpand(chainKey, nil, DomainChainKey, 32)
	if err != nil {
		return nil, nil, err
	}
	mk, err := HKDFExtractExpand(chainKey, nil, DomainMessageKey, 32)
	if err != nil {
		Zeroize(nextCK)
		return nil, nil, err
	}
	return nextCK, mk, nil
}

// DeriveRootStep performs a DH ratchet step:
// Combines current Root Key (RK) and a new ECDH shared secret (dhSecret) to produce a new Root Key and Chain Key.
//
// Formula:
//
//	New_RK, New_CK = HKDF-Expand(HMAC-SHA256(RK, dhSecret), "palagos-v1-root-ratchet", 64)
func DeriveRootStep(rootKey, dhSecret []byte) (nextRootKey []byte, nextChainKey []byte, err error) {
	derived, err := HKDFExtractExpand(dhSecret, rootKey, DomainRootKey, 64)
	if err != nil {
		return nil, nil, err
	}
	nextRootKey = make([]byte, 32)
	nextChainKey = make([]byte, 32)
	copy(nextRootKey, derived[0:32])
	copy(nextChainKey, derived[32:64])
	Zeroize(derived)
	return nextRootKey, nextChainKey, nil
}

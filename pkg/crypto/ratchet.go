package crypto

import (
	"crypto/ecdh"
	"fmt"
	"sync"
)

// Ratchet State represents a peer's cryptographic Double Ratchet state.
//
// Double Ratchet Architecture:
// Palagos uses a Double Ratchet algorithm combining:
// 1. KDF Chain (Symmetric Ratchet): Stepwise derivation of message keys from chain keys.
// 2. DH Ratchet (Asymmetric Ratchet): Ephemeral X25519 key exchanges whenever new public keys are received.
//
// Security Properties:
// - Forward Secrecy: Compromise of current keys cannot decrypt past messages, because chain keys advance
//   via one-way HKDF functions and old keys are zeroized.
// - Post-Compromise Security (Break-in Recovery): If an adversary steals temporary state, receiving a fresh
//   DH ratchet step resets the Root Key with uncompromised entropy, healing the protocol state.
type Ratchet struct {
	mu sync.Mutex

	// DH Ephemeral Keypair
	DHsLocal *ecdh.PrivateKey // Local ephemeral keypair
	DHrPeer  *ecdh.PublicKey  // Remote peer's ephemeral public key

	// Chains and Keys
	RK  []byte // 32-byte Root Key
	CKs []byte // 32-byte Sending Chain Key
	CKr []byte // 32-byte Receiving Chain Key

	// Sequence Numbers
	Ns uint32 // Sending message counter
	Nr uint32 // Receiving message counter
	PN uint32 // Number of messages in previous sending chain

	// Out-of-order skipped message key cache: map[ephemeral_pub_hex + seq]MessageKey
	skippedKeys map[string][]byte
}

// NewRatchet initializes a Double Ratchet session state given a shared secret derived from initial key exchange.
func NewRatchet(sharedSecret []byte, isInitiator bool, localDH *ecdh.PrivateKey, remoteDHPub *ecdh.PublicKey) (*Ratchet, error) {
	if len(sharedSecret) != 32 {
		return nil, fmt.Errorf("ratchet: shared secret must be 32 bytes")
	}

	r := &Ratchet{
		RK:          make([]byte, 32),
		Ns:          1,
		Nr:          1,
		skippedKeys: make(map[string][]byte),
	}
	copy(r.RK, sharedSecret)

	if isInitiator {
		if remoteDHPub == nil {
			return nil, fmt.Errorf("ratchet: initiator requires remote DH public key")
		}
		// Initiator generates fresh local ratchet keypair DHs
		aliceRatchetDH, _, err := GenerateECDHKeyPair()
		if err != nil {
			return nil, err
		}
		r.DHsLocal = aliceRatchetDH
		r.DHrPeer = remoteDHPub

		// Perform initial DH step: DH(DH_A, DH_B)
		dhSecret, err := ComputeECDHSharedSecret(r.DHsLocal, remoteDHPub)
		if err != nil {
			return nil, fmt.Errorf("ratchet: initial DH step failed: %w", err)
		}
		r.RK, r.CKs, err = DeriveRootStep(r.RK, dhSecret)
		Zeroize(dhSecret)
		if err != nil {
			return nil, err
		}
	} else {
		// Responder Bob keeps localDH (DH_B). DHrPeer remains nil until Alice's first message arrives
		if localDH == nil {
			return nil, fmt.Errorf("ratchet: responder requires local DH keypair")
		}
		r.DHsLocal = localDH
	}

	return r, nil
}

// RatchetEncrypt encrypts a plaintext message under the current sending chain key and advances the symmetric ratchet.
func (r *Ratchet) RatchetEncrypt(plaintext []byte, staticAAD []byte, getAAD func(ephemeralPub []byte) []byte) (ephemeralPubBytes []byte, ciphertext []byte, sequence uint32, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.CKs) == 0 {
		if r.DHrPeer == nil {
			return nil, nil, 0, fmt.Errorf("ratchet: cannot send without remote DH public key")
		}
		// DH Ratchet step for sender if sending chain key is uninitialized
		newLocalDH, _, err := GenerateECDHKeyPair()
		if err != nil {
			return nil, nil, 0, fmt.Errorf("ratchet: failed to generate new local DH keypair: %w", err)
		}
		r.DHsLocal = newLocalDH

		dhSecretSend, err := ComputeECDHSharedSecret(r.DHsLocal, r.DHrPeer)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("ratchet: DH send step failed: %w", err)
		}

		r.RK, r.CKs, err = DeriveRootStep(r.RK, dhSecretSend)
		Zeroize(dhSecretSend)
		if err != nil {
			return nil, nil, 0, err
		}

		r.PN = r.Ns
		r.Ns = 1
	}

	ephemeralPubBytes = r.DHsLocal.PublicKey().Bytes()
	var aad []byte
	if getAAD != nil {
		aad = getAAD(ephemeralPubBytes)
	} else {
		aad = staticAAD
	}

	// Advance symmetric sending chain ratchet
	nextCKs, messageKey, err := DeriveRatchetedKeys(r.CKs)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("ratchet: failed to advance sending chain: %w", err)
	}

	// Zeroize old chain key and store next chain key
	Zeroize(r.CKs)
	r.CKs = nextCKs

	sequence = r.Ns
	r.Ns++

	// Derived 24-byte nonce combining sequence number & CSPRNG for XChaCha20-Poly1305
	nonce, err := SecureRandom(NonceSizeXChaCha20Poly1305)
	if err != nil {
		Zeroize(messageKey)
		return nil, nil, 0, err
	}

	ciphertext, err = EncryptAEAD(messageKey, nonce, plaintext, aad)
	Zeroize(messageKey)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("ratchet: AEAD encryption failed: %w", err)
	}

	// Prepend nonce to ciphertext slice for transportation
	fullCiphertext := append(nonce, ciphertext...)

	return ephemeralPubBytes, fullCiphertext, sequence, nil
}

// RatchetDecrypt decrypts an incoming message and performs DH / Symmetric Ratchet steps as necessary.
func (r *Ratchet) RatchetDecrypt(ephemeralPubBytes, fullCiphertext, aad []byte, sequence uint32) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(fullCiphertext) < NonceSizeXChaCha20Poly1305 {
		return nil, fmt.Errorf("ratchet: ciphertext too short")
	}

	nonce := fullCiphertext[:NonceSizeXChaCha20Poly1305]
	ciphertext := fullCiphertext[NonceSizeXChaCha20Poly1305:]

	peerPub, err := ecdh.X25519().NewPublicKey(ephemeralPubBytes)
	if err != nil {
		return nil, fmt.Errorf("ratchet: invalid peer ephemeral public key: %w", err)
	}

	// Check if a new DH Ratchet step is triggered (peer sent a new ephemeral key)
	if r.DHrPeer == nil || !r.DHrPeer.Equal(peerPub) {
		// Skip remaining message keys in current receiving chain
		r.DHrPeer = peerPub

		// Perform DH Ratchet Step 1: Receiver step
		dhSecretRecv, err := ComputeECDHSharedSecret(r.DHsLocal, r.DHrPeer)
		if err != nil {
			return nil, fmt.Errorf("ratchet: DH recv step failed: %w", err)
		}
		r.RK, r.CKr, err = DeriveRootStep(r.RK, dhSecretRecv)
		Zeroize(dhSecretRecv)
		if err != nil {
			return nil, err
		}

		// Perform DH Ratchet Step 2: Sender step (generate new local DH keypair)
		newLocalDH, newLocalDHPub, err := GenerateECDHKeyPair()
		if err != nil {
			return nil, err
		}
		r.DHsLocal = newLocalDH
		_ = newLocalDHPub

		dhSecretSend, err := ComputeECDHSharedSecret(r.DHsLocal, r.DHrPeer)
		if err != nil {
			return nil, fmt.Errorf("ratchet: DH send step failed: %w", err)
		}
		r.RK, r.CKs, err = DeriveRootStep(r.RK, dhSecretSend)
		Zeroize(dhSecretSend)
		if err != nil {
			return nil, err
		}

		r.PN = r.Ns
		r.Ns = 1
		r.Nr = 1
	}

	// Advance symmetric receiving chain ratchet to current sequence number
	for r.Nr < sequence {
		nextCKr, skippedMK, err := DeriveRatchetedKeys(r.CKr)
		if err != nil {
			return nil, err
		}
		Zeroize(r.CKr)
		r.CKr = nextCKr
		skipKey := fmt.Sprintf("%x-%d", peerPub.Bytes(), r.Nr)
		r.skippedKeys[skipKey] = skippedMK
		r.Nr++
	}

	// Derive message key for current packet
	nextCKr, messageKey, err := DeriveRatchetedKeys(r.CKr)
	if err != nil {
		return nil, err
	}
	Zeroize(r.CKr)
	r.CKr = nextCKr
	r.Nr++

	plaintext, err := DecryptAEAD(messageKey, nonce, ciphertext, aad)
	Zeroize(messageKey)
	if err != nil {
		return nil, fmt.Errorf("ratchet: decryption failed: %w", err)
	}

	return plaintext, nil
}

package tests

import (
	"bytes"
	"testing"

	"palagos/pkg/crypto"
)

func TestECDHKeyExchange(t *testing.T) {
	alicePriv, alicePub, err := crypto.GenerateECDHKeyPair()
	if err != nil {
		t.Fatalf("Alice ECDH generation failed: %v", err)
	}

	bobPriv, bobPub, err := crypto.GenerateECDHKeyPair()
	if err != nil {
		t.Fatalf("Bob ECDH generation failed: %v", err)
	}

	secretAlice, err := crypto.ComputeECDHSharedSecret(alicePriv, bobPub)
	if err != nil {
		t.Fatalf("Alice ECDH compute failed: %v", err)
	}

	secretBob, err := crypto.ComputeECDHSharedSecret(bobPriv, alicePub)
	if err != nil {
		t.Fatalf("Bob ECDH compute failed: %v", err)
	}

	if !bytes.Equal(secretAlice, secretBob) {
		t.Fatalf("ECDH scalar multiplication mismatch! Alice secret != Bob secret")
	}
}

func TestEd25519SignAndVerify(t *testing.T) {
	pub, priv, err := crypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("Ed25519 generation failed: %v", err)
	}

	message := []byte("Palagos Protocol Identity Verification Challenge")
	sig, err := crypto.SignMessage(priv, message)
	if err != nil {
		t.Fatalf("SignMessage failed: %v", err)
	}

	if !crypto.VerifySignature(pub, message, sig) {
		t.Fatalf("Valid signature failed verification!")
	}

	// Corrupt signature
	sig[0] ^= 0xFF
	if crypto.VerifySignature(pub, message, sig) {
		t.Fatalf("Corrupted signature passed verification!")
	}
}

func TestHKDFDerivation(t *testing.T) {
	secret := []byte("shared-ecdh-master-secret-32-bytes")
	salt := []byte("unique-salt-value")

	key1, err := crypto.HKDFExtractExpand(secret, salt, "context-a", 32)
	if err != nil {
		t.Fatalf("HKDF failed: %v", err)
	}

	key2, err := crypto.HKDFExtractExpand(secret, salt, "context-b", 32)
	if err != nil {
		t.Fatalf("HKDF failed: %v", err)
	}

	if bytes.Equal(key1, key2) {
		t.Fatalf("Domain separation failure: different context strings yielded identical keys!")
	}
}

func TestChaCha20Poly1305AEAD(t *testing.T) {
	key, err := crypto.SecureRandom(32)
	if err != nil {
		t.Fatalf("SecureRandom failed: %v", err)
	}

	nonce, err := crypto.SecureRandom(crypto.NonceSizeXChaCha20Poly1305)
	if err != nil {
		t.Fatalf("SecureRandom nonce failed: %v", err)
	}

	plaintext := []byte("Confidential message payload")
	aad := []byte("Authenticated Header AAD v1.0")

	ciphertext, err := crypto.EncryptAEAD(key, nonce, plaintext, aad)
	if err != nil {
		t.Fatalf("AEAD encrypt failed: %v", err)
	}

	decrypted, err := crypto.DecryptAEAD(key, nonce, ciphertext, aad)
	if err != nil {
		t.Fatalf("AEAD decrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatalf("Decrypted plaintext mismatch!")
	}

	// Test AAD tampering
	corruptedAAD := []byte("Corrupted Header AAD v1.0")
	_, err = crypto.DecryptAEAD(key, nonce, ciphertext, corruptedAAD)
	if err == nil {
		t.Fatalf("AEAD failed to detect corrupted AAD!")
	}

	// Test Ciphertext tampering
	ciphertext[0] ^= 0x01
	_, err = crypto.DecryptAEAD(key, nonce, ciphertext, aad)
	if err == nil {
		t.Fatalf("AEAD failed to detect corrupted ciphertext!")
	}
}

func TestDoubleRatchetTransitions(t *testing.T) {
	sharedSecret, _ := crypto.SecureRandom(32)

	aliceDH, alicePub, _ := crypto.GenerateECDHKeyPair()
	bobDH, bobPub, _ := crypto.GenerateECDHKeyPair()

	aliceRatchet, err := crypto.NewRatchet(sharedSecret, true, aliceDH, bobPub)
	if err != nil {
		t.Fatalf("Alice ratchet init failed: %v", err)
	}

	bobRatchet, err := crypto.NewRatchet(sharedSecret, false, bobDH, alicePub)
	if err != nil {
		t.Fatalf("Bob ratchet init failed: %v", err)
	}

	msg1 := []byte("Message 1: Initial state")
	aad1 := []byte("aad-1")

	ePub1, ciphertext1, seq1, err := aliceRatchet.RatchetEncrypt(msg1, aad1, nil)
	if err != nil {
		t.Fatalf("Alice encrypt failed: %v", err)
	}

	decrypted1, err := bobRatchet.RatchetDecrypt(ePub1, ciphertext1, aad1, seq1)
	if err != nil {
		t.Fatalf("Bob decrypt msg 1 failed: %v", err)
	}

	if !bytes.Equal(msg1, decrypted1) {
		t.Fatalf("Ratchet msg 1 mismatch!")
	}

	// Bob replies to Alice
	msg2 := []byte("Message 2: Ratchet reply")
	aad2 := []byte("aad-2")

	ePub2, ciphertext2, seq2, err := bobRatchet.RatchetEncrypt(msg2, aad2, nil)
	if err != nil {
		t.Fatalf("Bob encrypt failed: %v", err)
	}

	decrypted2, err := aliceRatchet.RatchetDecrypt(ePub2, ciphertext2, aad2, seq2)
	if err != nil {
		t.Fatalf("Alice decrypt msg 2 failed: %v", err)
	}

	if !bytes.Equal(msg2, decrypted2) {
		t.Fatalf("Ratchet msg 2 mismatch!")
	}
}

package identity

import (
	"testing"
)

func TestPairingSuccess(t *testing.T) {
	// 1. Setup Alice and Bob identities
	aliceId, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("Failed to generate Alice identity: %v", err)
	}

	bobId, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("Failed to generate Bob identity: %v", err)
	}

	pin := "849201" // Shared PIN spoken out-loud by Alice and Bob

	// 2. Alice creates pairing payload for Bob
	payloadA, err := CreatePairingPayload(aliceId, "Alice-Phone", pin)
	if err != nil {
		t.Fatalf("Alice failed to create pairing payload: %v", err)
	}

	// 3. Serialize and transmit over Bluetooth
	rawBytes := payloadA.Marshal()
	receivedPayload, err := UnmarshalPairingPayload(rawBytes)
	if err != nil {
		t.Fatalf("Failed to unmarshal pairing payload: %v", err)
	}

	// 4. Bob opens payload using the agreed PIN
	peerIdAlice, sasBob, err := OpenPairingPayload(receivedPayload, bobId, pin)
	if err != nil {
		t.Fatalf("Bob failed to open pairing payload: %v", err)
	}

	if peerIdAlice.Alias != "Alice-Phone" {
		t.Errorf("Expected alias 'Alice-Phone', got '%s'", peerIdAlice.Alias)
	}

	if string(peerIdAlice.PublicKey) != string(aliceId.PublicKey) {
		t.Errorf("Extracted public key does not match Alice's actual public key")
	}

	// 5. Alice generates SAS for her payload once she has Bob's public key
	sasAlice, err := payloadA.GenerateSAS(aliceId, bobId.PublicKey, pin)
	if err != nil {
		t.Fatalf("Alice failed to generate SAS: %v", err)
	}

	if sasAlice != sasBob {
		t.Fatalf("SAS Mismatch! Alice computed %s, Bob computed %s", sasAlice, sasBob)
	}

	t.Logf("[+] Alice extracted Bob FP: %s", peerIdAlice.FormattedFingerprint())
	t.Logf("[+] SAS Confirmation Code MATCH! (Alice: %s, Bob: %s)", sasAlice, sasBob)
}

func TestPairingInvalidPIN(t *testing.T) {
	aliceId, _ := GenerateIdentity()
	bobId, _ := GenerateIdentity()

	correctPIN := "123456"
	wrongPIN := "654321"

	payload, err := CreatePairingPayload(aliceId, "Alice", correctPIN)
	if err != nil {
		t.Fatalf("Failed to create payload: %v", err)
	}

	// Attacker or user with wrong PIN tries to open payload
	_, _, err = OpenPairingPayload(payload, bobId, wrongPIN)
	if err == nil {
		t.Fatalf("Expected error when opening payload with wrong PIN, but got success")
	}
	t.Logf("[+] Correctly rejected invalid PIN: %v", err)
}

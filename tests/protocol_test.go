package tests

import (
	"bytes"
	"testing"

	"palagos/pkg/identity"
	"palagos/pkg/protocol"
)

func TestPacketMarshalUnmarshal(t *testing.T) {
	pkt := &protocol.Packet{
		Version:            protocol.CurrentProtocolVersion,
		Type:               protocol.MessageTypeData,
		Epoch:              42,
		Sequence:           1001,
		SenderFingerprint:  [32]byte{1, 2, 3, 4},
		RecipientFingerprint: [32]byte{5, 6, 7, 8},
		EphemeralPublicKey: [32]byte{9, 10, 11, 12},
		Nonce:              [24]byte{13, 14, 15},
		Payload:            []byte("Encrypted Ciphertext Payload Data"),
		Signature:          [64]byte{99},
	}

	data, err := pkt.Marshal()
	if err != nil {
		t.Fatalf("Packet.Marshal failed: %v", err)
	}

	var decoded protocol.Packet
	if err := decoded.Unmarshal(data); err != nil {
		t.Fatalf("Packet.Unmarshal failed: %v", err)
	}

	if decoded.Version != pkt.Version || decoded.Type != pkt.Type || decoded.Sequence != pkt.Sequence {
		t.Fatalf("Packet unmarshal field mismatch!")
	}

	if !bytes.Equal(decoded.Payload, pkt.Payload) {
		t.Fatalf("Packet unmarshal payload mismatch!")
	}
}

func TestReplayProtectionWindow(t *testing.T) {
	rw := protocol.NewReplayWindow()

	// 1. First packet (seq 100) -> Accept
	if !rw.CheckAndAdd(100) {
		t.Fatalf("Initial sequence 100 rejected!")
	}

	// 2. Duplicate packet (seq 100) -> Reject
	if rw.CheckAndAdd(100) {
		t.Fatalf("Replayed sequence 100 accepted!")
	}

	// 3. Out-of-order older packet within window (seq 95) -> Accept
	if !rw.CheckAndAdd(95) {
		t.Fatalf("Valid out-of-order sequence 95 rejected!")
	}

	// 4. Duplicate out-of-order packet (seq 95) -> Reject
	if rw.CheckAndAdd(95) {
		t.Fatalf("Replayed out-of-order sequence 95 accepted!")
	}

	// 5. Jump window forward (seq 200) -> Accept
	if !rw.CheckAndAdd(200) {
		t.Fatalf("New max sequence 200 rejected!")
	}

	// 6. Old sequence far behind window (seq 100) -> Reject (diff = 100 >= 64)
	if rw.CheckAndAdd(100) {
		t.Fatalf("Expired sequence 100 accepted!")
	}
}

func TestFullSessionHandshakeAndMessaging(t *testing.T) {
	aliceId, _ := identity.GenerateIdentity()
	bobId, _ := identity.GenerateIdentity()

	alicePeer, _ := identity.NewPeerIdentity(bobId.PublicKey, "Bob")
	bobPeer, _ := identity.NewPeerIdentity(aliceId.PublicKey, "Alice")

	aliceSession := protocol.NewSession(aliceId, alicePeer)
	bobSession := protocol.NewSession(bobId, bobPeer)

	// Step 1: Alice creates HandshakeInit
	initPkt, aliceEphemeralPriv, err := aliceSession.CreateHandshakeInit()
	if err != nil {
		t.Fatalf("Alice CreateHandshakeInit failed: %v", err)
	}

	// Step 2: Bob processes HandshakeInit & creates HandshakeResp
	respPkt, err := bobSession.ProcessHandshakeInit(initPkt)
	if err != nil {
		t.Fatalf("Bob ProcessHandshakeInit failed: %v", err)
	}

	// Step 3: Alice completes handshake with HandshakeResp
	if err := aliceSession.CompleteInitiatorHandshake(respPkt, aliceEphemeralPriv); err != nil {
		t.Fatalf("Alice CompleteInitiatorHandshake failed: %v", err)
	}

	if !aliceSession.IsEstablished || !bobSession.IsEstablished {
		t.Fatalf("Session establishment flag missing!")
	}

	// Step 4: Alice encrypts message -> Bob decrypts
	plaintextMsg := []byte("Top Secret Palagos Protocol Handshake Complete")
	dataPkt, err := aliceSession.EncryptMessage(plaintextMsg)
	if err != nil {
		t.Fatalf("Alice EncryptMessage failed: %v", err)
	}

	decryptedMsg, err := bobSession.DecryptMessage(dataPkt)
	if err != nil {
		t.Fatalf("Bob DecryptMessage failed: %v", err)
	}

	if !bytes.Equal(plaintextMsg, decryptedMsg) {
		t.Fatalf("Decrypted message mismatch!")
	}
}

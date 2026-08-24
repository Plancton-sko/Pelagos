package tests

import (
	"bytes"
	"net"
	"testing"
	"time"

	"palagos/pkg/identity"
	"palagos/pkg/protocol"
	"palagos/pkg/server"
	"palagos/pkg/transport"
)

func TestEndToEndRelayMessaging(t *testing.T) {
	// 1. Initialize Relay Server with Server Identity
	srv, err := server.NewServer()
	if err != nil {
		t.Fatalf("Failed to initialize server: %v", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer listener.Close()

	// Server handle loop
	go func() {
		for {
			rawConn, err := listener.Accept()
			if err != nil {
				return
			}
			conn := transport.NewFramedConn(rawConn)
			go func(c *transport.FramedConn) {
				clientFP, err := srv.AuthenticateClient(c)
				if err != nil {
					c.Close()
					return
				}
				_ = srv.DeliverMailbox(clientFP, c)

				for {
					pktData, err := c.ReceivePacket()
					if err != nil {
						return
					}
					_ = srv.RoutePacket(pktData)
				}
			}(conn)
		}
	}()

	serverAddr := listener.Addr().String()

	// 2. Setup Alice and Bob Identities
	aliceId, err := identity.GenerateIdentity()
	if err != nil {
		t.Fatalf("Failed to generate Alice identity: %v", err)
	}

	bobId, err := identity.GenerateIdentity()
	if err != nil {
		t.Fatalf("Failed to generate Bob identity: %v", err)
	}

	alicePeerBob, _ := identity.NewPeerIdentity(bobId.PublicKey, "Bob")
	bobPeerAlice, _ := identity.NewPeerIdentity(aliceId.PublicKey, "Alice")

	// 3. Alice connects & authenticates with Relay Server
	aliceNetConn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		t.Fatalf("Alice dial failed: %v", err)
	}
	defer aliceNetConn.Close()
	aliceConn := transport.NewFramedConn(aliceNetConn)

	if err := server.VerifyServerIdentity(aliceConn, srv.ServerId.PublicKey); err != nil {
		t.Fatalf("Alice server verification failed: %v", err)
	}
	if err := aliceConn.SendPacket(aliceId.PublicKey); err != nil {
		t.Fatalf("Alice send public key failed: %v", err)
	}

	// 4. Bob connects & authenticates with Relay Server
	bobNetConn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		t.Fatalf("Bob dial failed: %v", err)
	}
	defer bobNetConn.Close()
	bobConn := transport.NewFramedConn(bobNetConn)

	if err := server.VerifyServerIdentity(bobConn, srv.ServerId.PublicKey); err != nil {
		t.Fatalf("Bob server verification failed: %v", err)
	}
	if err := bobConn.SendPacket(bobId.PublicKey); err != nil {
		t.Fatalf("Bob send public key failed: %v", err)
	}

	// 5. Establish Double Ratchet Session between Alice & Bob
	aliceSession := protocol.NewSession(aliceId, alicePeerBob)
	bobSession := protocol.NewSession(bobId, bobPeerAlice)

	// Step A: Alice sends HandshakeInit
	initPkt, aliceEphemeralPriv, err := aliceSession.CreateHandshakeInit()
	if err != nil {
		t.Fatalf("Alice CreateHandshakeInit failed: %v", err)
	}
	initData, _ := initPkt.Marshal()
	if err := aliceConn.SendPacket(initData); err != nil {
		t.Fatalf("Alice send HandshakeInit failed: %v", err)
	}

	// Step B: Bob receives HandshakeInit & sends HandshakeResp
	bobNetConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	recvInitData, err := bobConn.ReceivePacket()
	if err != nil {
		t.Fatalf("Bob ReceivePacket HandshakeInit failed: %v", err)
	}
	var recvInitPkt protocol.Packet
	if err := recvInitPkt.Unmarshal(recvInitData); err != nil {
		t.Fatalf("Bob Unmarshal HandshakeInit failed: %v", err)
	}

	respPkt, err := bobSession.ProcessHandshakeInit(&recvInitPkt)
	if err != nil {
		t.Fatalf("Bob ProcessHandshakeInit failed: %v", err)
	}
	respData, _ := respPkt.Marshal()
	if err := bobConn.SendPacket(respData); err != nil {
		t.Fatalf("Bob send HandshakeResp failed: %v", err)
	}

	// Step C: Alice receives HandshakeResp & completes handshake
	aliceNetConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	recvRespData, err := aliceConn.ReceivePacket()
	if err != nil {
		t.Fatalf("Alice ReceivePacket HandshakeResp failed: %v", err)
	}
	var recvRespPkt protocol.Packet
	if err := recvRespPkt.Unmarshal(recvRespData); err != nil {
		t.Fatalf("Alice Unmarshal HandshakeResp failed: %v", err)
	}

	if err := aliceSession.CompleteInitiatorHandshake(&recvRespPkt, aliceEphemeralPriv); err != nil {
		t.Fatalf("Alice CompleteInitiatorHandshake failed: %v", err)
	}

	if !aliceSession.IsEstablished || !bobSession.IsEstablished {
		t.Fatalf("Sessions failed to establish!")
	}

	// 6. Multi-turn Messaging & Ratchet Evolution Verification
	msgs := []string{
		"Message 1 from Alice: High priority cryptographic data payload.",
		"Message 2 from Bob: Acknowledged. Replying with fresh ratchet keys.",
		"Message 3 from Alice: Symmetric key step advance test.",
	}

	// Turn 1: Alice -> Bob
	alicePkt1, _ := aliceSession.EncryptMessage([]byte(msgs[0]))
	data1, _ := alicePkt1.Marshal()
	_ = aliceConn.SendPacket(data1)

	bobNetConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	recvData1, err := bobConn.ReceivePacket()
	if err != nil {
		t.Fatalf("Bob failed to receive msg 1: %v", err)
	}
	var bobRecvPkt1 protocol.Packet
	_ = bobRecvPkt1.Unmarshal(recvData1)
	decrypted1, err := bobSession.DecryptMessage(&bobRecvPkt1)
	if err != nil || string(decrypted1) != msgs[0] {
		t.Fatalf("Decryption msg 1 failed: %v", err)
	}

	// Turn 2: Bob -> Alice (triggers DH ratchet step)
	bobPkt2, _ := bobSession.EncryptMessage([]byte(msgs[1]))
	data2, _ := bobPkt2.Marshal()
	_ = bobConn.SendPacket(data2)

	aliceNetConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	recvData2, err := aliceConn.ReceivePacket()
	if err != nil {
		t.Fatalf("Alice failed to receive msg 2: %v", err)
	}
	var aliceRecvPkt2 protocol.Packet
	_ = aliceRecvPkt2.Unmarshal(recvData2)
	decrypted2, err := aliceSession.DecryptMessage(&aliceRecvPkt2)
	if err != nil || string(decrypted2) != msgs[1] {
		t.Fatalf("Decryption msg 2 failed: %v", err)
	}

	// Turn 3: Alice -> Bob
	alicePkt3, _ := aliceSession.EncryptMessage([]byte(msgs[2]))
	data3, _ := alicePkt3.Marshal()
	_ = aliceConn.SendPacket(data3)

	bobNetConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	recvData3, err := bobConn.ReceivePacket()
	if err != nil {
		t.Fatalf("Bob failed to receive msg 3: %v", err)
	}
	var bobRecvPkt3 protocol.Packet
	_ = bobRecvPkt3.Unmarshal(recvData3)
	decrypted3, err := bobSession.DecryptMessage(&bobRecvPkt3)
	if err != nil || string(decrypted3) != msgs[2] {
		t.Fatalf("Decryption msg 3 failed: %v", err)
	}
}

func TestReplayAttackRejectionInSession(t *testing.T) {
	aliceId, _ := identity.GenerateIdentity()
	bobId, _ := identity.GenerateIdentity()

	alicePeerBob, _ := identity.NewPeerIdentity(bobId.PublicKey, "Bob")
	bobPeerAlice, _ := identity.NewPeerIdentity(aliceId.PublicKey, "Alice")

	aliceSession := protocol.NewSession(aliceId, alicePeerBob)
	bobSession := protocol.NewSession(bobId, bobPeerAlice)

	// Quick direct handshake initialization
	initPkt, alicePriv, _ := aliceSession.CreateHandshakeInit()
	respPkt, _ := bobSession.ProcessHandshakeInit(initPkt)
	_ = aliceSession.CompleteInitiatorHandshake(respPkt, alicePriv)

	// Encrypt a valid message
	msgPkt, _ := aliceSession.EncryptMessage([]byte("Valid Secret Message"))

	// Bob decrypts valid message first time -> PASS
	decrypted, err := bobSession.DecryptMessage(msgPkt)
	if err != nil || !bytes.Equal(decrypted, []byte("Valid Secret Message")) {
		t.Fatalf("First decryption failed: %v", err)
	}

	// Replay exact same packet second time -> MUST REJECT
	_, err = bobSession.DecryptMessage(msgPkt)
	if err == nil {
		t.Fatalf("Replay protection failure: duplicate packet was accepted!")
	}
}

func TestTamperedPayloadSignatureRejection(t *testing.T) {
	aliceId, _ := identity.GenerateIdentity()
	bobId, _ := identity.GenerateIdentity()

	alicePeerBob, _ := identity.NewPeerIdentity(bobId.PublicKey, "Bob")
	bobPeerAlice, _ := identity.NewPeerIdentity(aliceId.PublicKey, "Alice")

	aliceSession := protocol.NewSession(aliceId, alicePeerBob)
	bobSession := protocol.NewSession(bobId, bobPeerAlice)

	initPkt, alicePriv, _ := aliceSession.CreateHandshakeInit()
	respPkt, _ := bobSession.ProcessHandshakeInit(initPkt)
	_ = aliceSession.CompleteInitiatorHandshake(respPkt, alicePriv)

	msgPkt, _ := aliceSession.EncryptMessage([]byte("Tamper Test Payload"))

	// Tamper payload byte
	msgPkt.Payload[0] ^= 0xFF

	// Bob attempts decryption -> MUST REJECT
	_, err := bobSession.DecryptMessage(msgPkt)
	if err == nil {
		t.Fatalf("Security failure: tampered payload was accepted!")
	}
}

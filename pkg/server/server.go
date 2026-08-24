package server

import (
	"crypto/ed25519"
	"fmt"
	"sync"

	"palagos/pkg/crypto"
	"palagos/pkg/identity"
	"palagos/pkg/protocol"
	"palagos/pkg/transport"
)

// Server represents a zero-trust Palagos rendezvous and relay server.
//
// Threat Model & Zero-Trust Rationale:
// 1. Server Confidentiality: The server NEVER possesses message keys or private identity keys. All payloads
//    are encrypted with ChaCha20-Poly1305 under Double Ratchet keys known exclusively to Alice and Bob.
// 2. Header Integrity: Server cannot alter sequence numbers, sender IDs, or version fields without triggering
//    AEAD AAD verification failure on the receiving client.
// 3. Server Identity Authentication: The server holds an Ed25519 identity key. Clients authenticate the server
//    via challenge-response during connection establishment to prevent rogue server spoofing / DNS hijacking.
type Server struct {
	mu           sync.Mutex
	ServerId     *identity.Identity
	mailboxes    map[[32]byte][][]byte // Map: Recipient Fingerprint -> Queue of binary Palagos packets
	clients      map[[32]byte]transport.Conn
	transports   []transport.Transport
}

// NewServer initializes a new relay server with a fresh Ed25519 server identity keypair.
func NewServer() (*Server, error) {
	serverId, err := identity.GenerateIdentity()
	if err != nil {
		return nil, fmt.Errorf("server: failed to generate server identity: %w", err)
	}

	return &Server{
		ServerId:  serverId,
		mailboxes: make(map[[32]byte][][]byte),
		clients:   make(map[[32]byte]transport.Conn),
	}, nil
}

// AuthenticateClient performs challenge-response to prove server identity to client.
func (s *Server) AuthenticateClient(conn transport.Conn) ([32]byte, error) {
	// 1. Receive client challenge nonce (32 bytes)
	challenge, err := conn.ReceivePacket()
	if err != nil || len(challenge) != 32 {
		return [32]byte{}, fmt.Errorf("server: invalid challenge received from client")
	}

	// 2. Sign challenge with Server's private identity key
	serverSig, err := s.ServerId.Sign(challenge)
	if err != nil {
		return [32]byte{}, err
	}

	// 3. Send server public key + signature back to client
	authResp := append(s.ServerId.PublicKey, serverSig...)
	if err := conn.SendPacket(authResp); err != nil {
		return [32]byte{}, fmt.Errorf("server: failed to send auth response: %w", err)
	}

	// 4. Receive client's public identity key packet
	clientAuthPkt, err := conn.ReceivePacket()
	if err != nil || len(clientAuthPkt) != ed25519.PublicKeySize {
		return [32]byte{}, fmt.Errorf("server: failed to receive client identity")
	}

	var clientFP [32]byte
	clientPeer, err := identity.NewPeerIdentity(clientAuthPkt, "client")
	if err != nil {
		return clientFP, err
	}

	clientFP = clientPeer.Fingerprint()
	s.mu.Lock()
	s.clients[clientFP] = conn
	s.mu.Unlock()

	return clientFP, nil
}

// RoutePacket accepts a binary packet and routes it directly to an online client or stores it in their offline mailbox.
func (s *Server) RoutePacket(rawPacket []byte) error {
	var pkt protocol.Packet
	if err := pkt.Unmarshal(rawPacket); err != nil {
		return fmt.Errorf("server: failed to unmarshal packet for routing: %w", err)
	}

	recipientFP := pkt.RecipientFingerprint

	s.mu.Lock()
	conn, isOnline := s.clients[recipientFP]
	if isOnline {
		s.mu.Unlock()
		if err := conn.SendPacket(rawPacket); err != nil {
			// If send fails, push to offline mailbox
			s.mu.Lock()
			delete(s.clients, recipientFP)
			s.mailboxes[recipientFP] = append(s.mailboxes[recipientFP], rawPacket)
			s.mu.Unlock()
		}
		return nil
	}

	// Recipient is offline: store in mailbox
	s.mailboxes[recipientFP] = append(s.mailboxes[recipientFP], rawPacket)
	s.mu.Unlock()

	return nil
}

// DeliverMailbox flushes all pending offline packets to a newly reconnected client.
func (s *Server) DeliverMailbox(clientFP [32]byte, conn transport.Conn) error {
	s.mu.Lock()
	packets, hasMail := s.mailboxes[clientFP]
	delete(s.mailboxes, clientFP)
	s.mu.Unlock()

	if !hasMail {
		return nil
	}

	for _, rawPkt := range packets {
		if err := conn.SendPacket(rawPkt); err != nil {
			return fmt.Errorf("server: failed delivering mailbox packet: %w", err)
		}
	}
	return nil
}

// VerifyServerIdentity is used on the client side to verify that the server owns its claimed Ed25519 identity key.
func VerifyServerIdentity(conn transport.Conn, expectedServerPub ed25519.PublicKey) error {
	// 1. Generate local 32-byte random challenge
	challenge, err := crypto.SecureRandom(32)
	if err != nil {
		return err
	}

	// 2. Send challenge to server
	if err := conn.SendPacket(challenge); err != nil {
		return fmt.Errorf("client: failed sending auth challenge: %w", err)
	}

	// 3. Receive server response (32-byte pubkey + 64-byte sig)
	resp, err := conn.ReceivePacket()
	if err != nil || len(resp) != ed25519.PublicKeySize+ed25519.SignatureSize {
		return fmt.Errorf("client: invalid server auth response format")
	}

	serverPub := ed25519.PublicKey(resp[:ed25519.PublicKeySize])
	serverSig := resp[ed25519.PublicKeySize:]

	// Verify server matches expected public key
	if len(expectedServerPub) > 0 && !serverPub.Equal(expectedServerPub) {
		return fmt.Errorf("client: SERVER IMPERSONATION DETECTED: received server pubkey does not match expected identity")
	}

	// Verify server signature over challenge
	if !crypto.VerifySignature(serverPub, challenge, serverSig) {
		return fmt.Errorf("client: SERVER AUTHENTICATION FAILED: invalid signature over challenge")
	}

	return nil
}

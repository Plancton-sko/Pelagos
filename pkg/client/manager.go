package client

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"palagos/pkg/identity"
	"palagos/pkg/protocol"
	"palagos/pkg/transport"
)

// ConnectionMode specifies whether the client routes messages via a Relay Server or Direct P2P.
type ConnectionMode string

const (
	ModeRelay     ConnectionMode = "relay"      // Relay Server Store-and-Forward mode
	ModeDirectP2P ConnectionMode = "direct_p2p" // Direct Peer-to-Peer Onion/TCP mode
)

// Contact represents a remote peer saved in the local contact book.
type Contact struct {
	Fingerprint  [32]byte               `json:"fingerprint"`
	FormattedFP  string                 `json:"formatted_fingerprint"`
	PublicKeyHex string                 `json:"public_key_hex"`
	CustomAlias  string                 `json:"custom_alias"` // Custom user-defined name/alias
	OnionAddress string                 `json:"onion_address"`
	PeerIdentity *identity.PeerIdentity `json:"-"`
	CreatedAt    time.Time              `json:"created_at"`
}

// Message represents an encrypted or decrypted chat message in memory.
type Message struct {
	ID         string    `json:"id"`
	SenderFP   string    `json:"sender_fp"`
	SenderIsMe bool      `json:"sender_is_me"`
	Content    string    `json:"content"`
	Sequence   uint64    `json:"sequence"`
	Timestamp  time.Time `json:"timestamp"`
}

// Manager orchestrates multiple local identities, contacts, and active Double Ratchet sessions.
type Manager struct {
	mu             sync.RWMutex
	Identities     map[string]*identity.Identity // Profile Name -> Local Identity
	ActiveProfile  string
	Contacts       map[[32]byte]*Contact // Remote Peer FP -> Contact Info
	Sessions       map[[32]byte]*protocol.Session
	Messages       map[[32]byte][]Message
	ActiveConns    map[[32]byte]transport.Conn
	TorSocksAddr   string
	RelayAddr      string
	Mode           ConnectionMode
	OnionTransport *transport.OnionTransport
	onMessageFunc  func(peerFP [32]byte, msg Message)
}

// NewManager initializes a new Client Manager instance.
func NewManager(socksAddr string) (*Manager, error) {
	ot, err := transport.NewOnionTransport(socksAddr)
	if err != nil {
		return nil, fmt.Errorf("manager: failed to init onion transport: %w", err)
	}

	// Create default initial profile
	id, err := identity.GenerateIdentity()
	if err != nil {
		return nil, err
	}

	m := &Manager{
		Identities:     make(map[string]*identity.Identity),
		ActiveProfile:  "Default",
		Contacts:       make(map[[32]byte]*Contact),
		Sessions:       make(map[[32]byte]*protocol.Session),
		Messages:       make(map[[32]byte][]Message),
		ActiveConns:    make(map[[32]byte]transport.Conn),
		TorSocksAddr:   socksAddr,
		Mode:           ModeRelay,
		OnionTransport: ot,
	}

	m.Identities["Default"] = id
	return m, nil
}

// SetConnectionMode switches between Relay mode and Direct P2P mode.
func (m *Manager) SetConnectionMode(mode ConnectionMode, relayAddr string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Mode = mode
	m.RelayAddr = relayAddr
}

// SetOnMessageCallback sets a callback triggered whenever a new message is received.
func (m *Manager) SetOnMessageCallback(callback func(peerFP [32]byte, msg Message)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onMessageFunc = callback
}

// AddIdentityProfile allows generating or importing multiple local identities.
func (m *Manager) AddIdentityProfile(name string, id *identity.Identity) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Identities[name] = id
}

// SwitchProfile switches the active local identity profile.
func (m *Manager) SwitchProfile(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.Identities[name]; !ok {
		return fmt.Errorf("profile '%s' does not exist", name)
	}
	m.ActiveProfile = name
	return nil
}

// GetActiveIdentity returns the currently selected local Identity.
func (m *Manager) GetActiveIdentity() *identity.Identity {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.Identities[m.ActiveProfile]
}

// SaveContact adds or updates a contact with a user-chosen custom alias.
func (m *Manager) SaveContact(pubKeyBytes []byte, customAlias string, onionAddr string) (*Contact, error) {
	if len(pubKeyBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("manager: invalid public key length %d", len(pubKeyBytes))
	}

	fp := sha256.Sum256(pubKeyBytes)
	peerId, err := identity.NewPeerIdentity(pubKeyBytes, customAlias)
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	c := &Contact{
		Fingerprint:  fp,
		FormattedFP:  peerId.FormattedFingerprint(),
		PublicKeyHex: hex.EncodeToString(pubKeyBytes),
		CustomAlias:  customAlias,
		OnionAddress: onionAddr,
		PeerIdentity: peerId,
		CreatedAt:    time.Now(),
	}

	m.Contacts[fp] = c
	return c, nil
}

// GetContactByFP retrieves a contact by fingerprint.
func (m *Manager) GetContactByFP(fp [32]byte) (*Contact, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c, ok := m.Contacts[fp]
	return c, ok
}

// ListContacts returns all saved contacts with custom aliases.
func (m *Manager) ListContacts() []*Contact {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var list []*Contact
	for _, c := range m.Contacts {
		list = append(list, c)
	}
	return list
}

// GetOrCreateSession retrieves or creates a Double Ratchet session for a given peer contact.
func (m *Manager) GetOrCreateSession(peerFP [32]byte) (*protocol.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if s, ok := m.Sessions[peerFP]; ok {
		return s, nil
	}

	c, ok := m.Contacts[peerFP]
	if !ok {
		return nil, fmt.Errorf("manager: contact not found for fingerprint %x", peerFP[:8])
	}

	localId := m.Identities[m.ActiveProfile]
	s := protocol.NewSession(localId, c.PeerIdentity)
	m.Sessions[peerFP] = s
	return s, nil
}

// SendTextMessage encrypts and sends a text message to a contact over the selected mode (Relay or Direct P2P).
func (m *Manager) SendTextMessage(ctx context.Context, peerFP [32]byte, text string) (Message, error) {
	s, err := m.GetOrCreateSession(peerFP)
	if err != nil {
		return Message{}, err
	}

	dataPkt, err := s.EncryptMessage([]byte(text))
	if err != nil {
		return Message{}, fmt.Errorf("manager: encryption failed: %w", err)
	}

	rawBytes, err := dataPkt.Marshal()
	if err != nil {
		return Message{}, fmt.Errorf("manager: packet marshal failed: %w", err)
	}

	// Route based on Connection Mode
	m.mu.RLock()
	conn, hasConn := m.ActiveConns[peerFP]
	targetOnion := ""
	if c, ok := m.Contacts[peerFP]; ok {
		targetOnion = c.OnionAddress
	}
	mode := m.Mode
	relayAddr := m.RelayAddr
	m.mu.RUnlock()

	if !hasConn {
		var dialAddr string
		if mode == ModeRelay && relayAddr != "" {
			dialAddr = relayAddr
		} else if targetOnion != "" {
			dialAddr = targetOnion
		} else {
			return Message{}, fmt.Errorf("manager: no connection address available for peer %x", peerFP[:8])
		}

		newConn, err := m.OnionTransport.Dial(ctx, dialAddr)
		if err != nil {
			return Message{}, fmt.Errorf("manager: dial failed to %s: %w", dialAddr, err)
		}
		conn = newConn

		m.mu.Lock()
		m.ActiveConns[peerFP] = conn
		m.mu.Unlock()
	}

	if err := conn.SendPacket(rawBytes); err != nil {
		m.mu.Lock()
		delete(m.ActiveConns, peerFP)
		m.mu.Unlock()
		conn.Close()
		return Message{}, fmt.Errorf("manager: send failed: %w", err)
	}

	msg := m.AddMessage(peerFP, text, true, dataPkt.Sequence)
	return msg, nil
}

// AddMessage appends a message to a contact's history thread and triggers optional callback.
func (m *Manager) AddMessage(peerFP [32]byte, content string, isMe bool, seq uint64) Message {
	m.mu.Lock()
	msg := Message{
		ID:         fmt.Sprintf("%d-%d", time.Now().UnixNano(), seq),
		SenderFP:   hex.EncodeToString(peerFP[:]),
		SenderIsMe: isMe,
		Content:    content,
		Sequence:   seq,
		Timestamp:  time.Now(),
	}

	m.Messages[peerFP] = append(m.Messages[peerFP], msg)
	cb := m.onMessageFunc
	m.mu.Unlock()

	if cb != nil {
		cb(peerFP, msg)
	}

	return msg
}

// GetMessages returns the history for a given contact fingerprint.
func (m *Manager) GetMessages(peerFP [32]byte) []Message {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.Messages[peerFP]
}

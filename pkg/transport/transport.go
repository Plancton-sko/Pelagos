package transport

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// Transport defines the transport-agnostic networking interface for Palagos.
//
// Transport Independence Principle:
// Palagos cryptographic protocol operates entirely independently of the transport layer.
// Messages encrypted by the session layer can travel over TCP, Tor .onion sockets, Bluetooth RFCOMM,
// Wi-Fi Direct, or Store-and-Forward Mesh without altering key evolution, AEAD authentication, or replay protection.
type Transport interface {
	// Listen starts accepting incoming encrypted Palagos connections.
	Listen(ctx context.Context, address string) error
	// Dial connects to a remote peer address.
	Dial(ctx context.Context, address string) (Conn, error)
	// Accept waits for and returns the next incoming peer connection.
	Accept(ctx context.Context) (Conn, error)
	// Close shuts down the transport listener.
	Close() error
	// Addr returns the local listening address.
	Addr() string
}

// Conn represents an abstract framed binary connection.
type Conn interface {
	SendPacket(packet []byte) error
	ReceivePacket() ([]byte, error)
	RemoteAddr() string
	Close() error
}

// FramedConn wraps an underlying net.Conn with a 4-byte length-prefix framing protocol.
type FramedConn struct {
	conn net.Conn
}

// NewFramedConn creates a length-prefixed stream wrapper over net.Conn.
func NewFramedConn(c net.Conn) *FramedConn {
	return &FramedConn{conn: c}
}

// SendPacket writes a 4-byte big-endian uint32 payload length followed by the packet payload.
func (fc *FramedConn) SendPacket(packet []byte) error {
	if len(packet) > 10*1024*1024 {
		return fmt.Errorf("transport: packet size %d exceeds 10MB limit", len(packet))
	}
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(packet)))

	if _, err := fc.conn.Write(lenBuf); err != nil {
		return fmt.Errorf("transport: failed to write frame length: %w", err)
	}
	if _, err := fc.conn.Write(packet); err != nil {
		return fmt.Errorf("transport: failed to write frame payload: %w", err)
	}
	return nil
}

// ReceivePacket reads the 4-byte length header and reads the exact frame payload into memory.
func (fc *FramedConn) ReceivePacket() ([]byte, error) {
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(fc.conn, lenBuf); err != nil {
		return nil, fmt.Errorf("transport: failed to read frame length: %w", err)
	}
	payloadLen := binary.BigEndian.Uint32(lenBuf)
	if payloadLen > 10*1024*1024 {
		return nil, fmt.Errorf("transport: incoming packet frame size %d exceeds 10MB limit", payloadLen)
	}

	buf := make([]byte, payloadLen)
	if _, err := io.ReadFull(fc.conn, buf); err != nil {
		return nil, fmt.Errorf("transport: failed to read frame payload: %w", err)
	}
	return buf, nil
}

// RemoteAddr returns the remote network endpoint address string.
func (fc *FramedConn) RemoteAddr() string {
	return fc.conn.RemoteAddr().String()
}

// Close closes the underlying network connection.
func (fc *FramedConn) Close() error {
	return fc.conn.Close()
}

package transport

import (
	"context"
	"fmt"
	"net"
	"sync"
)

// TCPTransport provides standard IPv4/IPv6 TCP socket networking for Palagos.
type TCPTransport struct {
	mu       sync.Mutex
	listener net.Listener
}

// NewTCPTransport creates a new TCP transport.
func NewTCPTransport() *TCPTransport {
	return &TCPTransport{}
}

// Listen binds a local TCP address and starts listening for incoming peer connections.
func (t *TCPTransport) Listen(ctx context.Context, address string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	var lc net.ListenConfig
	l, err := lc.Listen(ctx, "tcp", address)
	if err != nil {
		return fmt.Errorf("tcp_transport: failed to listen on %s: %w", address, err)
	}
	t.listener = l
	return nil
}

// Dial connects to a remote TCP peer address.
func (t *TCPTransport) Dial(ctx context.Context, address string) (Conn, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("tcp_transport: failed to dial %s: %w", address, err)
	}
	return NewFramedConn(conn), nil
}

// Accept blocks until an incoming connection arrives on the TCP listener.
func (t *TCPTransport) Accept(ctx context.Context) (Conn, error) {
	t.mu.Lock()
	l := t.listener
	t.mu.Unlock()

	if l == nil {
		return nil, fmt.Errorf("tcp_transport: transport is not listening")
	}

	conn, err := l.Accept()
	if err != nil {
		return nil, fmt.Errorf("tcp_transport: accept error: %w", err)
	}
	return NewFramedConn(conn), nil
}

// Close closes the TCP listener socket.
func (t *TCPTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.listener != nil {
		return t.listener.Close()
	}
	return nil
}

// Addr returns the local TCP listening address string.
func (t *TCPTransport) Addr() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.listener != nil {
		return t.listener.Addr().String()
	}
	return ""
}

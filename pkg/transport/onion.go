package transport

import (
	"context"
	"fmt"
	"net"
	"sync"

	"golang.org/x/net/proxy"
)

// DefaultTorSOCKS5Proxy is the standard local port for Tor SOCKS5 proxy service.
const DefaultTorSOCKS5Proxy = "127.0.0.1:9050"

// OnionTransport routes Palagos peer-to-peer connections over the Tor overlay network using SOCKS5 proxying.
//
// Privacy Rationale & Tor .onion Mechanics:
// 1. IP & Location Anonymity: Tor routes traffic through 3 encrypted hops (Guard, Middle, Exit / Rendezvous).
//    Neither peer nor intermediate nodes can observe real IP addresses.
// 2. NAT & Firewall Traversal: Tor v3 Hidden Services (.onion addresses) allow peers behind strict home NATs,
//    CGNAT, or hostile cellular firewalls to accept incoming P2P connections without open ports or UPnP.
// 3. Metadata Protection: While Palagos encrypts content and header AAD, Tor obfuscates transport metadata
//    (sender IP, recipient IP, network topology).
type OnionTransport struct {
	mu            sync.Mutex
	socksProxyAddr string
	listener      net.Listener
	dialer        proxy.Dialer
}

// NewOnionTransport initializes a Tor SOCKS5 proxy transport.
// If socksAddr is empty, DefaultTorSOCKS5Proxy ("127.0.0.1:9050") is used.
func NewOnionTransport(socksAddr string) (*OnionTransport, error) {
	if socksAddr == "" {
		socksAddr = DefaultTorSOCKS5Proxy
	}

	dialer, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("onion_transport: failed to create SOCKS5 dialer for proxy %s: %w", socksAddr, err)
	}

	return &OnionTransport{
		socksProxyAddr: socksAddr,
		dialer:        dialer,
	}, nil
}

// Dial connects to a remote peer's .onion address (or standard address) via Tor SOCKS5 proxy.
func (ot *OnionTransport) Dial(ctx context.Context, address string) (Conn, error) {
	// Execute SOCKS5 dial. The SOCKS5 proxy resolves hostnames remotely, preventing DNS leaks.
	conn, err := ot.dialer.Dial("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("onion_transport: failed to dial .onion address %s via Tor proxy %s: %w", address, ot.socksProxyAddr, err)
	}
	return NewFramedConn(conn), nil
}

// Listen starts a local listener for Tor rendezvous connections.
func (ot *OnionTransport) Listen(ctx context.Context, address string) error {
	ot.mu.Lock()
	defer ot.mu.Unlock()

	var lc net.ListenConfig
	l, err := lc.Listen(ctx, "tcp", address)
	if err != nil {
		return fmt.Errorf("onion_transport: failed to open local onion listener on %s: %w", address, err)
	}
	ot.listener = l
	return nil
}

// Accept accepts incoming connections routed through Tor hidden service.
func (ot *OnionTransport) Accept(ctx context.Context) (Conn, error) {
	ot.mu.Lock()
	l := ot.listener
	ot.mu.Unlock()

	if l == nil {
		return nil, fmt.Errorf("onion_transport: listener is not active")
	}

	conn, err := l.Accept()
	if err != nil {
		return nil, fmt.Errorf("onion_transport: accept error: %w", err)
	}
	return NewFramedConn(conn), nil
}

// Close closes the Tor listener.
func (ot *OnionTransport) Close() error {
	ot.mu.Lock()
	defer ot.mu.Unlock()
	if ot.listener != nil {
		return ot.listener.Close()
	}
	return nil
}

// Addr returns the local listener address string.
func (ot *OnionTransport) Addr() string {
	ot.mu.Lock()
	defer ot.mu.Unlock()
	if ot.listener != nil {
		return ot.listener.Addr().String()
	}
	return ""
}

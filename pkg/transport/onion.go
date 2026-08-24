package transport

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"

	"golang.org/x/net/proxy"
)

// DefaultTorSOCKS5Proxy is the standard local port for Tor SOCKS5 proxy service.
const DefaultTorSOCKS5Proxy = "127.0.0.1:9050"

// DefaultTorControlPort is the standard local port for Tor Control protocol interactions.
const DefaultTorControlPort = "127.0.0.1:9051"

// OnionListener represents an active listener bound to an automated ephemeral Tor v3 hidden service.
type OnionListener struct {
	net.Listener
	ControlClient *TorControlClient
	ServiceInfo   *OnionServiceInfo
}

// OnionAddress returns the full generated .onion address string (e.g. xxxxx.onion:9090).
func (ol *OnionListener) OnionAddress() string {
	if ol.ServiceInfo != nil {
		return fmt.Sprintf("%s:%d", ol.ServiceInfo.OnionAddress, ol.ServiceInfo.VirtualPort)
	}
	return ol.Listener.Addr().String()
}

// Close teardowns the ephemeral hidden service via Tor Control Port and closes the socket listener.
func (ol *OnionListener) Close() error {
	var errs []string
	if ol.ControlClient != nil && ol.ServiceInfo != nil {
		if err := ol.ControlClient.DestroyEphemeralOnion(ol.ServiceInfo.ServiceID); err != nil {
			errs = append(errs, err.Error())
		}
		_ = ol.ControlClient.Close()
	}
	if ol.Listener != nil {
		if err := ol.Listener.Close(); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("onion listener close error: %s", strings.Join(errs, "; "))
	}
	return nil
}

// OnionTransport routes Palagos peer-to-peer connections over the Tor overlay network using SOCKS5 proxying and Control API.
type OnionTransport struct {
	mu             sync.Mutex
	socksProxyAddr string
	listener       net.Listener
	activeOnion    *OnionListener
	dialer         proxy.Dialer
}

// NewOnionTransport initializes a Tor SOCKS5 proxy transport.
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
		dialer:         dialer,
	}, nil
}

// Dial connects to a remote peer's .onion address via Tor SOCKS5 proxy.
func (ot *OnionTransport) Dial(ctx context.Context, address string) (Conn, error) {
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

// ProvisionEphemeralOnion connects to Tor Control Port, authenticates, and dynamically creates a v3 .onion hidden service.
func (ot *OnionTransport) ProvisionEphemeralOnion(ctx context.Context, controlAddr, password, cookiePath string, virtPort int, localTargetAddr string) (*OnionListener, error) {
	ot.mu.Lock()
	defer ot.mu.Unlock()

	if controlAddr == "" {
		controlAddr = DefaultTorControlPort
	}
	if virtPort <= 0 {
		virtPort = 9090
	}
	if localTargetAddr == "" {
		localTargetAddr = "127.0.0.1:0"
	}

	// 1. Start local TCP listener that will receive redirected Tor traffic
	var lc net.ListenConfig
	localListener, err := lc.Listen(ctx, "tcp", localTargetAddr)
	if err != nil {
		return nil, fmt.Errorf("onion_transport: failed binding local target listener: %w", err)
	}

	actualTarget := localListener.Addr().String()

	// 2. Connect and authenticate with Tor Control Port
	controlClient := NewTorControlClient(controlAddr)
	if err := controlClient.Connect(); err != nil {
		localListener.Close()
		return nil, err
	}

	if err := controlClient.Authenticate(password, cookiePath); err != nil {
		controlClient.Close()
		localListener.Close()
		return nil, fmt.Errorf("onion_transport: Tor Control authentication failed: %w", err)
	}

	// 3. Issue ADD_ONION command to Tor Control Port
	svcInfo, err := controlClient.CreateEphemeralOnion(virtPort, actualTarget, "")
	if err != nil {
		controlClient.Close()
		localListener.Close()
		return nil, err
	}

	onionListener := &OnionListener{
		Listener:      localListener,
		ControlClient: controlClient,
		ServiceInfo:   svcInfo,
	}

	ot.activeOnion = onionListener
	ot.listener = localListener
	return onionListener, nil
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

// Close closes the Tor listener and destroys any active ephemeral .onion service.
func (ot *OnionTransport) Close() error {
	ot.mu.Lock()
	defer ot.mu.Unlock()

	if ot.activeOnion != nil {
		err := ot.activeOnion.Close()
		ot.activeOnion = nil
		ot.listener = nil
		return err
	}

	if ot.listener != nil {
		err := ot.listener.Close()
		ot.listener = nil
		return err
	}
	return nil
}

// Addr returns the local listener or active .onion address string.
func (ot *OnionTransport) Addr() string {
	ot.mu.Lock()
	defer ot.mu.Unlock()

	if ot.activeOnion != nil {
		return ot.activeOnion.OnionAddress()
	}
	if ot.listener != nil {
		return ot.listener.Addr().String()
	}
	return ""
}

package transport

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// OnionServiceInfo holds details of a dynamically provisioned v3 Tor hidden service.
type OnionServiceInfo struct {
	ServiceID    string // 56-character v3 Service ID (without .onion suffix)
	OnionAddress string // Full address ending in .onion (e.g. xxxxx.onion)
	PrivateKey   string // ED25519-V3 private key blob for service persistence
	VirtualPort  int    // Virtual port exposed on the .onion address
	TargetAddr   string // Local listening address target (e.g. 127.0.0.1:8080)
}

// TorControlClient manages raw TCP interaction with the local Tor Control Port (default 127.0.0.1:9051).
type TorControlClient struct {
	mu          sync.Mutex
	conn        net.Conn
	reader      *bufio.Reader
	ControlAddr string
}

// NewTorControlClient creates an unauthenticated Tor Control client instance.
func NewTorControlClient(controlAddr string) *TorControlClient {
	if controlAddr == "" {
		controlAddr = "127.0.0.1:9051"
	}
	return &TorControlClient{
		ControlAddr: controlAddr,
	}
}

// Connect establishes TCP stream with the Tor Control Port.
func (c *TorControlClient) Connect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	conn, err := net.Dial("tcp", c.ControlAddr)
	if err != nil {
		return fmt.Errorf("tor control: failed connecting to control port %s: %w", c.ControlAddr, err)
	}

	c.conn = conn
	c.reader = bufio.NewReader(conn)
	return nil
}

// Authenticate attempts null auth, cookie auth, or password auth with the Tor Control Port.
func (c *TorControlClient) Authenticate(password string, customCookiePath string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return fmt.Errorf("tor control: not connected")
	}

	// Step 1: Try Null Authentication: AUTHENTICATE ""
	if err := c.sendCmd(`AUTHENTICATE ""`); err == nil {
		_, err := c.readResponse()
		if err == nil {
			return nil // Null authentication succeeded
		}
	}

	// Step 2: Try Cookie Authentication if cookie file exists
	cookiePaths := []string{}
	if customCookiePath != "" {
		cookiePaths = append(cookiePaths, customCookiePath)
	}
	homeDir, _ := os.UserHomeDir()
	cookiePaths = append(cookiePaths,
		"/var/lib/tor/control_auth_cookie",
		"/run/tor/control.authcookie",
		filepath.Join(homeDir, ".tor", "control_auth_cookie"),
	)

	for _, path := range cookiePaths {
		cookieBytes, err := os.ReadFile(path)
		if err == nil && len(cookieBytes) > 0 {
			hexCookie := hex.EncodeToString(cookieBytes)
			if err := c.sendCmd(fmt.Sprintf("AUTHENTICATE %s", hexCookie)); err == nil {
				_, err := c.readResponse()
				if err == nil {
					return nil // Cookie authentication succeeded
				}
			}
		}
	}

	// Step 3: Try Password Authentication
	if password != "" {
		if err := c.sendCmd(fmt.Sprintf(`AUTHENTICATE "%s"`, password)); err == nil {
			_, err := c.readResponse()
			if err == nil {
				return nil // Password authentication succeeded
			}
		}
	}

	return fmt.Errorf("tor control: authentication failed (null, cookie, and password all failed)")
}

// CreateEphemeralOnion sends ADD_ONION NEW:ED25519-V3 to provision a fresh v3 hidden service.
func (c *TorControlClient) CreateEphemeralOnion(virtPort int, targetAddr string, keyBlob string) (*OnionServiceInfo, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	keySpec := "NEW:ED25519-V3"
	if keyBlob != "" {
		keySpec = keyBlob
	}

	cmd := fmt.Sprintf("ADD_ONION %s Port=%d,%s", keySpec, virtPort, targetAddr)
	if err := c.sendCmd(cmd); err != nil {
		return nil, fmt.Errorf("tor control: failed sending ADD_ONION: %w", err)
	}

	lines, err := c.readResponse()
	if err != nil {
		return nil, fmt.Errorf("tor control: ADD_ONION rejected: %w", err)
	}

	info := &OnionServiceInfo{
		VirtualPort: virtPort,
		TargetAddr:  targetAddr,
	}

	for _, line := range lines {
		if strings.HasPrefix(line, "250-ServiceID=") {
			info.ServiceID = strings.TrimPrefix(line, "250-ServiceID=")
			info.OnionAddress = info.ServiceID + ".onion"
		} else if strings.HasPrefix(line, "250-PrivateKey=") {
			info.PrivateKey = strings.TrimPrefix(line, "250-PrivateKey=")
		}
	}

	if info.ServiceID == "" {
		return nil, fmt.Errorf("tor control: ADD_ONION response missing ServiceID")
	}

	return info, nil
}

// DestroyEphemeralOnion sends DEL_ONION <serviceID> to teardown an active hidden service.
func (c *TorControlClient) DestroyEphemeralOnion(serviceID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	cmd := fmt.Sprintf("DEL_ONION %s", serviceID)
	if err := c.sendCmd(cmd); err != nil {
		return err
	}

	_, err := c.readResponse()
	return err
}

// Close closes the TCP connection to the Control Port.
func (c *TorControlClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		_ = c.sendCmd("QUIT")
		err := c.conn.Close()
		c.conn = nil
		return err
	}
	return nil
}

func (c *TorControlClient) sendCmd(cmd string) error {
	if c.conn == nil {
		return fmt.Errorf("tor control: socket closed")
	}
	_, err := fmt.Fprintf(c.conn, "%s\r\n", cmd)
	return err
}

func (c *TorControlClient) readResponse() ([]string, error) {
	var lines []string
	for {
		line, err := c.reader.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("tor control: read error: %w", err)
		}

		line = strings.TrimRight(line, "\r\n")
		lines = append(lines, line)

		if strings.HasPrefix(line, "250 OK") || line == "250 OK" {
			return lines, nil
		}

		if strings.HasPrefix(line, "5") || strings.HasPrefix(line, "4") {
			return nil, fmt.Errorf("tor control command error: %s", line)
		}
	}
}

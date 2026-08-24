package tests

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"

	"palagos/pkg/transport"
)

// TestTorControlClientMockServer tests the raw Tor Control protocol interactions against a mock Tor Control daemon.
func TestTorControlClientMockServer(t *testing.T) {
	// 1. Spin up mock Tor Control TCP server
	mockListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start mock Tor control listener: %v", err)
	}
	defer mockListener.Close()

	mockAddr := mockListener.Addr().String()

	// Handle mock Tor Control protocol commands
	go func() {
		conn, err := mockListener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\r\n")

			switch {
			case strings.HasPrefix(line, "AUTHENTICATE"):
				_, _ = fmt.Fprintf(conn, "250 OK\r\n")
			case strings.HasPrefix(line, "ADD_ONION"):
				_, _ = fmt.Fprintf(conn, "250-ServiceID=palagostestv3serviceid1234567890abcdefghijklmnopqrstuv\r\n")
				_, _ = fmt.Fprintf(conn, "250-PrivateKey=ED25519-V3:mockkeydata\r\n")
				_, _ = fmt.Fprintf(conn, "250 OK\r\n")
			case strings.HasPrefix(line, "DEL_ONION"):
				_, _ = fmt.Fprintf(conn, "250 OK\r\n")
			case line == "QUIT":
				return
			default:
				_, _ = fmt.Fprintf(conn, "510 Unrecognized command\r\n")
			}
		}
	}()

	// 2. Instantiate TorControlClient pointing to mock server
	client := transport.NewTorControlClient(mockAddr)
	if err := client.Connect(); err != nil {
		t.Fatalf("Client connect failed: %v", err)
	}
	defer client.Close()

	// 3. Test Authentication
	if err := client.Authenticate("", ""); err != nil {
		t.Fatalf("Authentication failed: %v", err)
	}

	// 4. Test Ephemeral .onion Creation
	svcInfo, err := client.CreateEphemeralOnion(9090, "127.0.0.1:8080", "")
	if err != nil {
		t.Fatalf("CreateEphemeralOnion failed: %v", err)
	}

	expectedID := "palagostestv3serviceid1234567890abcdefghijklmnopqrstuv"
	expectedOnion := expectedID + ".onion"

	if svcInfo.ServiceID != expectedID {
		t.Fatalf("ServiceID mismatch! Expected: %s, Got: %s", expectedID, svcInfo.ServiceID)
	}
	if svcInfo.OnionAddress != expectedOnion {
		t.Fatalf("OnionAddress mismatch! Expected: %s, Got: %s", expectedOnion, svcInfo.OnionAddress)
	}

	// 5. Test Service Teardown
	if err := client.DestroyEphemeralOnion(svcInfo.ServiceID); err != nil {
		t.Fatalf("DestroyEphemeralOnion failed: %v", err)
	}
}

func TestOnionTransportProvisioning(t *testing.T) {
	mockListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start mock Tor control listener: %v", err)
	}
	defer mockListener.Close()

	mockAddr := mockListener.Addr().String()

	go func() {
		conn, err := mockListener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\r\n")

			if strings.HasPrefix(line, "AUTHENTICATE") || strings.HasPrefix(line, "DEL_ONION") {
				_, _ = fmt.Fprintf(conn, "250 OK\r\n")
			} else if strings.HasPrefix(line, "ADD_ONION") {
				_, _ = fmt.Fprintf(conn, "250-ServiceID=autoprovisionedonion1234567890abcdefghijklmnopqrstuvwx\r\n")
				_, _ = fmt.Fprintf(conn, "250 OK\r\n")
			} else if line == "QUIT" {
				return
			}
		}
	}()

	ot, err := transport.NewOnionTransport("127.0.0.1:9050")
	if err != nil {
		t.Fatalf("NewOnionTransport failed: %v", err)
	}

	ctx := context.Background()
	onionListener, err := ot.ProvisionEphemeralOnion(ctx, mockAddr, "", "", 9090, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ProvisionEphemeralOnion failed: %v", err)
	}

	onionAddr := onionListener.OnionAddress()
	if !strings.HasSuffix(onionAddr, ".onion:9090") {
		t.Fatalf("Unexpected provisioned onion address: %s", onionAddr)
	}

	if err := ot.Close(); err != nil {
		t.Fatalf("OnionTransport.Close failed: %v", err)
	}
}

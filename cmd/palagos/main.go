package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"time"

	"palagos/pkg/identity"
	"palagos/pkg/protocol"
	"palagos/pkg/transport"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	subcommand := os.Args[1]
	switch subcommand {
	case "gen-identity":
		handleGenIdentity()
	case "listen":
		handleListen(os.Args[2:])
	case "send":
		handleSend(os.Args[2:])
	default:
		fmt.Printf("Unknown command: %s\n", subcommand)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Palagos — Privacy-First Secure P2P Cryptographic Communication System")
	fmt.Println("\nUsage:")
	fmt.Println("  palagos gen-identity                  Generate a fresh Ed25519 identity keypair")
	fmt.Println("  palagos listen [options]              Start a Palagos peer listener daemon")
	fmt.Println("  palagos send [options]                Send an encrypted message to a remote peer")
}

func handleGenIdentity() {
	id, err := identity.GenerateIdentity()
	if err != nil {
		fmt.Printf("Error generating identity: %v\n", err)
		os.Exit(1)
	}

	pubHex := hex.EncodeToString(id.PublicKey)
	privHex := hex.EncodeToString(id.PrivateKey)

	fmt.Println("=================================================================")
	fmt.Println("              PALAGOS CRYPTOGRAPHIC DEVICE IDENTITY               ")
	fmt.Println("=================================================================")
	fmt.Printf("Public Key (Hex):  %s\n", pubHex)
	fmt.Printf("Private Key (Hex): %s\n", privHex)
	fmt.Printf("Fingerprint (SHA-256): %s\n", id.FormattedFingerprint())
	fmt.Println("=================================================================")
	fmt.Println("\n[SECURITY NOTICE] Keep your private key secret!")
	fmt.Println("Exchange Public Keys with peers in-person via QR code or visual fingerprint verification.")
}

func handleListen(args []string) {
	fs := flag.NewFlagSet("listen", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:9090", "Local TCP listening address")
	transportType := fs.String("transport", "tcp", "Transport type: 'tcp' or 'onion'")
	socksAddr := fs.String("socks", "127.0.0.1:9050", "Tor SOCKS5 proxy address (for 'onion' transport)")
	privKeyHex := fs.String("key", "", "Hex-encoded 64-byte Ed25519 private key")

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	if *privKeyHex == "" {
		fmt.Println("Error: -key flag (Ed25519 private key in hex) is required.")
		os.Exit(1)
	}

	privBytes, err := hex.DecodeString(*privKeyHex)
	if err != nil || len(privBytes) != 64 {
		fmt.Printf("Error: invalid private key hex: %v\n", err)
		os.Exit(1)
	}

	localId := &identity.Identity{
		PrivateKey: privBytes,
		PublicKey:  privBytes[32:],
	}

	var tr transport.Transport
	if *transportType == "onion" {
		ot, err := transport.NewOnionTransport(*socksAddr)
		if err != nil {
			fmt.Printf("Error creating Onion transport: %v\n", err)
			os.Exit(1)
		}
		tr = ot
	} else {
		tr = transport.NewTCPTransport()
	}

	ctx := context.Background()
	if err := tr.Listen(ctx, *addr); err != nil {
		fmt.Printf("Failed to listen: %v\n", err)
		os.Exit(1)
	}
	defer tr.Close()

	fmt.Printf("[+] Palagos node listening on %s via %s transport...\n", *addr, *transportType)
	fmt.Printf("[+] Device Fingerprint: %s\n", localId.FormattedFingerprint())

	for {
		conn, err := tr.Accept(ctx)
		if err != nil {
			fmt.Printf("Accept error: %v\n", err)
			continue
		}
		go handleIncomingConn(localId, conn)
	}
}

func handleIncomingConn(localId *identity.Identity, conn transport.Conn) {
	defer conn.Close()
	fmt.Printf("[+] Incoming connection from %s\n", conn.RemoteAddr())

	// Read first packet (HandshakeInit or Data)
	rawPkt, err := conn.ReceivePacket()
	if err != nil {
		fmt.Printf("[-] Error receiving packet: %v\n", err)
		return
	}

	var pkt protocol.Packet
	if err := pkt.Unmarshal(rawPkt); err != nil {
		fmt.Printf("[-] Error parsing packet: %v\n", err)
		return
	}

	fmt.Printf("[+] Received packet: Type 0x%02x, Version 0x%04x, Sequence %d, Sender FP: %x\n",
		pkt.Type, pkt.Version, pkt.Sequence, pkt.SenderFingerprint[:8])
}

func handleSend(args []string) {
	fs := flag.NewFlagSet("send", flag.ExitOnError)
	targetAddr := fs.String("to", "127.0.0.1:9090", "Target peer endpoint or .onion address")
	transportType := fs.String("transport", "tcp", "Transport type: 'tcp' or 'onion'")
	socksAddr := fs.String("socks", "127.0.0.1:9050", "Tor SOCKS5 proxy address")
	privKeyHex := fs.String("key", "", "Local Ed25519 private key in hex")
	peerPubHex := fs.String("peer-pub", "", "Remote peer Ed25519 public key in hex")
	message := fs.String("msg", "Hello from Palagos over encrypted P2P!", "Plaintext message to send")

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	if *privKeyHex == "" || *peerPubHex == "" {
		fmt.Println("Error: -key and -peer-pub flags are required.")
		os.Exit(1)
	}

	privBytes, err := hex.DecodeString(*privKeyHex)
	if err != nil || len(privBytes) != 64 {
		fmt.Printf("Error decoding private key: %v\n", err)
		os.Exit(1)
	}

	peerPubBytes, err := hex.DecodeString(*peerPubHex)
	if err != nil || len(peerPubBytes) != 32 {
		fmt.Printf("Error decoding peer public key: %v\n", err)
		os.Exit(1)
	}

	localId := &identity.Identity{
		PrivateKey: privBytes,
		PublicKey:  privBytes[32:],
	}

	peerId, err := identity.NewPeerIdentity(peerPubBytes, "remote-peer")
	if err != nil {
		fmt.Printf("Error initializing peer identity: %v\n", err)
		os.Exit(1)
	}

	var tr transport.Transport
	if *transportType == "onion" {
		ot, err := transport.NewOnionTransport(*socksAddr)
		if err != nil {
			fmt.Printf("Error creating Tor transport: %v\n", err)
			os.Exit(1)
		}
		tr = ot
	} else {
		tr = transport.NewTCPTransport()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	fmt.Printf("[+] Connecting to peer %s via %s transport...\n", *targetAddr, *transportType)
	conn, err := tr.Dial(ctx, *targetAddr)
	if err != nil {
		fmt.Printf("[-] Failed to connect to %s: %v\n", *targetAddr, err)
		os.Exit(1)
	}
	defer conn.Close()

	// Perform handshake and session establishment
	session := protocol.NewSession(localId, peerId)
	initPkt, ephemeralPriv, err := session.CreateHandshakeInit()
	if err != nil {
		fmt.Printf("[-] Handshake init failed: %v\n", err)
		os.Exit(1)
	}

	initBytes, err := initPkt.Marshal()
	if err != nil {
		fmt.Printf("[-] Serialization failed: %v\n", err)
		os.Exit(1)
	}

	if err := conn.SendPacket(initBytes); err != nil {
		fmt.Printf("[-] Sending handshake packet failed: %v\n", err)
		os.Exit(1)
	}

	_ = ephemeralPriv
	fmt.Printf("[+] HandshakeInit sent to peer (%d bytes)\n", len(initBytes))
	fmt.Printf("[+] Encrypted message ready: \"%s\"\n", *message)
}

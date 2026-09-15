package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"palagos/pkg/client"
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
	case "pair-create":
		handlePairCreate(os.Args[2:])
	case "pair-open":
		handlePairOpen(os.Args[2:])
	case "ui":
		handleUI(os.Args[2:])
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
	fmt.Println("  palagos pair-create [options]         Create a PIN-encrypted pairing payload (Camera-free key exchange)")
	fmt.Println("  palagos pair-open [options]           Open a PIN-encrypted pairing payload and generate 6-digit SAS code")
	fmt.Println("  palagos ui [options]                  Launch embedded Midnight Blue Web UI server")
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
	addr := fs.String("addr", "127.0.0.1:9090", "Local listening address / MAC address")
	transportType := fs.String("transport", "onion", "Transport type: 'onion' or 'bluetooth'")
	socksAddr := fs.String("socks", "127.0.0.1:9050", "Tor SOCKS5 proxy address (for 'onion' transport)")
	privKeyHex := fs.String("key", "", "Hex-encoded 64-byte Ed25519 private key")
	peerPubHex := fs.String("peer-pub", "", "Remote peer Ed25519 public key in hex (for session establishment)")

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

	// Peer identity is optional for listen mode (can be set after handshake)
	var peerId *identity.PeerIdentity
	if *peerPubHex != "" {
		peerPubBytes, err := hex.DecodeString(*peerPubHex)
		if err != nil || len(peerPubBytes) != 32 {
			fmt.Printf("Error: invalid peer public key hex: %v\n", err)
			os.Exit(1)
		}
		peerId, err = identity.NewPeerIdentity(peerPubBytes, "remote-peer")
		if err != nil {
			fmt.Printf("Error creating peer identity: %v\n", err)
			os.Exit(1)
		}
	}

	var tr transport.Transport
	switch *transportType {
	case "onion":
		ot, err := transport.NewOnionTransport(*socksAddr)
		if err != nil {
			fmt.Printf("Error creating Onion transport: %v\n", err)
			os.Exit(1)
		}
		tr = ot
	case "bluetooth":
		tr = transport.NewBluetoothTransport(*addr)
	default:
		fmt.Printf("Error: unsupported transport type '%s'. Supported types: 'onion', 'bluetooth'\n", *transportType)
		os.Exit(1)
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
		go handleIncomingConn(localId, peerId, conn)
	}
}

// handleIncomingConn performs the full handshake as responder (Bob) and then
// receives and decrypts incoming messages, printing each to stdout.
func handleIncomingConn(localId *identity.Identity, peerId *identity.PeerIdentity, conn transport.Conn) {
	defer conn.Close()
	fmt.Printf("[+] Incoming connection from %s\n", conn.RemoteAddr())

	// 1. Read HandshakeInit
	rawInit, err := conn.ReceivePacket()
	if err != nil {
		fmt.Printf("[-] Error receiving HandshakeInit: %v\n", err)
		return
	}

	var initPkt protocol.Packet
	if err := initPkt.Unmarshal(rawInit); err != nil {
		fmt.Printf("[-] Error parsing HandshakeInit: %v\n", err)
		return
	}

	if initPkt.Type != 0x01 { // MessageTypeHandshakeInit
		fmt.Printf("[-] Expected HandshakeInit, got type 0x%02x\n", initPkt.Type)
		return
	}

	// If no peer identity was configured ahead of time, derive it from the packet's SenderFingerprint.
	// NOTE: This accepts any peer. For production, always pass -peer-pub for pinned verification.
	if peerId == nil {
		fmt.Printf("[!] Warning: no peer identity pinned (-peer-pub). Accepting anonymous peer FP: %x\n", initPkt.SenderFingerprint[:8])
		peerId = &identity.PeerIdentity{PublicKey: initPkt.Payload[:32]}
	}

	// 2. Process HandshakeInit -> produce HandshakeResp
	session := protocol.NewSession(localId, peerId)
	respPkt, err := session.ProcessHandshakeInit(&initPkt)
	if err != nil {
		fmt.Printf("[-] HandshakeInit processing failed: %v\n", err)
		return
	}

	respBytes, err := respPkt.Marshal()
	if err != nil {
		fmt.Printf("[-] Failed to marshal HandshakeResp: %v\n", err)
		return
	}

	if err := conn.SendPacket(respBytes); err != nil {
		fmt.Printf("[-] Failed to send HandshakeResp: %v\n", err)
		return
	}

	fmt.Printf("[+] Session established with %x\n", initPkt.SenderFingerprint[:8])

	// 3. Receive loop: decrypt and print incoming data messages
	for {
		rawData, err := conn.ReceivePacket()
		if err != nil {
			fmt.Printf("[-] Connection closed: %v\n", err)
			return
		}

		var dataPkt protocol.Packet
		if err := dataPkt.Unmarshal(rawData); err != nil {
			fmt.Printf("[-] Error parsing data packet: %v\n", err)
			continue
		}

		plaintext, err := session.DecryptMessage(&dataPkt)
		if err != nil {
			fmt.Printf("[-] Decryption failed (seq=%d): %v\n", dataPkt.Sequence, err)
			continue
		}

		fmt.Printf("[MSG seq=%d] %s\n", dataPkt.Sequence, string(plaintext))
	}
}

func handleSend(args []string) {
	fs := flag.NewFlagSet("send", flag.ExitOnError)
	targetAddr := fs.String("to", "127.0.0.1:9090", "Target peer endpoint, .onion address, or Bluetooth MAC")
	transportType := fs.String("transport", "onion", "Transport type: 'onion' or 'bluetooth'")
	socksAddr := fs.String("socks", "127.0.0.1:9050", "Tor SOCKS5 proxy address")
	privKeyHex := fs.String("key", "", "Local Ed25519 private key in hex")
	peerPubHex := fs.String("peer-pub", "", "Remote peer Ed25519 public key in hex")
	message := fs.String("msg", "", "Single plaintext message to send (omit for interactive stdin mode)")

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
	switch *transportType {
	case "onion":
		ot, err := transport.NewOnionTransport(*socksAddr)
		if err != nil {
			fmt.Printf("Error creating Tor transport: %v\n", err)
			os.Exit(1)
		}
		tr = ot
	case "bluetooth":
		tr = transport.NewBluetoothTransport(*targetAddr)
	default:
		fmt.Printf("Error: unsupported transport type '%s'. Supported types: 'onion', 'bluetooth'\n", *transportType)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	fmt.Printf("[+] Connecting to peer %s via %s transport...\n", *targetAddr, *transportType)
	conn, err := tr.Dial(ctx, *targetAddr)
	if err != nil {
		fmt.Printf("[-] Failed to connect to %s: %v\n", *targetAddr, err)
		os.Exit(1)
	}
	defer conn.Close()

	// 1. Perform handshake as initiator (Alice)
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
		fmt.Printf("[-] Sending HandshakeInit failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[+] HandshakeInit sent (%d bytes). Waiting for response...\n", len(initBytes))

	// 2. Receive and process HandshakeResp
	rawResp, err := conn.ReceivePacket()
	if err != nil {
		fmt.Printf("[-] Failed to receive HandshakeResp: %v\n", err)
		os.Exit(1)
	}

	var respPkt protocol.Packet
	if err := respPkt.Unmarshal(rawResp); err != nil {
		fmt.Printf("[-] Failed to parse HandshakeResp: %v\n", err)
		os.Exit(1)
	}

	if err := session.CompleteInitiatorHandshake(&respPkt, ephemeralPriv); err != nil {
		fmt.Printf("[-] Handshake completion failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[+] Secure session established with %x\n", respPkt.SenderFingerprint[:8])

	// 3a. Single-shot mode: -msg flag provided
	if *message != "" {
		sendEncryptedMessage(session, conn, *message)
		return
	}

	// 3b. Interactive stdin mode: read lines and send each as an encrypted message
	fmt.Println("[+] Interactive mode. Type messages and press Enter to send. Ctrl+C to quit.")
	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("> ")
		if !scanner.Scan() {
			break
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		sendEncryptedMessage(session, conn, line)
	}
}

// sendEncryptedMessage encrypts and sends a single plaintext message over the established session.
func sendEncryptedMessage(session *protocol.Session, conn transport.Conn, plaintext string) {
	dataPkt, err := session.EncryptMessage([]byte(plaintext))
	if err != nil {
		fmt.Printf("[-] Encryption failed: %v\n", err)
		return
	}

	dataBytes, err := dataPkt.Marshal()
	if err != nil {
		fmt.Printf("[-] Serialization failed: %v\n", err)
		return
	}

	if err := conn.SendPacket(dataBytes); err != nil {
		fmt.Printf("[-] Send failed: %v\n", err)
		return
	}

	fmt.Printf("[+] Sent (seq=%d, %d bytes encrypted)\n", dataPkt.Sequence, len(dataBytes))
}

func handlePairCreate(args []string) {
	fs := flag.NewFlagSet("pair-create", flag.ExitOnError)
	privKeyHex := fs.String("key", "", "Local Ed25519 private key in hex")
	pin := fs.String("pin", "", "Agreed 4 to 6-digit PIN for presential pairing")
	alias := fs.String("alias", "MyDevice", "Local device alias")

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	if *privKeyHex == "" || *pin == "" {
		fmt.Println("Error: -key and -pin flags are required.")
		os.Exit(1)
	}

	privBytes, err := hex.DecodeString(*privKeyHex)
	if err != nil || len(privBytes) != 64 {
		fmt.Printf("Error decoding private key: %v\n", err)
		os.Exit(1)
	}

	localId := &identity.Identity{
		PrivateKey: privBytes,
		PublicKey:  privBytes[32:],
	}

	payload, err := identity.CreatePairingPayload(localId, *alias, *pin)
	if err != nil {
		fmt.Printf("Error creating pairing payload: %v\n", err)
		os.Exit(1)
	}

	rawBytes := payload.Marshal()
	payloadHex := hex.EncodeToString(rawBytes)

	fmt.Println("=================================================================")
	fmt.Println("         		PALAGOS PRESENTIAL PAIRING PAYLOAD 		   	      ")
	fmt.Println("=================================================================")
	fmt.Printf("Device Fingerprint: %s\n", localId.FormattedFingerprint())
	fmt.Printf("Device Alias:       %s\n", *alias)
	fmt.Printf("Shared PIN:         %s\n", *pin)
	fmt.Println("-----------------------------------------------------------------")
	fmt.Println("Pairing Payload (Hex):")
	fmt.Println(payloadHex)
	fmt.Println("=================================================================")
	fmt.Println("\nTransmit this payload over Bluetooth or local channel to your peer.")
}

func handlePairOpen(args []string) {
	fs := flag.NewFlagSet("pair-open", flag.ExitOnError)
	privKeyHex := fs.String("key", "", "Local Ed25519 private key in hex")
	pin := fs.String("pin", "", "Agreed 4 to 6-digit PIN for presential pairing")
	payloadHex := fs.String("payload", "", "Hex-encoded pairing payload received from peer")

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	if *privKeyHex == "" || *pin == "" || *payloadHex == "" {
		fmt.Println("Error: -key, -pin, and -payload flags are required.")
		os.Exit(1)
	}

	privBytes, err := hex.DecodeString(*privKeyHex)
	if err != nil || len(privBytes) != 64 {
		fmt.Printf("Error decoding private key: %v\n", err)
		os.Exit(1)
	}

	localId := &identity.Identity{
		PrivateKey: privBytes,
		PublicKey:  privBytes[32:],
	}

	rawBytes, err := hex.DecodeString(*payloadHex)
	if err != nil {
		fmt.Printf("Error decoding payload hex: %v\n", err)
		os.Exit(1)
	}

	payload, err := identity.UnmarshalPairingPayload(rawBytes)
	if err != nil {
		fmt.Printf("Error parsing pairing payload: %v\n", err)
		os.Exit(1)
	}

	peerId, sasCode, err := identity.OpenPairingPayload(payload, localId, *pin)
	if err != nil {
		fmt.Printf("[-] Pairing failed: %v\n", err)
		os.Exit(1)
	}

	peerPubHex := hex.EncodeToString(peerId.PublicKey)

	fmt.Println("=================================================================")
	fmt.Println("         		PALAGOS PRESENTIAL PAIRING SUCCESS     		      ")
	fmt.Println("=================================================================")
	fmt.Printf("Peer Device Alias:   %s\n", peerId.Alias)
	fmt.Printf("Peer Public Key Hex: %s\n", peerPubHex)
	fmt.Printf("Peer Fingerprint:    %s\n", peerId.FormattedFingerprint())
	fmt.Println("-----------------------------------------------------------------")
	fmt.Printf("SAS CONFIRMATION CODE:  [ %s ]\n", sasCode)
	fmt.Println("=================================================================")
	fmt.Println("\n[SECURITY VERIFICATION] Confirm that the 6-digit SAS code matches on both screens!")
}

func handleUI(args []string) {
	fs := flag.NewFlagSet("ui", flag.ExitOnError)
	port := fs.String("port", "4040", "HTTP port for local Web UI server")
	socksAddr := fs.String("socks", "127.0.0.1:9050", "Tor SOCKS5 proxy address")

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	mgr, err := client.NewManager(*socksAddr)
	if err != nil {
		fmt.Printf("Error starting client manager: %v\n", err)
		os.Exit(1)
	}

	listenAddr := fmt.Sprintf("127.0.0.1:%s", *port)
	server := client.NewWebServer(mgr, listenAddr)

	fmt.Println("=================================================================")
	fmt.Println("           PALAGOS EMBEDDED WEB UI (DISCORD & TELEGRAM STYLE)   ")
	fmt.Println("=================================================================")
	fmt.Printf("Web Interface URL:  http://%s\n", listenAddr)
	fmt.Printf("Tor SOCKS5 Proxy:  %s\n", *socksAddr)
	fmt.Println("=================================================================")

	if err := server.Start(); err != nil {
		fmt.Printf("Web UI server error: %v\n", err)
		os.Exit(1)
	}
}



package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"palagos/pkg/server"
	"palagos/pkg/transport"
)

func main() {
	addr := flag.String("addr", "0.0.0.0:8080", "Server listening address")
	transportType := flag.String("transport", "tcp", "Transport type: 'tcp' or 'onion'")
	socksAddr := flag.String("socks", "127.0.0.1:9050", "Tor SOCKS5 proxy address")
	torControlAddr := flag.String("tor-control", "127.0.0.1:9051", "Tor Control Port address for automated .onion creation")
	torPass := flag.String("tor-pass", "", "Tor Control Port authentication password")
	torCookie := flag.String("tor-cookie", "", "Tor Control Port cookie file path")
	flag.Parse()

	srv, err := server.NewServer()
	if err != nil {
		fmt.Printf("Error creating Palagos server: %v\n", err)
		os.Exit(1)
	}

	pubHex := hex.EncodeToString(srv.ServerId.PublicKey)
	fp := srv.ServerId.FormattedFingerprint()

	fmt.Println("=================================================================")
	fmt.Println("             PALAGOS ZERO-TRUST RELAY SERVER DAEMON              ")
	fmt.Println("=================================================================")
	fmt.Printf("Server Public Key (Hex):  %s\n", pubHex)
	fmt.Printf("Server Identity FP:       %s\n", fp)
	fmt.Printf("Listening Address:        %s\n", *addr)
	fmt.Printf("Transport Engine:         %s\n", *transportType)

	var tr transport.Transport
	var onionListener *transport.OnionListener

	ctx := context.Background()

	if *transportType == "onion" {
		ot, err := transport.NewOnionTransport(*socksAddr)
		if err != nil {
			fmt.Printf("Error initializing Tor transport: %v\n", err)
			os.Exit(1)
		}

		// Attempt automated ephemeral .onion service creation via Tor Control Port
		onionListener, err = ot.ProvisionEphemeralOnion(ctx, *torControlAddr, *torPass, *torCookie, 9090, *addr)
		if err != nil {
			fmt.Printf("[!] Warning: Tor Control Port provisioning failed (%v). Falling back to direct socket listener on %s\n", err, *addr)
			if err := ot.Listen(ctx, *addr); err != nil {
				fmt.Printf("Failed to bind server listener: %v\n", err)
				os.Exit(1)
			}
		} else {
			fmt.Printf("Automated v3 .onion Address: %s\n", onionListener.OnionAddress())
		}
		tr = ot
	} else {
		tr = transport.NewTCPTransport()
		if err := tr.Listen(ctx, *addr); err != nil {
			fmt.Printf("Failed to bind server listener: %v\n", err)
			os.Exit(1)
		}
	}
	defer tr.Close()

	fmt.Println("=================================================================")
	fmt.Println("\n[ZERO-TRUST GUARANTEE] Server operates strictly as a store-and-forward relay.")
	fmt.Println("Zero visibility into message plaintexts; zero capability to forge/tamper packet headers.")

	for {
		conn, err := tr.Accept(ctx)
		if err != nil {
			fmt.Printf("Accept error: %v\n", err)
			continue
		}
		go handleClient(srv, conn)
	}
}

func handleClient(srv *server.Server, conn transport.Conn) {
	defer conn.Close()
	fmt.Printf("[+] Client connected from %s\n", conn.RemoteAddr())

	clientFP, err := srv.AuthenticateClient(conn)
	if err != nil {
		fmt.Printf("[-] Authentication failed for %s: %v\n", conn.RemoteAddr(), err)
		return
	}
	fmt.Printf("[+] Client authenticated: FP %x\n", clientFP[:8])

	// Flush pending offline mailbox
	if err := srv.DeliverMailbox(clientFP, conn); err != nil {
		fmt.Printf("[-] Mailbox delivery error: %v\n", err)
	}

	// Main packet routing loop
	for {
		rawPkt, err := conn.ReceivePacket()
		if err != nil {
			fmt.Printf("[-] Connection closed by client %x\n", clientFP[:8])
			break
		}
		if err := srv.RoutePacket(rawPkt); err != nil {
			fmt.Printf("[-] Packet routing error: %v\n", err)
		} else {
			fmt.Printf("[+] Routed packet (%d bytes)\n", len(rawPkt))
		}
	}
}

# ADR 0003: Tor .onion SOCKS5 Proxy Transport Integration

## Context & Problem Statement
Standard IPv4/IPv6 TCP socket networking leaks physical IP addresses, geographic location, and network topology to passive network observers and relay servers. Furthermore, peers behind strict home NATs or hostile cellular firewalls cannot accept incoming direct P2P connections.

## Decision
We implement `OnionTransport` wrapping `golang.org/x/net/proxy` SOCKS5 proxy dialers (`127.0.0.1:9050`). The transport layer resolves `.onion` hostnames remotely over the Tor network.

## Consequences
- **Positive**:
  - Hides IP addresses, location metadata, and routing topology from passive network observers.
  - Bypasses NATs, CGNATs, and strict cellular firewalls via Tor v3 Hidden Service rendezvous sockets.
  - Full transport independence: The underlying Double Ratchet crypto protocol remains 100% unchanged.
- **Negative**:
  - Requires a running local Tor daemon or Tor SOCKS5 proxy service.
  - Higher initial connection latency compared to direct LAN TCP sockets.

# ADR 0003: Tor .onion SOCKS5 Proxy & Control Port Integration

## Context & Problem Statement
Standard IPv4/IPv6 TCP socket networking leaks physical IP addresses, geographic location, and network topology to passive network observers and relay servers. Furthermore, peers behind strict home NATs or hostile cellular firewalls cannot accept incoming direct P2P connections without complex router configuration or UPnP.

## Decision
1. **SOCKS5 Outbound Proxy**: We implement `OnionTransport` wrapping `golang.org/x/net/proxy` SOCKS5 proxy dialers (`127.0.0.1:9050`). The transport layer resolves `.onion` hostnames remotely over the Tor network to prevent DNS leaks.
2. **Native Tor Control Port Client**: We implement `TorControlClient` in `pkg/transport/tor_control.go` communicating over TCP with the local Tor Control Port (`127.0.0.1:9051`).
   - Supports **Null Authentication**, **Cookie Authentication**, and **Password Authentication**.
   - Issues `ADD_ONION NEW:ED25519-V3 Port=<virtPort>,<targetAddr>` to dynamically provision ephemeral v3 `.onion` hidden services (`<56-char>.onion`) on daemon startup.
   - Issues `DEL_ONION <serviceID>` to cleanly teardown the hidden service on shutdown.

## Consequences
- **Positive**:
  - Zero external third-party Go dependencies required (100% standard library Go implementation).
  - Hides IP addresses, location metadata, and routing topology from passive network observers.
  - Bypasses NATs, CGNATs, and strict cellular firewalls via Tor v3 Hidden Service rendezvous sockets without manual `/etc/tor/torrc` edits.
  - Full transport independence: The underlying Double Ratchet crypto protocol remains 100% unchanged.
- **Negative**:
  - Requires a running local Tor daemon with Control Port enabled (`ControlPort 9051`).

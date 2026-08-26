# Palagos — Secure P2P Cryptographic Communication Protocol

> *"Two people who have established trust should be able to communicate securely even if the infrastructure between them is hostile, compromised, monitored, censored, or completely controlled by an adversary."*

Palagos is a privacy-first, peer-to-peer cryptographic communication system engineered in Go. It serves as an **auditable, educational cryptographic and protocol engineering reference** built around zero-trust transport, key evolution (Double Ratchet), authenticated encryption (ChaCha20-Poly1305), identity verification (Ed25519), and transport independence (including Tor `.onion` overlay sockets).

---

## Quick Navigation

- 🚀 [Quick Start & Installation](#-quick-start--installation)
- ⚙️ [How It Works](#️-how-it-works)
- 📁 [Project Layout](#-project-layout)
- 💻 [CLI Operating Guide](#-cli-operating-guide)
- 📐 [Mathematical Foundations (`docs/math.md`)](docs/math.md)
- 📚 [Documentation Index](#-documentation-index)
- 🧪 [Build & Test Suite](#-build--test-suite)

---

## 🚀 Quick Start & Installation

### Prerequisites
- **Go**: Version 1.20 or later installed.
- **Git**: For cloning the repository.

### 1. Clone & Build
```bash
git clone https://github.com/Plancton-sko/Pelagos.git
cd Pelagos

# Build client and server binaries into bin/
mkdir -p bin
go build -o bin/palagos ./cmd/palagos
go build -o bin/palagos-server ./cmd/palagos-server
```

### 2. Generate Cryptographic Identity
```bash
./bin/palagos gen-identity
```

### 3. Start Zero-Trust Relay Server
```bash
./bin/palagos-server -addr 0.0.0.0:8080 -transport tcp
```

---

## ⚙️ How It Works

Palagos cryptographically decouples peer identities, session ratchets, binary packet framing, and network socket transports into independent operational layers.

```text
+-----------------------------------------------------------------------+
|                       Application / User Interface                     |
+-----------------------------------------------------------------------+
                                   |
                                   v
+-----------------------------------------------------------------------+
|                           Identity Layer                              |
|   - Long-Term Ed25519 Device Keys                                     |
|   - SHA-256 Fingerprints & Out-of-Band QR Code Verification           |
+-----------------------------------------------------------------------+
                                   |
                                   v
+-----------------------------------------------------------------------+
|                          Protocol Session                             |
|   - Double Ratchet Engine (Symmetric + Ephemeral DH)                  |
|   - Replay Protection Window (64-bit Sliding Bitmap)                  |
|   - Protocol Version Verification & State Machine                     |
+-----------------------------------------------------------------------+
                                   |
                                   v
+-----------------------------------------------------------------------+
|                         Cryptographic Engine                          |
|   - X25519 ECDH Scalar Multiplication                                 |
|   - HKDF-SHA256 (Extract & Expand with Domain Separation)             |
|   - ChaCha20-Poly1305 AEAD Encryption with Header AAD                 |
+-----------------------------------------------------------------------+
                                   |
                                   v
+-----------------------------------------------------------------------+
|                         Binary Wire Protocol                          |
|   - Compact 203-byte header layout, zero JSON overhead                |
+-----------------------------------------------------------------------+
                                   |
                                   v
+-----------------------------------------------------------------------+
|                      Transport Abstraction Layer                      |
|                                                                       |
|   +---------------+   +---------------+   +-----------------------+   |
|   | TCP Socket    |   | Tor .onion    |   | Bluetooth / Mesh Stub |   |
|   | (IP Network)  |   | (SOCKS5 Proxy)|   | (Local P2P / Radio)   |   |
|   +---------------+   +---------------+   +-----------------------+   |
+-----------------------------------------------------------------------+
```

### Core Architecture Highlights

1. **Zero-Trust Relay Model**: Relay servers hold zero decryption keys and zero user private keys. The server acts strictly as a store-and-forward mailbox relay. Headers are tamper-proofed via Associated Authenticated Data (AAD).
2. **Double Ratchet Key Evolution**: Provides both **Forward Secrecy (FS)** (past messages cannot be decrypted if keys are compromised today) and **Post-Compromise Security (PCS)** (sessions self-heal when a new ephemeral key arrives).
3. **Transport Independence**: The core engine operates over standard TCP or anonymous **Tor `.onion` SOCKS5 proxies**, hiding IP metadata and bypassing NAT firewalls.
4. **Out-of-Band Verification**: Peers exchange long-term identity fingerprints in person (via hexadecimal strings or QR codes) to eliminate Man-in-the-Middle (MITM) risks.

---

## 📁 Project Layout

```text
Pelagos/
├── cmd/
│   ├── palagos/             # CLI Client Application (identity, keys, messaging)
│   └── palagos-server/      # Standalone Store-and-Forward Relay Daemon
├── pkg/
│   ├── crypto/              # CSPRNG, X25519, Ed25519, HKDF, AEAD, Double Ratchet
│   ├── identity/            # Ed25519 Identity, Fingerprinting, QR code export
│   ├── protocol/            # Binary Packet Encoding, Replay Window, Session State
│   ├── transport/           # Abstract Transport, TCP, Tor .onion, Bluetooth/Mesh stubs
│   └── server/              # Zero-Trust Store-and-Forward Relay Server
├── tests/                   # Crypto unit tests, protocol tests, Go fuzz tests
├── docs/                    # Dedicated specifications & mathematical proofs
│   ├── math.md              # Complete mathematical foundations & field algebra
│   ├── cryptography.md      # Cryptographic primitives & implementation rules
│   ├── architecture.md      # System layering & component responsibilities
│   ├── protocol.md          # Binary wire format & message type specification
│   └── threat-model.md      # Formal adversary matrix & security guarantees
├── go.mod
├── go.sum
└── README.md
```

---

## 💻 CLI Operating Guide

### Identity Management

```bash
# Generate a new long-term Ed25519 identity keypair
./bin/palagos gen-identity

# Export identity fingerprint and QR code for out-of-band trust establishment
./bin/palagos export-qr -out identity_qr.png
```

### Running the Relay Server

```bash
# Start a TCP relay server listener
./bin/palagos-server -addr 0.0.0.0:8080 -transport tcp
```

### Messaging over Tor `.onion` Overlay

```bash
# Send an encrypted message over Tor SOCKS5 proxy to a hidden service peer
./bin/palagos send -transport onion -socks 127.0.0.1:9050 -to xxxxx.onion:9090 -msg "Hello securely over Tor"
```

---

## 📚 Documentation Index

For in-depth specifications, formal proofs, threat modeling, and protocol wire layouts, consult the dedicated documentation in `docs/`:

| Document | Focus & Contents |
|---|---|
| 📐 [**Math Foundations**](docs/math.md) | $\mathbb{F}_{2^{255}-19}$ curve equations, Ed25519 verification proofs, HKDF domain separation, Poly1305 finite field algebra, Double Ratchet state equations, 64-bit sliding window bitwise algebra |
| 🛡️ [**Cryptography Spec**](docs/cryptography.md) | Primitives selection (X25519, Ed25519, ChaCha20-Poly1305, HKDF), constant-time guarantees, zeroization limitations |
| 🏗️ [**Architecture Spec**](docs/architecture.md) | Layer decoupling, state machine management, transport abstraction rules |
| 📦 [**Wire Protocol Spec**](docs/protocol.md) | 203-byte header layout, bitwise field definitions, message types, AAD calculation |
| 🔒 [**Threat Model**](docs/threat-model.md) | Formal adversary matrix (passive eavesdropper, active attacker, malicious relay server, quantum adversary limits) |

---

## 🧪 Build & Test Suite

### Running Unit Tests
```bash
# Execute unit test suite across all packages
go test -v ./...
```

### Running Native Go Fuzzing
```bash
# Run fuzz testing on binary packet unmarshaler to catch buffer overreads
go test -v -fuzz=FuzzPacketUnmarshal -fuzztime=10s ./tests
```

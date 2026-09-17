# Palagos — Secure P2P Cryptographic Communication Protocol & Reusable Core Engine

> *"Two people who have established trust should be able to communicate securely even if the infrastructure between them is hostile, compromised, monitored, censored, or completely controlled by an adversary."*

Palagos is a privacy-first, peer-to-peer cryptographic communication system and **reusable core engine** written in Go. It provides end-to-end encrypted messaging, zero-trust relaying, key evolution (Double Ratchet), camera-free presential key pairing (PAKE/SAS), and dual-mode networking (Store-and-Forward Relay vs. Direct P2P Tor `.onion` sockets).

---

## 🌟 Key Architectural Features

- 🛡️ **Zero-Trust Store-and-Forward Relay**: Relay servers (e.g., deployed via Coolify) hold zero decryption keys. Messages are encrypted with ChaCha20-Poly1305 and Double Ratchet keys known exclusively to the endpoints.
- 🔄 **Dual Connection Modes**:
  - **Relay Mode (`ModeRelay`)**: Routes messages through your home server relay (`.onion:9090`) with 72-hour offline mailbox queuing.
  - **Direct P2P Mode (`ModeDirectP2P`)**: Direct peer-to-peer connection over Tor `.onion` hidden services or local sockets with **zero intermediary servers**.
- 🔑 **Camera-Free Presential Pairing (PAKE & SAS)**:
  - Exchange public keys over Bluetooth or proximity channels using a shared 6-digit PIN.
  - Generates a 6-digit **Short Authentication String (SAS)** (e.g., `[ 848-711 ]`) for visual confirmation without requesting camera permissions.
- 🔌 **Universal Native App Integration (3-in-1 SDK Engine)**:
  - **CGo FFI Bridge (`pkg/bridge`)**: In-memory C-bindings (`libpalagos.so`, `palagos.dll`, `.aar`) for Flutter (Dart FFI), Swift, Kotlin, or C/C++ apps.
  - **Security-Enforced RPC Daemon (`pkg/daemon`)**: Local daemon (`palagos daemon -rpc 5050`) with **256-bit CSPRNG Bearer Token auth** and **CSRF protection**.
  - **Go Client SDK (`pkg/client`)**: High-level Go client manager supporting custom contact aliases and multiple user profiles.
- 🎨 **Embedded Web UI**: Subcommand `palagos ui -port 4040` launches a Telegram/Discord hybrid dark mode interface accessible via any local browser.

---

## Quick Navigation

- 🚀 [Quick Start & Installation](#-quick-start--installation)
- ⚙️ [How It Works](#️-how-it-works)
- 🐳 [Home Server & Coolify Deployment](#-home-server--coolify-deployment)
- 📁 [Project Layout](#-project-layout)
- 💻 [CLI Operating Guide](#-cli-operating-guide)
- 📐 [Mathematical Foundations (`docs/math.md`)](docs/math.md)
- 🧪 [Build & Test Suite](#-build--test-suite)

---

## 🚀 Quick Start & Installation

### Prerequisites
- **Go**: Version 1.20 or later installed.
- **Git**: For cloning the repository.
- **Tor**: Daemon installed and running (`SOCKS5` on `127.0.0.1:9050`).

### 1. Clone & Build
```bash
git clone https://github.com/Plancton-sko/Pelagos.git
cd Pelagos

# Build client and server binaries into bin/
mkdir -p bin
go build -o bin/palagos ./cmd/palagos
go build -o bin/palagos-server ./cmd/palagos-server

# Cross-compile for Android (ARM64)
GOOS=android GOARCH=arm64 go build -o bin/palagos-android-arm64 ./cmd/palagos
```

### 2. Generate Cryptographic Identity
```bash
./bin/palagos gen-identity
```

### 3. Launch Embedded Web UI (Midnight Blue Dark Mode)
```bash
./bin/palagos ui -port 4040
```
Open **`http://localhost:4040`** in your browser to access the chat interface!

---

## ⚙️ How It Works

Palagos cryptographically decouples peer identities, session ratchets, binary packet framing, and network socket transports into independent operational layers.

```text
+-----------------------------------------------------------------------+
|                    Native UI Apps (Flutter / Swift / C++ / Web)       |
+-----------------------------------------------------------------------+
                                   |
         +-------------------------+-------------------------+
         | (CGo FFI Bridge)        | (RPC Bearer Token)      | (Go SDK)
         v                         v                         v
+-----------------------------------------------------------------------+
|                    Palagos Client Engine / Manager                    |
|   - Multi-Profile Local Identities & Custom Contact Aliases           |
|   - Presential PIN Pairing & SAS Confirmation Generator               |
|   - Dual-Mode Connection Router (Relay vs Direct P2P)                 |
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
|                      Transport Abstraction Layer                      |
|                                                                       |
|   +-----------------------+   +-----------------------+               |
|   | Tor .onion Sockets    |   | Bluetooth RFCOMM / BLE|               |
|   | (Anonymity Overlay)   |   | (Camera-Free Pairing) |               |
|   +-----------------------+   +-----------------------+               |
+-----------------------------------------------------------------------+
```

---

## 🐳 Home Server & Coolify Deployment

The repository includes a ready-to-deploy [`Dockerfile`](Dockerfile) and [`docker-compose.yml`](docker-compose.yml) with an embedded Tor daemon.

### Deploying on Coolify:
1. Open your **Coolify** dashboard ➔ **New Resource** ➔ **Public Repository**.
2. Input your Pelagos Git repository URL.
3. Select **Docker Compose** build type.
4. Click **Deploy**.
5. Check container **Logs** for your dynamically provisioned v3 `.onion` address:
   ```text
   Automated v3 .onion Address: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.onion:9090
   ```

---

## 📁 Project Layout

```text
Pelagos/
├── cmd/
│   ├── palagos/             # CLI Client Application (identity, keys, UI, daemon, pairing)
│   └── palagos-server/      # Standalone Store-and-Forward Relay Server
├── pkg/
│   ├── bridge/              # CGo FFI Export Bindings for Flutter / Native Apps
│   ├── client/              # Multi-session Client Manager & Embedded Web UI
│   ├── crypto/              # CSPRNG, X25519, Ed25519, HKDF, AEAD, Double Ratchet
│   ├── daemon/              # Security-Enforced Local RPC/IPC Engine Daemon
│   ├── identity/            # Ed25519 Identity, Fingerprinting & PIN/SAS Pairing
│   ├── protocol/            # Binary Packet Encoding, Replay Window, Session State
│   ├── server/              # Zero-Trust Store-and-Forward Relay Server
│   └── transport/           # Transport Abstraction, Tor .onion, Bluetooth RFCOMM
├── tests/                   # Unit tests, integration tests & Go fuzz tests
├── docs/                    # Architectural & mathematical specifications
├── bin/                     # Pre-compiled executables (Desktop & Android ARM64)
├── Dockerfile               # Multi-stage Docker build with Tor daemon
├── docker-compose.yml       # Coolify / Docker Compose deployment configuration
└── entrypoint.sh            # Container initialization script
```

---

## 💻 CLI Operating Guide

### Camera-Free PIN Pairing (No Camera Required)

```bash
# Device 1 (Alice): Create PIN-encrypted pairing payload
./bin/palagos pair-create -key <PRIV_KEY> -pin 482901 -alias "Alice-Phone"

# Device 2 (Bob): Open received payload using the shared PIN
./bin/palagos pair-open -key <PRIV_KEY> -pin 482901 -payload <PAYLOAD_HEX>
# Out: SAS CONFIRMATION CODE: [ 848-711 ]
```

### Running the Engine Daemon (For Native Apps)

```bash
# Launch local RPC Engine Daemon (Prints 256-bit Auth Token)
./bin/palagos daemon -rpc 5050 -socks 127.0.0.1:9050
```

### Running the Store-and-Forward Relay Server

```bash
# Start zero-trust relay server
./bin/palagos-server -addr 0.0.0.0:8080 -transport onion
```

---

## 📚 Documentation Index

| Document | Focus & Contents |
|---|---|
| 📐 [**Math Foundations**](docs/math.md) | $\mathbb{F}_{2^{255}-19}$ curve equations, Ed25519 verification, HKDF domain separation, Poly1305 algebra, Double Ratchet state equations |
| 🛡️ [**Cryptography Spec**](docs/cryptography.md) | Primitives selection (X25519, Ed25519, ChaCha20-Poly1305, HKDF), constant-time guarantees |
| 🏗️ [**Architecture Spec**](docs/architecture.md) | Core engine decoupling, FFI bridge, RPC daemon security, transport abstraction |
| 📦 [**Wire Protocol Spec**](docs/protocol.md) | 203-byte header layout, bitwise field definitions, AAD calculation |
| 🔒 [**Threat Model**](docs/threat-model.md) | Formal adversary matrix (passive eavesdropper, active attacker, malicious relay server) |

---

## 🧪 Build & Test Suite

### Running Unit & Integration Tests
```bash
go test -v ./...
```

### Running Fuzz Testing
```bash
go test -v -fuzz=FuzzPacketUnmarshal -fuzztime=10s ./tests
```

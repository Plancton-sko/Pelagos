# Palagos — Secure P2P Communication Protocol

> *"Two people who have established trust should be able to communicate securely even if the infrastructure between them is hostile, compromised, monitored, censored, or completely controlled by an adversary."*

Palagos is a privacy-first, peer-to-peer cryptographic communication system engineered in Go. It serves as an **auditable, educational cryptographic and protocol engineering reference** designed around zero-trust transport, key evolution (Double Ratchet), authenticated encryption (ChaCha20-Poly1305), identity verification (Ed25519), and transport independence (including Tor `.onion` overlay sockets).

---

## Table of Contents

1. [Core Philosophy & Non-Goals](#1-core-philosophy--non-goals)
2. [Threat Model & Security Claims](#2-threat-model--security-claims)
3. [Mathematical Foundations](#3-mathematical-foundations)
   - [A. Elliptic Curve Cryptography (Curve25519 & X25519)](#a-elliptic-curve-cryptography-curve25519--x25519)
   - [B. Digital Signatures (Ed25519 / EdDSA)](#b-digital-signatures-ed25519--eddsa)
   - [C. Key Derivation Hierarchy (HKDF-SHA256)](#c-key-derivation-hierarchy-hkdf-sha256)
   - [D. Authenticated Encryption (ChaCha20-Poly1305 AEAD & AAD)](#d-authenticated-encryption-chacha20-poly1305-aead--aad)
   - [E. Key Evolution: Double Ratchet vs. Historical Substitution Ciphers](#e-key-evolution-double-ratchet-vs-historical-substitution-ciphers)
   - [F. Replay Protection: 64-Bit Sliding Window Bitmap](#f-replay-protection-64-bit-sliding-window-bitmap)
4. [Memory Erasure & Go Runtime Limitations](#4-memory-erasure--go-runtime-limitations)
5. [Protocol Binary Wire Format](#5-protocol-binary-wire-format)
6. [Zero-Trust Relay Server Architecture](#6-zero-trust-relay-server-architecture)
7. [Transport Agility & Tor `.onion` Transport](#7-transport-agility--tor-onion-transport)
8. [Project Layout](#8-project-layout)
9. [Build, Test, & Execution Guide](#9-build-test--execution-guide)

---

## 1. Core Philosophy & Non-Goals

Palagos prioritizes cryptographic security and peer privacy over server convenience:

- **No Cloud Backups**: Messages are never backed up to remote servers or cloud databases.
- **No Server Plaintexts**: Relay servers NEVER possess decryption keys.
- **One Device = One Identity**: Device loss means local message loss by design.
- **In-Person Out-of-Band Trust**: Public keys are exchanged and verified out-of-band (via QR codes or visual hexadecimal fingerprints) to eliminate Man-in-the-Middle (MITM) attacks.
- **Transport Independence**: The cryptographic protocol operates identically over TCP, Tor `.onion` sockets, Bluetooth RFCOMM, or Store-and-Forward Mesh networks.

---

## 2. Threat Model & Security Claims

### Adversary Matrix

```text
+-----------------------+------------------------------------------+-------------------------------------+
| Adversary Model       | Capabilities                             | Palagos Guarantee                   |
+-----------------------+------------------------------------------+-------------------------------------+
| Passive Eavesdropper  | Records raw network packets              | 100% Confidentiality via AEAD       |
| Active Attacker       | Modifies, injects, or replays packets    | Rejected via AAD & Replay Window    |
| Malicious Relay Server| Controls server, buffers/relays packets  | Cannot read or forge messages       |
| Compromised Endpoint  | Inspects current state at time t         | Forward Secrecy & Post-Compromise   |
| Traffic Analyzer      | Observes IP endpoints & packet timings   | Mitigated via Tor .onion Transport  |
+-----------------------+------------------------------------------+-------------------------------------+
```

### Concrete Security Guarantees
1. **End-to-End Confidentiality**: Encrypted at source, decrypted strictly at target peer.
2. **Forward Secrecy**: Compromising current keys cannot decrypt historical message ciphertexts.
3. **Post-Compromise Security**: Receiving fresh ephemeral public keys heals compromised ratchets.
4. **Replay Protection**: Duplicate packets are dropped via 64-bit sliding window bitmap.

---

## 3. Mathematical Foundations

### A. Elliptic Curve Cryptography (Curve25519 & X25519)

Curve25519 is a Montgomery curve defined over $\mathbb{F}_p$ where $p = 2^{255} - 19$:

$$y^2 = x^3 + 486662 x^2 + x \pmod{2^{255} - 19}$$

#### Key Agreement Mechanics
- Alice chooses private scalar $a \in \mathbb{F}_p$ and computes public key $A = a \cdot G$.
- Bob chooses private scalar $b \in \mathbb{F}_p$ and computes public key $B = b \cdot G$.
- Alice computes shared point $S = a \cdot B = a(bG) = (ab)G$.
- Bob computes shared point $S = b \cdot A = b(aG) = (ba)G$.

Because scalar multiplication over elliptic curve groups is commutative, $S_{\text{alice}} == S_{\text{bob}} == abG$. Recovering $a$ from $A$ and $G$ requires solving the **Elliptic Curve Discrete Logarithm Problem (ECDLP)**, requiring $\sim 2^{128}$ operations.

```go
// Go mapping in pkg/crypto/ecdh.go
secret, err := privateKey.ECDH(peerPublicKey)
```

---

### B. Digital Signatures (Ed25519 / EdDSA)

Ed25519 operates on the birationally equivalent twisted Edwards curve:

$$-x^2 + y^2 = 1 - \frac{121665}{121666} x^2 y^2 \pmod{2^{255} - 19}$$

#### Signature Algorithm
For message $M$ signed by private key $K$:
1. $r = \text{SHA-512}(h \parallel M) \pmod L$ (Deterministic nonce generation preventing RNG failure).
2. $R = r \cdot G$.
3. $k = \text{SHA-512}(R \parallel A \parallel M) \pmod L$.
4. $S = (r + k \cdot a) \pmod L$.
5. Signature $\sigma = (R, S)$. Verification checks $S \cdot G == R + k \cdot A$.

---

### C. Key Derivation Hierarchy (HKDF-SHA256)

HKDF (RFC 5869) uses HMAC-SHA256:

1. **Extract**: $\text{PRK} = \text{HMAC-SHA256}(\text{Salt}, \text{IKM})$
2. **Expand**: $T(i) = \text{HMAC-SHA256}(\text{PRK}, T(i-1) \parallel \text{info} \parallel i)$

#### Domain Separation Contexts
- `palagos-v1-root-ratchet`: Root key step.
- `palagos-v1-chain-step`: Symmetric chain key step.
- `palagos-v1-message-key`: AEAD message key generation.

---

### D. Authenticated Encryption (ChaCha20-Poly1305 AEAD & AAD)

#### ChaCha20 Stream Cipher
Operates on a $4 \times 4$ matrix of 32-bit words running 20 rounds of quarter-round operations.

#### Poly1305 MAC
Evaluates polynomial modulo prime $2^{130} - 5$ using 256-bit one-time key derived from ChaCha20 block 0:

$$a = \left( \sum_{i=1}^{k} m_i r^{k-i+1} \right) + s \pmod{2^{130} - 5}$$

#### Associated Authenticated Data (AAD)
Header metadata (Version, Message Type, Epoch, Sequence, Sender/Recipient Fingerprints, Ephemeral PubKey) is bound into the Poly1305 MAC tag calculation. Header tampering causes decryption failure.

---

### E. Key Evolution: Double Ratchet vs. Historical Substitution Ciphers

```text
Historical Enigma:              Palagos Double Ratchet:
Polyalphabetic substitution     Stateful One-Way Key Evolution
State easily reversed           Mathematical Forward & Post-Compromise Security
if wheel order is known.        Cannot be reversed due to SHA-256 Preimage Resistance.
```

- **Symmetric Ratchet**: Advancing chain key $CK_{i+1} = \text{HKDF-Expand}(CK_i, \text{"palagos-v1-chain-step"})$. Old keys are immediately zeroized.
- **DH Ratchet**: When peer sends a new ephemeral public key, a fresh X25519 key exchange resets the Root Key ($RK$), injecting uncompromised entropy.

---

### F. Replay Protection: 64-Bit Sliding Window Bitmap

Tracks sequence numbers in range $[\text{maxSeq} - 63, \text{maxSeq}]$:

```text
Bit Position:   63 62 61 ... 3 2 1 0  (relative to maxSeq)
Status Bit:      1  0  1 ... 1 1 1 1  (1 = received, 0 = open)
```

Duplicate sequence numbers or sequence numbers older than 64 hops are dropped before decryption.

---

## 4. Memory Erasure & Go Runtime Limitations

Palagos implements `Zeroize(b []byte)` to overwrite keys with zeros. However, in Go:

1. **Garbage Collection (GC)**: GC moves objects during stack copying/heap compaction, leaving historical copies in unallocated memory.
2. **Compiler Optimization**: Dead-store elimination may remove zeroing loops if not carefully referenced.
3. **OS Swap & Crash Dumps**: Memory containing secrets may be flushed to disk swap.

*Conclusion*: Zeroization minimizes the temporal vulnerability window but cannot guarantee absolute physical erasure in high-level managed languages.

---

## 5. Protocol Binary Wire Format

Compact 203-byte header layout (Big-Endian integer encoding):

```text
+-------------------+-------------------+--------------------+
| Field Name        | Size (Bytes)      | Description        |
+-------------------+-------------------+--------------------+
| Protocol Version  | 2 (uint16)        | 0x0100 (v1.0)      |
| Message Type      | 1 (uint8)         | Handshake/Data/Ack |
| Epoch             | 4 (uint32)        | Key Epoch          |
| Sequence Number   | 8 (uint64)        | Monotonic Counter  |
| Sender FP         | 32 ([32]byte)     | Identity SHA-256   |
| Recipient FP      | 32 ([32]byte)     | Identity SHA-256   |
| Ephemeral PubKey  | 32 ([32]byte)     | Ephemeral X25519   |
| Nonce             | 24 ([24]byte)     | XChaCha20 Nonce    |
| Payload Length    | 4 (uint32)        | Length of Payload  |
| Payload           | Variable          | Ciphertext + Tag   |
| Signature         | 64 ([64]byte)     | Ed25519 Signature  |
+-------------------+-------------------+--------------------+
```

---

## 6. Zero-Trust Relay Server Architecture

- Server holds its own **Ed25519 Server Identity Key**.
- Clients verify server identity via challenge-response during connection.
- Server acts strictly as a store-and-forward mailbox relay.
- Zero plaintext visibility; zero capability to alter headers.

---

## 7. Transport Agility & Tor `.onion` Transport

Palagos cryptographically decouples protocol logic from socket transports.

### Tor `.onion` SOCKS5 Transport Integration
Using `golang.org/x/net/proxy`, Palagos dials Tor SOCKS5 proxies (`127.0.0.1:9050`):

```bash
# Dial a remote peer over Tor network:
./bin/palagos send -transport onion -socks 127.0.0.1:9050 -to xxxxx.onion:9090 ...
```

- **IP Anonymity**: Sender and recipient real IP addresses are concealed behind 3-hop Tor circuits.
- **NAT Traversal**: Tor v3 Hidden Services enable direct P2P connections through home firewalls and CGNAT.

---

## 8. Project Layout

```text
Pelagos/
├── cmd/
│   ├── palagos/             # CLI Client Application
│   └── palagos-server/      # Standalone Relay Server Daemon
├── pkg/
│   ├── crypto/              # CSPRNG, X25519, Ed25519, HKDF, AEAD, Double Ratchet
│   ├── identity/            # Ed25519 Identity, Fingerprinting, QR export
│   ├── protocol/            # Binary Packet Encoding, Replay Window, Session State
│   ├── transport/           # Abstract Transport, TCP, Tor .onion, Bluetooth/Mesh stubs
│   └── server/              # Zero-Trust Store-and-Forward Relay Server
├── tests/                   # Crypto unit tests, protocol tests, Go fuzz tests
├── docs/                    # Architecture, Cryptography, Protocol, Threat Model, ADRs
├── go.mod
├── go.sum
└── README.md
```

---

## 9. Build, Test, & Execution Guide

### Compilation
```bash
# Build client and server binaries into bin/
mkdir -p bin
go build -o bin/palagos ./cmd/palagos
go build -o bin/palagos-server ./cmd/palagos-server
```

### Running Test Suite
```bash
# Run unit tests
go test -v ./...

# Run Go native fuzzing
go test -v -fuzz=FuzzPacketUnmarshal -fuzztime=10s ./tests
```

### Generate Identity
```bash
./bin/palagos gen-identity
```

### Run Relay Server
```bash
./bin/palagos-server -addr 0.0.0.0:8080 -transport tcp
```

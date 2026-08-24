# Palagos Architecture & Layer Separation Specification

Palagos is designed around strict separation of cryptographic identity, session state evolution, packet formatting, and physical transport.

---

## 1. System Layering Overview

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
|                          Protocol Session                              |
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
|   - Version, Type, Epoch, Sequence, Fingerprints, EphemeralPub,       |
|     Nonce, Length, Payload, Ed25519 Header Signature                  |
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

---

## 2. Layer Responsibilities & Guarantees

### A. Identity Layer (`pkg/identity`)
- **Responsibility**: Manages device-level cryptographic identity using long-term Ed25519 keypairs.
- **Out-of-Band Trust**: Users exchange identity fingerprints in person (e.g. scanning QR codes or visual hexadecimal comparison).
- **Separation**: Identity keys are **never** used directly for symmetric payload encryption or X25519 key exchange without explicit digital signature binding.

### B. Session & State Evolution (`pkg/protocol/session.go`, `pkg/crypto/ratchet.go`)
- **Responsibility**: Manages state transitions, session setup handshakes, Double Ratchet step logic, and sequence counter monotonicity.
- **Replay Protection**: Houses a 64-bit sliding window bitmap (`ReplayWindow`) to reject duplicate or old network packets before decryption.

### C. Cryptographic Engine (`pkg/crypto`)
- **Responsibility**: Pure, constant-time cryptographic primitives.
- **Primitives**:
  - `ecdh.go`: X25519 Curve25519 scalar multiplication.
  - `hkdf.go`: HKDF-SHA256 derivation with strict context domain separation strings (`palagos-v1-root-ratchet`, `palagos-v1-chain-step`, `palagos-v1-message-key`).
  - `aead.go`: ChaCha20-Poly1305 AEAD authenticated encryption.

### D. Transport Layer (`pkg/transport`)
- **Responsibility**: Delivers binary Palagos frames over physical or virtual network channels.
- **Transport Independence**: The cryptographic layer treats the transport as an untrusted byte pipe. Replacing TCP with Tor `.onion` SOCKS5 or Bluetooth RFCOMM requires zero changes to key derivation or packet format.

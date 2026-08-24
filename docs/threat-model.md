# Palagos Formal Threat Model & Adversary Matrix

Security in Palagos is defined relative to explicit adversary models and capabilities.

---

## 1. Adversary Matrix

| Adversary Model | Capabilities | Mitigated By Palagos | Limitations / Non-Goals |
|---|---|---|---|
| **Passive Network Eavesdropper** | Can record all encrypted network traffic over TCP/Internet/Wi-Fi | **YES**: ChaCha20-Poly1305 AEAD confidentiality protects message contents | Can observe packet timing, size, and TCP IP addresses unless Tor `.onion` is used |
| **Active Network Attacker** | Can drop, inject, modify, or replay network packets | **YES**: Ed25519 signatures, AEAD AAD header binding, and 64-bit sliding replay window | Denial of Service (dropping all packets prevents communication) |
| **Malicious Relay Server** | Fully controls relay server, can inspect, modify, or buffer relay packets | **YES**: Server does NOT hold message keys or identity keys. Cannot read plaintexts or modify headers | Server can drop packets or drop offline mailbox |
| **Long-Term Traffic Recorder** | Records encrypted traffic today; attempts to decrypt years later after key compromise | **YES**: Double Ratchet forward secrecy ensures past messages cannot be decrypted even if current keys leak | Does not protect messages if identity keys and state were recorded *and* ephemeral keys compromised simultaneously |
| **Stolen / Compromised Endpoint** | Physical theft or malware on device | **PARTIAL**: Zeroizing memory contracts key exposure; no cloud backups exist | Endpoint malware with root privileges can read unencrypted UI plaintext |
| **Quantum Adversary** | Quantum computer running Shor's algorithm | **NO**: X25519 and Ed25519 are broken by Shor's algorithm | Post-quantum hybrid migration (ML-KEM) planned for future versions |

---

## 2. Security Claims & Guarantees

1. **End-to-End Confidentiality**: Plaintext messages are encrypted at the sending peer and decrypted exclusively at the receiving peer. No intermediate server or relay can decrypt messages.
2. **Entity Authentication**: Long-term identity keys (Ed25519) sign handshake parameters. In-person out-of-band verification (QR code / fingerprint) guarantees peer identity against MITM attacks.
3. **Forward Secrecy**: Message keys are derived via one-way HKDF chains and immediately zeroized. Compromising state at time $t$ does not compromise messages sent at time $t - k$.
4. **Post-Compromise Security**: If ephemeral state is compromised at time $t$, receiving a new DH ratchet step from the peer injects fresh entropy, healing the session.
5. **Replay Resistance**: Replayed network packets fail the 64-bit sliding window check or sequence verification.

---

## 3. Metadata Exposure Limits

- **Content Privacy**: 100% encrypted via ChaCha20-Poly1305.
- **Header Privacy**: Public fields (Version, Type, Epoch, Sequence, Fingerprints) are authenticated via AAD, but exposed in plaintext on the wire for server routing.
- **Transport Privacy**: Standard TCP exposes IP endpoints. Using the **Tor `.onion` transport** hides IP addresses, location metadata, and routing topology.

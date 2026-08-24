# ADR 0002: Binary Wire Format & AAD Header Binding

## Context & Problem Statement
Textual serializations (such as JSON or XML) introduce parsing overhead, ambiguity, integer overflow vulnerabilities, and high bandwidth overhead for binary cryptographic keys. Unauthenticated packet headers can be manipulated in transit by hostile network relays.

## Decision
We define a packed big-endian **Binary Protocol Layout** (203-byte header) and pass header fields into ChaCha20-Poly1305 as **Associated Authenticated Data (AAD)**:
`AAD = Version || Type || Epoch || Sequence || SenderFP || RecipientFP || EphemeralPubKey`

## Consequences
- **Positive**:
  - Zero-copy binary parsing performance.
  - Guaranteed header integrity: Any modification to sequence numbers, version, or fingerprints causes AEAD verification to fail before payload decryption.
- **Negative**:
  - Fixed binary layout requires strict versioning for future upgrades.

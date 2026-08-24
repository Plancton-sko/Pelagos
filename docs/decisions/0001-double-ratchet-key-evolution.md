# ADR 0001: Double Ratchet Key Evolution Strategy

## Context & Problem Statement
The original conceptual requirement of Palagos called for continuously changing cryptographic state, inspired by the historical Enigma rotor machine. Modern protocol design requires achieving key evolution using well-studied, provably secure constructions rather than custom substitution ciphers.

## Decision
We adopt the **Double Ratchet Algorithm** combining:
1. **Symmetric-Key KDF Ratchet**: Advancing message keys via one-way HKDF-SHA256 hash chains (`palagos-v1-chain-step`).
2. **Diffie-Hellman Ephemeral Ratchet**: Advancing root keys via X25519 scalar multiplication whenever new ephemeral public keys are received.

## Consequences
- **Positive**:
  - Provides mathematical **Forward Secrecy**: Stolen current keys cannot decrypt past messages.
  - Provides mathematical **Post-Compromise Security**: State self-heals after temporary endpoint key compromise.
- **Negative**:
  - Requires maintaining ephemeral ratchet state in memory.

# Palagos Cryptographic Protocol — Mathematical Foundations

This document provides a comprehensive mathematical specification of the cryptographic primitives, finite field arithmetic, signature verifications, key derivation hierarchies, and state transition equations used in the **Palagos P2P Communication Protocol**.

---

## Table of Contents

1. [Finite Field & Elliptic Curve Arithmetic (Curve25519 & X25519)](#1-finite-field--elliptic-curve-arithmetic-curve25519--x25519)
2. [Twisted Edwards Curves & Digital Signatures (Ed25519 / EdDSA)](#2-twisted-edwards-curves--digital-signatures-ed25519--eddsa)
3. [Key Derivation Algebra (HKDF-SHA256)](#3-key-derivation-algebra-hkdf-sha256)
4. [Authenticated Encryption with Associated Data (ChaCha20-Poly1305 AEAD)](#4-authenticated-encryption-with-associated-data-chacha20-poly1305-aead)
5. [Key Evolution Mathematics (Double Ratchet Engine)](#5-key-evolution-mathematics-double-ratchet-engine)
6. [Replay Protection Sliding Window Bitwise Algebra](#6-replay-protection-sliding-window-bitwise-algebra)

---

## 1. Finite Field & Elliptic Curve Arithmetic (Curve25519 & X25519)

Palagos utilizes Curve25519 for non-interactive and interactive key exchanges.

### Prime Field Definition

Curve25519 operates over the prime field $\mathbb{F}_p$, where $p$ is the Mersenne-like prime:

$$p = 2^{255} - 19$$

The order of the curve $E(\mathbb{F}_p)$ is $8 \cdot \ell$, where $\ell$ is a prime number of approximately $2^{252}$ bits:

$$\ell = 2^{252} + 27742317777372353535851937790883648493$$

### Montgomery Curve Form

The curve equation in Montgomery coordinates is defined by:

$$y^2 = x^3 + 486662 x^2 + x \pmod{2^{255} - 19}$$

where $A = 486662$ and $B = 1$.

### Generator Point $G$

The standard generator (base point) $G$ has $u$-coordinate $u = 9$.

### Key Agreement Mechanics (X25519)

Let Alice select a private scalar $a \in \mathbb{F}_p$ (clamped to ensure key security) and Bob select a private scalar $b \in \mathbb{F}_p$.

1. **Public Key Computation**:
   $$A = a \cdot G \quad (\text{Alice's Public Key})$$
   $$B = b \cdot G \quad (\text{Bob's Public Key})$$

2. **Shared Secret Agreement**:
   $$\text{Alice calculates: } S_{\text{alice}} = a \cdot B = a \cdot (b \cdot G) = (ab) \cdot G$$
   $$\text{Bob calculates: } S_{\text{bob}} = b \cdot A = b \cdot (a \cdot G) = (ba) \cdot G$$

Since scalar multiplication in abelian elliptic curve groups is commutative:

$$S_{\text{alice}} = S_{\text{bob}} = (ab) \cdot G$$

### Security Assumption (ECDLP)

Extracting the scalar $a$ from $A = a \cdot G$ requires solving the **Elliptic Curve Discrete Logarithm Problem (ECDLP)**. On Curve25519, Pollard's $\rho$ algorithm requires approximately $\sqrt{\pi \cdot \ell / 4} \approx 2^{128}$ group operations, making private key recovery mathematically computationally intractable.

---

## 2. Twisted Edwards Curves & Digital Signatures (Ed25519 / EdDSA)

For long-term identity authentication and packet header signatures, Palagos uses Ed25519 on the birationally equivalent twisted Edwards curve.

### Curve Form

$$-x^2 + y^2 = 1 - d x^2 y^2 \pmod{2^{255} - 19}$$

where $d = -\frac{121665}{121666} \pmod{2^{255}-19}$.

### Signature Generation Algorithm

To sign message $M$ using private key secret $K$:

1. Compute hash of private key secret $K$:
   $$\text{SHA-512}(K) = (a \parallel h)$$
   where $a$ is the 256-bit secret scalar and $h$ is a 256-bit prefix.

2. Generate deterministic nonce $r$:
   $$r = \text{SHA-512}(h \parallel M) \pmod \ell$$
   *(Deterministic nonce derivation prevents private key leakage caused by poor random number generators).*

3. Compute commitment point $R$:
   $$R = r \cdot G$$

4. Compute challenge scalar $k$:
   $$k = \text{SHA-512}(R \parallel A \parallel M) \pmod \ell$$
   where $A = a \cdot G$ is the public key.

5. Compute signature scalar $S$:
   $$S = (r + k \cdot a) \pmod \ell$$

6. Output 64-byte signature tuple $\sigma = (R, S)$.

### Verification Proof

The verifier receives signature $\sigma = (R, S)$, public key $A$, and message $M$. The verifier recomputes $k = \text{SHA-512}(R \parallel A \parallel M) \pmod \ell$ and checks:

$$S \cdot G \stackrel{?}{=} R + k \cdot A$$

**Proof of Verification Equivalence**:

$$S \cdot G = ((r + k \cdot a) \pmod \ell) \cdot G = (r \cdot G) + k \cdot (a \cdot G) = R + k \cdot A$$

---

## 3. Key Derivation Algebra (HKDF-SHA256)

Palagos utilizes HKDF (RFC 5869) built on HMAC-SHA256 for key derivation and domain separation.

### Stage 1: Extract

Extracts a uniform pseudorandom key ($\text{PRK}$) from Input Keying Material ($\text{IKM}$) using optional $\text{Salt}$:

$$\text{PRK} = \text{HMAC-SHA256}(\text{Salt}, \text{IKM})$$

### Stage 2: Expand

Expands $\text{PRK}$ into output keying material ($\text{OKM}$) of length $L$:

$$\text{OKM} = T(1) \parallel T(2) \parallel \dots \parallel T(N)$$

where:

$$T(0) = \text{empty}$$
$$T(1) = \text{HMAC-SHA256}(\text{PRK}, \text{info} \parallel 0\text{x}01)$$
$$T(2) = \text{HMAC-SHA256}(\text{PRK}, T(1) \parallel \text{info} \parallel 0\text{x}02)$$

### Domain Separation Strings

To guarantee cryptographic context isolation, distinct `info` strings are assigned across protocol components:

- `palagos-v1-root-ratchet`: Root key step.
- `palagos-v1-chain-step`: Symmetric message chain advancement.
- `palagos-v1-message-key`: Per-packet AEAD encryption key derivation.
- `palagos-v1-handshake-master`: Session initialization master secret.

---

## 4. Authenticated Encryption with Associated Data (ChaCha20-Poly1305 AEAD)

Payload confidentiality and integrity are enforced via ChaCha20-Poly1305 (RFC 8439) with 192-bit nonces (XChaCha20).

### ChaCha20 Matrix Operations

ChaCha20 maintains a state matrix of sixteen 32-bit words:

$$\begin{pmatrix}
c_0 & c_1 & c_2 & c_3 \\
k_0 & k_1 & k_2 & k_3 \\
k_4 & k_5 & k_6 & k_7 \\
b & n_0 & n_1 & n_2
\end{pmatrix}$$

where $c_i$ are constants, $k_i$ key words, $b$ block counter, and $n_i$ nonce words. State transitions run 20 rounds of quarter-round additions, rotations, and XOR operations.

### Poly1305 Polynomial Evaluation over Prime Field $\mathbb{F}_{2^{130}-5}$

Poly1305 evaluates a message polynomial modulo $p_{\text{poly}} = 2^{130} - 5$ using a 256-bit one-time key $(r, s)$:

$$a = \left( \sum_{i=1}^{k} m_i r^{k-i+1} \right) + s \pmod{2^{130} - 5}$$

### Associated Authenticated Data (AAD) Security Guarantee

Header metadata (Version, Message Type, Epoch, Sequence, Sender/Recipient Fingerprints, Ephemeral PubKey) is concatenated to form canonical byte string $\text{AAD}$. Poly1305 calculates the tag over:

$$\text{Tag} = \text{Poly1305}_{r,s}\left( \text{AAD} \parallel \text{pad1} \parallel \text{Ciphertext} \parallel \text{pad2} \parallel \text{len}(\text{AAD}) \parallel \text{len}(\text{Ciphertext}) \right)$$

Any modification to header fields in transit alters the evaluated polynomial $a$, causing decryption to abort prior to revealing plaintext.

---

## 5. Key Evolution Mathematics (Double Ratchet Engine)

Palagos provides **Forward Secrecy (FS)** and **Post-Compromise Security (PCS)** via a stateful Double Ratchet engine.

### Symmetric Ratchet Step

For message sequence index $i$, the symmetric chain key $CK_i$ advances via HKDF-Expand:

$$CK_{i+1} = \text{HKDF-Expand}(CK_i, \text{"palagos-v1-chain-step"})$$
$$MK_i = \text{HKDF-Expand}(CK_i, \text{"palagos-v1-message-key"})$$

As soon as $MK_i$ encrypts or decrypts packet $i$, $MK_i$ is zeroized in memory.

### Diffie-Hellman (DH) Ratchet Step

When receiving a new ephemeral public key $DH_{\text{recv}}$:

1. **Step 1**: $DH_{\text{out}} = \text{X25519}(DH_{\text{local\_priv}}, DH_{\text{recv}})$
2. **Step 2**: $RK_{j+1}, CK_{r} = \text{HKDF-Extract-and-Expand}(RK_j, DH_{\text{out}}, \text{"palagos-v1-root-ratchet"})$
3. **Step 3**: Generate new local ephemeral keypair $DH_{\text{new\_priv}}, DH_{\text{new\_pub}}$
4. **Step 4**: $DH_{\text{out2}} = \text{X25519}(DH_{\text{new\_priv}}, DH_{\text{recv}})$
5. **Step 5**: $RK_{j+2}, CK_{s} = \text{HKDF-Extract-and-Expand}(RK_{j+1}, DH_{\text{out2}}, \text{"palagos-v1-root-ratchet"})$

### Comparison with Historical Ciphers

Unlike historical polyalphabetic substitution ciphers (e.g. Enigma) whose state machine operations were reversible if rotor configurations were compromised, the SHA-256 underlying HKDF is one-way (Preimage Resistant):

$$\text{Given } CK_{i+1}, \text{ computing } CK_i \text{ requires reversing SHA-256}, \text{ taking } \sim 2^{256} \text{ ops.}$$

---

## 6. Replay Protection Sliding Window Bitwise Algebra

To prevent network packet replay attacks, Palagos tracks sequence numbers using a 64-bit sliding window bitmap over sequence ring $\mathbb{Z}_{2^{64}}$.

### Window State Definitions

Let $\text{maxSeq}$ be the highest sequence number verified and accepted so far, and $\text{bitmap} \in \{0,1\}^{64}$ represent receipt history of the window $[\text{maxSeq} - 63, \text{maxSeq}]$.

### Transition Rules for Incoming Sequence $s$:

1. **Case 1: $s > \text{maxSeq}$ (Newer packet)**
   $$\Delta = s - \text{maxSeq}$$
   $$\text{If } \Delta < 64: \quad \text{bitmap} = (\text{bitmap} \ll \Delta) \mid 1$$
   $$\text{If } \Delta \ge 64: \quad \text{bitmap} = 1$$
   $$\text{maxSeq} = s$$

2. **Case 2: $s \le \text{maxSeq}$ (Out-of-order or duplicate packet)**
   $$\text{offset} = \text{maxSeq} - s$$
   $$\text{If } \text{offset} \ge 64: \quad \text{Reject packet (Expired / Outside window)}$$
   $$\text{If } (\text{bitmap} \gg \text{offset}) \ \& \ 1 == 1: \quad \text{Reject packet (Duplicate)}$$
   $$\text{If } (\text{bitmap} \gg \text{offset}) \ \& \ 1 == 0: \quad \text{Accept packet}, \quad \text{bitmap} = \text{bitmap} \mid (1 \ll \text{offset})$$

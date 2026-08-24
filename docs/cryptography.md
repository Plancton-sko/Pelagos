# Palagos Cryptographic Foundations & Mathematical Proofs

Palagos strictly avoids non-standard or custom cryptographic primitives. All security properties stem from well-studied, standardized constructions implemented via Go's maintained cryptographic standard library and standard sub-packages (`golang.org/x/crypto`).

---

## 1. Elliptic Curve Cryptography: Curve25519 & X25519

### Mathematical Definition
Curve25519 is a Montgomery curve defined over the finite prime field $\mathbb{F}_p$ where $p = 2^{255} - 19$:

$$y^2 = x^3 + 486662x^2 + x \pmod{2^{255} - 19}$$

### Base Point $G$
The generator point $G$ is the point with $u$-coordinate $u = 9$.

### Key Agreement (X25519)
Let Alice generate private secret scalar $a \in [0, 2^{256}-1]$ and Bob generate private secret scalar $b \in [0, 2^{256}-1]$.

1. **Public Key Derivation**:
   $$A = a \cdot G \quad (\text{Alice's Public Key})$$
   $$B = b \cdot G \quad (\text{Bob's Public Key})$$

2. **Shared Secret Computation**:
   $$\text{Alice computes: } S_{\text{alice}} = a \cdot B = a \cdot (b \cdot G) = (ab) \cdot G$$
   $$\text{Bob computes: } S_{\text{bob}} = b \cdot A = b \cdot (a \cdot G) = (ba) \cdot G$$

Since scalar multiplication is commutative over the abelian curve group, $S_{\text{alice}} = S_{\text{bob}} = abG$.

### Security Assumption (ECDLP)
Given public points $A = aG$ and base point $G$, deriving scalar $a$ requires solving the **Elliptic Curve Discrete Logarithm Problem (ECDLP)**. On Curve25519, Pollard's rho algorithm requires approximately $2^{128}$ operations, making key extraction mathematically infeasible.

---

## 2. Digital Signatures: Ed25519 (EdDSA)

### Mathematical Curve Form
Ed25519 operates on the birationally equivalent twisted Edwards curve:

$$-x^2 + y^2 = 1 - \frac{121665}{121666} x^2 y^2 \pmod{2^{255} - 19}$$

### Signature Construction
To sign a message $M$ using private key $K$:

1. Compute secret scalar $a$ and prefix $h$ via SHA-512:
   $$\text{SHA-512}(K) = (a \parallel h)$$
2. Compute deterministic nonce $r$:
   $$r = \text{SHA-512}(h \parallel M) \pmod L$$
3. Compute commitment point $R$:
   $$R = r \cdot G$$
4. Compute challenge hash $k$:
   $$k = \text{SHA-512}(R \parallel \text{Public\_Key} \parallel M) \pmod L$$
5. Compute signature scalar $S$:
   $$S = (r + k \cdot a) \pmod L$$
6. Signature is the 64-byte tuple $\sigma = (R, S)$.

### Verification Equation
Verifier checks if:
$$S \cdot G \stackrel{?}{=} R + k \cdot \text{Public\_Key}$$

Proof of correctness:
$$S \cdot G = (r + k \cdot a) \cdot G = r \cdot G + k \cdot (a \cdot G) = R + k \cdot \text{Public\_Key}$$

---

## 3. Key Derivation Function: HKDF (RFC 5869)

HKDF uses HMAC-SHA256 in a two-stage construction:

### Stage 1: Extract
$$\text{PRK} = \text{HMAC-SHA256}(\text{Salt}, \text{IKM})$$
Extracts a uniformly distributed Pseudorandom Key ($\text{PRK}$) from Input Keying Material ($\text{IKM}$).

### Stage 2: Expand
$$\text{OKM} = T(1) \parallel T(2) \parallel \dots \parallel T(N)$$
where:
$$T(0) = \text{empty}$$
$$T(1) = \text{HMAC-SHA256}(\text{PRK}, \text{info} \parallel 0\text{x}01)$$
$$T(2) = \text{HMAC-SHA256}(\text{PRK}, T(1) \parallel \text{info} \parallel 0\text{x}02)$$

### Domain Separation Strings in Palagos
- `palagos-v1-root-ratchet`: Root key advancement.
- `palagos-v1-chain-step`: Symmetric chain key advancement.
- `palagos-v1-message-key`: Per-message AEAD encryption key derivation.
- `palagos-v1-handshake-master`: Handshake master secret derivation.

---

## 4. Authenticated Encryption with Associated Data (AEAD)

Palagos uses **ChaCha20-Poly1305** (RFC 8439) with 192-bit XChaCha20 nonces.

### Poly1305 Evaluation
Poly1305 evaluates a polynomial mod $2^{130} - 5$ using a 256-bit one-time key $(r, s)$:

$$a = \left( \sum_{i=1}^{k} m_i r^{k-i+1} \right) + s \pmod{2^{130} - 5}$$

### Why AEAD is Mandatory
Plaintext $P$ is encrypted under stream cipher keystream $K$: $C = P \oplus K$.
Without Poly1305 authentication, an active adversary can flip bit $i$ in $C$ ($C'_i = C_i \oplus \delta$), which flips bit $i$ in decrypted plaintext ($P'_i = P_i \oplus \delta$).
Poly1305 authentication over $(C \parallel \text{AAD})$ guarantees that any bit flip alters the MAC tag, causing immediate packet rejection.

---

## 5. Double Ratchet State Transitions

```text
                  Root Key (RK_0)
                         |
           +-------------+-------------+
           | DH(DH_A1, DH_B1)          |
           v                           v
     Root Key (RK_1)            Sending Chain (CK_s1)
           |                           |
           +-----+                     +-----+-----+
           | DH(DH_A1, DH_B2)          |           |
           v                           v           v
     Root Key (RK_2)                MK_1        CK_s2
                                (Message 1)      |
                                                 v
                                                MK_2
                                            (Message 2)
```

- **Symmetric Ratchet**: Advances chain key $CK_{i+1} = \text{HKDF-Expand}(CK_i, \text{"palagos-v1-chain-step"})$ for every message sent/received.
- **DH Ratchet**: Advances root key $RK_{j+1} = \text{HKDF-Expand}(\text{HMAC}(RK_j, DH_{\text{new}}), \text{"palagos-v1-root-ratchet"})$ whenever a new ephemeral public key arrives.

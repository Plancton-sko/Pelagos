# Palagos Binary Wire Protocol & State Machine Specification

Palagos implements a compact binary protocol with zero JSON overhead to minimize packet size, parsing overhead, and vulnerability surface area.

---

## 1. Binary Packet Layout

Every network frame consists of a fixed-size header (203 bytes) followed by variable length payload and signature:

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       Protocol Version        | Message Type  |  Epoch (uint32|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Sequence Number (uint64)                |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                     Sender Fingerprint (32 bytes)             +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                   Recipient Fingerprint (32 bytes)            +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                 Ephemeral Public Key (32 bytes)               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                    XChaCha20 Nonce (24 bytes)                  +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Payload Length (uint32)                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
...                 Encrypted Payload (Variable)              ...
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                  Ed25519 Signature (64 bytes)                 +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

---

## 2. Message Types

| Value | Name | Description |
|---|---|---|
| `0x01` | `MessageTypeHandshakeInit` | Alice sends ephemeral X25519 key signed by Ed25519 identity |
| `0x02` | `MessageTypeHandshakeResp` | Bob replies with ephemeral X25519 key signed by Ed25519 identity |
| `0x03` | `MessageTypeData` | Encrypted Double Ratchet payload |
| `0x04` | `MessageTypeAck` | Delivery confirmation acknowledgment |
| `0x05` | `MessageTypeHeartbeat` | Transport keep-alive frame |

---

## 3. Associated Authenticated Data (AAD) Protection

The AEAD decryption step verifies that header fields have not been modified in transit by passing the following canonical byte slice into Poly1305 evaluation:

```text
AAD = Version (2) || Type (1) || Epoch (4) || Sequence (8) || SenderFP (32) || RecipientFP (32) || EphemeralPubKey (32)
```

If an attacker modifies `Sequence` from 5 to 4 or changes `SenderFP`, `DecryptAEAD` fails MAC tag verification and drops the packet.

---

## 4. Replay Protection Window State Machine

Palagos maintains a 64-bit sliding window bitmap to track received message sequence numbers:

```text
       Window Boundary: [maxSeq - 63, maxSeq]
[... maxSeq - 64] | [maxSeq - 63 ......... maxSeq] | [maxSeq + 1 ...]
   REJECT (Expired)           BITMAP TRACKING           ACCEPT (Shift Window)
```

1. **`seq > maxSeq`**: Shift bitmap left by `(seq - maxSeq)`, set bit 0, update `maxSeq = seq`.
2. **`seq <= maxSeq`**:
   - If `(maxSeq - seq) >= 64`: Reject (Packet outside window boundary).
   - If bit `(maxSeq - seq)` is 1: Reject (Duplicate / Replayed packet).
   - If bit `(maxSeq - seq)` is 0: Accept (Out-of-order packet), set bit to 1.

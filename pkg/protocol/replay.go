package protocol

import (
	"fmt"
	"sync"
)

// ReplayWindowSize is the size of the sliding bitmap window (64 sequence numbers).
const ReplayWindowSize = 64

// ReplayWindow implements a 64-bit sliding window replay protection algorithm.
//
// Attack Vectors Mitigated:
// In network protocols, an active adversary or malicious relay server may record valid encrypted packets
// and re-transmit them later (e.g. replaying a "Transfer $100" packet).
// Since the ciphertext is valid, AEAD decryption would succeed without explicit replay protection!
//
// Sliding Window Algorithm Mechanics:
// Let maxSeq be the highest verified sequence number received so far.
// The bitmap tracks the receipt of packets with sequence numbers in the range [maxSeq - 63, maxSeq].
//
// 1. If seq == 0: Invalid / reserved.
// 2. If seq > maxSeq: The packet is newer than any seen before. The window bitmask is shifted left by (seq - maxSeq),
//    bit 0 is set to 1, and maxSeq is updated to seq.
// 3. If seq <= maxSeq:
//   - If (maxSeq - seq) >= 64: The packet is too old (outside window boundary) -> REJECT.
//   - If (maxSeq - seq) < 64: Check bit at position (maxSeq - seq) in bitmap:
//     * If bit is 1: Packet was already received -> REJECT REPLAY.
//     * If bit is 0: Valid out-of-order packet. Set bit to 1 -> ACCEPT.
type ReplayWindow struct {
	mu     sync.Mutex
	maxSeq uint64
	bitmap uint64
}

// NewReplayWindow initializes an empty replay protection sliding window.
func NewReplayWindow() *ReplayWindow {
	return &ReplayWindow{}
}

// CheckAndAdd evaluates a sequence number against the sliding window.
// Returns true if packet sequence is valid and accepted, false if it is a replayed or expired packet.
func (rw *ReplayWindow) CheckAndAdd(seq uint64) bool {
	rw.mu.Lock()
	defer rw.mu.Unlock()

	if seq == 0 {
		return false
	}

	// Case 1: Sequence number is greater than maxSeq seen so far
	if seq > rw.maxSeq {
		diff := seq - rw.maxSeq
		if diff >= ReplayWindowSize {
			rw.bitmap = 1 // Shifted beyond entire window
		} else {
			rw.bitmap = (rw.bitmap << diff) | 1
		}
		rw.maxSeq = seq
		return true
	}

	// Case 2: Sequence number is less than or equal to maxSeq
	diff := rw.maxSeq - seq
	if diff >= ReplayWindowSize {
		// Packet is too old (outside the 64-bit window)
		return false
	}

	bitPos := uint64(1) << diff
	if (rw.bitmap & bitPos) != 0 {
		// Bit is already set: Duplicate / Replayed packet!
		return false
	}

	// Mark sequence number as received
	rw.bitmap |= bitPos
	return true
}

// MaxSeq returns the current highest sequence number seen.
func (rw *ReplayWindow) MaxSeq() uint64 {
	rw.mu.Lock()
	defer rw.mu.Unlock()
	return rw.maxSeq
}

// Reset clears the replay window (used when key epoch advances).
func (rw *ReplayWindow) Reset() {
	rw.mu.Lock()
	defer rw.mu.Unlock()
	rw.maxSeq = 0
	rw.bitmap = 0
}

// VerifyReplayWindow returns error if sequence number is invalid.
func (rw *ReplayWindow) VerifyReplayWindow(seq uint64) error {
	if !rw.CheckAndAdd(seq) {
		return fmt.Errorf("replay protection: packet sequence %d rejected (duplicate or out-of-bounds)", seq)
	}
	return nil
}

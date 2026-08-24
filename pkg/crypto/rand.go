package crypto

import (
	"crypto/rand"
	"fmt"
)

// SecureRandom generates n cryptographically secure random bytes using the system's CSPRNG
// (crypto/rand), which delegates to OS entropy sources such as getrandom(2) or /dev/urandom on Linux.
//
// Cryptographic Security Rationale:
// Standard pseudo-random number generators (PRNGs) like math/rand use deterministic linear congruential
// or Mersenne Twister algorithms. If an attacker observes a few outputs of math/rand, they can reconstruct
// the internal seed state and predict all future "random" outputs. For key generation, nonces, and salts,
// unpredictable entropy is mandatory.
func SecureRandom(n int) ([]byte, error) {
	if n <= 0 {
		return nil, fmt.Errorf("crypto: random byte count must be positive, got %d", n)
	}
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		// Entropy failure scenarios:
		// 1. Operating system entropy pool exhaustion during early boot.
		// 2. Failure of underlying kernel syscall (e.g. getrandom(2) error).
		// 3. VM state duplication/cloning where PRNG entropy state is duplicated across instances.
		return nil, fmt.Errorf("crypto: entropy failure in CSPRNG: %w", err)
	}
	return b, nil
}

// Zeroize explicitly overwrites a byte slice with zeros to mitigate key lingering in memory.
//
// Limits of Secure Deletion in Go:
// 1. Garbage Collection (GC): Go's runtime GC moves memory objects and creates copies during heap compaction/copying.
// 2. Stack vs Heap allocation: If a byte slice escapes to the heap, its historical locations in memory are not zeroed by GC.
// 3. Compiler Optimization: Compilers may optimize away zeroing loops if the variable is not used afterward.
// 4. OS Swap & Crash Dumps: Memory containing secrets may be written to disk swap partitions or core dump files.
//
// Despite these OS/runtime limitations, calling Zeroize immediately after a secret key's lifecycle ends reduces
// the temporal window of vulnerability for cold-boot or memory inspection attacks.
func Zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

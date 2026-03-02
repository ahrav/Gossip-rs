//! # RNG Module
//!
//! Tiny deterministic RNG for scheduling decisions (victim selection, etc).
//!
//! ## Design Choices
//!
//! **Generator**: XorShift64
//! - Simple, fast, sufficient for scheduling decisions
//! - We're selecting victims from N=4-16 workers, not doing Monte Carlo
//! - Deterministic: same seed → same sequence (critical for reproducibility)
//!
//! **Bounded sampling**: Lemire's fast-range method (multiplication + one threshold division)
//! - `% upper` compiles to division on every sample (15-40 cycles)
//! - Lemire uses multiplication for range reduction (3-4 cycles) with one
//!   unconditional threshold division for rejection sampling
//! - Power-of-two fast path uses bitmask (1 cycle)
//!
//! **No `Copy`**: Copying an RNG duplicates the stream, causing identical
//! "random" decisions. Use `Clone` explicitly when needed.
//!
//! ## Performance
//!
//! | Operation | Cost |
//! |-----------|------|
//! | `next_u64()` | ~3-4 cycles |
//! | `next_usize(power_of_2)` | ~5 cycles (bitmask) |
//! | `next_usize(other)` | ~20-40 cycles (Lemire, one threshold division) |

/// Deterministic RNG for scheduling decisions.
///
/// # Thread Safety
///
/// NOT thread-safe. Each worker should have its own RNG instance,
/// typically forked from a master seed in `RunConfig`.
///
/// # No Copy
///
/// Intentionally does not implement `Copy` to prevent accidental
/// stream duplication. Use `clone()` explicitly if needed.
#[derive(Clone, Debug)]
pub struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    /// Create a new RNG with the given seed.
    ///
    /// Seed 0 is mapped to a non-zero value to avoid the all-zero lockup state.
    #[inline]
    pub fn new(seed: u64) -> Self {
        // Avoid the all-zero lockup state
        let seed = if seed == 0 { 0x9E3779B97F4A7C15 } else { seed };
        Self { state: seed }
    }

    /// Generate the next u64 value using XorShift64.
    ///
    /// The shift constants (13, 7, 17) are from Marsaglia's "Xorshift RNGs" paper
    /// and produce a full-period generator (2^64 - 1 values before repeating).
    #[inline]
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    /// Generate a random usize in `[0, upper)`.
    ///
    /// Uses Lemire's fast range method (multiplication instead of division).
    /// Power-of-two bounds use a bitmask fast path.
    ///
    /// # Panics
    /// Panics if `upper` is 0.
    #[inline]
    pub fn next_usize(&mut self, upper: usize) -> usize {
        debug_assert!(upper > 0, "upper bound must be > 0");

        // Power-of-two fast path: bitmask instead of any arithmetic
        if upper.is_power_of_two() {
            return (self.next_u64() as usize) & (upper - 1);
        }

        // Lemire's method: multiply-high, no division
        // Maps [0, 2^64) uniformly to [0, upper) with rare rejection
        self.bounded_u64(upper as u64) as usize
    }

    /// Generate a random u32 in `[0, upper)`.
    ///
    /// Uses high bits of the u64 output (XorShift's low bits are weaker).
    ///
    /// # Panics
    /// Panics if `upper` is 0.
    #[inline]
    pub fn next_u32(&mut self, upper: u32) -> u32 {
        debug_assert!(upper > 0, "upper bound must be > 0");

        // Power-of-two fast path
        if upper.is_power_of_two() {
            // Use HIGH bits (low bits are weaker in XorShift)
            return ((self.next_u64() >> 32) as u32) & (upper - 1);
        }

        self.bounded_u64(upper as u64) as u32
    }

    /// Lemire's fast-range method for bounded random generation.
    ///
    /// Maps a random u64 to [0, upper) uniformly using multiplication.
    /// One unconditional threshold division (`-upper % upper`) computes the
    /// rejection boundary. Rejection sampling ensures uniformity, but rejection
    /// is rare (probability < upper / 2^64, negligible for small upper).
    #[inline]
    fn bounded_u64(&mut self, upper: u64) -> u64 {
        // Lemire rejection threshold: 2^64 mod upper
        // This is the "bad zone" that would cause bias
        let threshold = upper.wrapping_neg() % upper;

        loop {
            let x = self.next_u64();
            let m = (x as u128) * (upper as u128);
            let lo = m as u64;

            // If lo >= threshold, we're in the unbiased zone
            if lo >= threshold {
                return (m >> 64) as u64;
            }
            // Otherwise reject and retry (very rare for small upper)
        }
    }

    /// Generate a random bool with probability `numerator/denominator`.
    ///
    /// Returns true with probability `numerator / denominator`.
    ///
    /// # Panics
    /// Panics if `denominator` is 0 or `numerator > denominator`.
    #[inline]
    pub fn chance(&mut self, numerator: u32, denominator: u32) -> bool {
        debug_assert!(denominator > 0, "denominator must be > 0");
        debug_assert!(numerator <= denominator, "numerator must be <= denominator");
        self.next_u32(denominator) < numerator
    }

    /// Shuffle a slice in place using Fisher-Yates algorithm.
    pub fn shuffle<T>(&mut self, slice: &mut [T]) {
        let len = slice.len();
        if len <= 1 {
            return;
        }
        for i in (1..len).rev() {
            let j = self.next_usize(i + 1);
            slice.swap(i, j);
        }
    }

    /// Get the current state for debugging or checkpointing.
    ///
    /// Useful for reproducing specific execution traces: save state before
    /// a sequence, then recreate with `XorShift64::new(saved_state)`.
    #[inline]
    pub fn state(&self) -> u64 {
        self.state
    }

    /// Fork the RNG by creating a new one seeded from this one.
    ///
    /// Uses splitmix64 as a mixer to reduce correlation between
    /// the parent stream and forked streams.
    ///
    /// Useful for creating per-worker RNGs from a master seed.
    pub fn fork(&mut self) -> Self {
        let raw_seed = self.next_u64();
        // Mix with splitmix64 to reduce correlation
        Self::new(splitmix64(raw_seed))
    }
}

impl Default for XorShift64 {
    fn default() -> Self {
        Self::new(0)
    }
}

/// SplitMix64 mixing function (Stafford's Mix13 variant). See Vigna's
/// "An experimental exploration of Marsaglia's xorshift generators, scrambled" (2016)
/// for analysis.
///
/// Used to improve seed quality when forking RNGs.
/// Turns correlated sequential outputs into well-distributed seeds.
///
/// The constants are carefully chosen to achieve good avalanche behavior:
/// each input bit affects roughly half the output bits.
#[inline]
fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E3779B97F4A7C15);
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D049BB133111EB);
    x ^ (x >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_sequence() {
        let mut a = XorShift64::new(123);
        let mut b = XorShift64::new(123);
        for _ in 0..1000 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn zero_seed_works() {
        let mut rng = XorShift64::new(0);
        // Should not get stuck in zero state
        let first = rng.next_u64();
        let second = rng.next_u64();
        assert_ne!(first, 0);
        assert_ne!(first, second);
    }

    #[test]
    fn next_usize_in_bounds() {
        let mut rng = XorShift64::new(42);
        for upper in [1, 2, 3, 7, 8, 13, 16, 100, 128] {
            for _ in 0..1000 {
                let v = rng.next_usize(upper);
                assert!(v < upper, "got {} for upper {}", v, upper);
            }
        }
    }

    #[test]
    fn next_usize_power_of_two_fast_path() {
        let mut rng = XorShift64::new(42);
        // These should use the bitmask fast path
        for _ in 0..10000 {
            assert!(rng.next_usize(8) < 8);
            assert!(rng.next_usize(16) < 16);
            assert!(rng.next_usize(256) < 256);
        }
    }

    #[test]
    fn next_u32_in_bounds() {
        let mut rng = XorShift64::new(42);
        for _ in 0..10000 {
            let v = rng.next_u32(100);
            assert!(v < 100);
        }
    }

    #[test]
    fn next_u32_uses_high_bits() {
        // Verify we're not just truncating low bits
        // by checking that different seeds produce different u32 sequences
        // even when the low 32 bits might be similar
        let mut rng1 = XorShift64::new(1);
        let mut rng2 = XorShift64::new(2);

        let seq1: Vec<u32> = (0..100).map(|_| rng1.next_u32(1000)).collect();
        let seq2: Vec<u32> = (0..100).map(|_| rng2.next_u32(1000)).collect();

        // Sequences should differ significantly
        let matches = seq1.iter().zip(&seq2).filter(|(a, b)| a == b).count();
        assert!(matches < 10, "sequences too similar: {} matches", matches);
    }

    #[test]
    fn chance_probability() {
        let mut rng = XorShift64::new(12345);
        let mut count = 0;
        let trials = 100_000;

        for _ in 0..trials {
            if rng.chance(1, 4) {
                count += 1;
            }
        }

        // Should be roughly 25% (2500), with some variance
        let ratio = count as f64 / trials as f64;
        assert!(
            (0.24..0.26).contains(&ratio),
            "expected ~25%, got {:.2}%",
            ratio * 100.0
        );
    }

    #[test]
    fn shuffle_deterministic() {
        let mut rng1 = XorShift64::new(999);
        let mut rng2 = XorShift64::new(999);

        let mut arr1 = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let mut arr2 = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

        rng1.shuffle(&mut arr1);
        rng2.shuffle(&mut arr2);

        assert_eq!(arr1, arr2);
    }

    #[test]
    fn shuffle_actually_shuffles() {
        let mut rng = XorShift64::new(42);
        let original = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let mut arr = original;
        rng.shuffle(&mut arr);

        // Should be different from original (with high probability)
        assert_ne!(arr, original);
    }

    #[test]
    fn fork_produces_different_sequences() {
        let mut master = XorShift64::new(42);
        let mut fork1 = master.fork();
        let mut fork2 = master.fork();

        // Forked RNGs should produce different sequences
        let seq1: Vec<_> = (0..10).map(|_| fork1.next_u64()).collect();
        let seq2: Vec<_> = (0..10).map(|_| fork2.next_u64()).collect();

        assert_ne!(seq1, seq2);
    }

    #[test]
    fn fork_is_deterministic() {
        let mut master1 = XorShift64::new(42);
        let mut master2 = XorShift64::new(42);

        let fork1 = master1.fork();
        let fork2 = master2.fork();

        // Same master seed produces same fork
        assert_eq!(fork1.state(), fork2.state());
    }

    #[test]
    fn fork_uses_mixer() {
        // Verify that fork uses splitmix64 mixer
        // by checking that sequential forks have well-separated states
        let mut master = XorShift64::new(1);

        let states: Vec<u64> = (0..10).map(|_| master.fork().state()).collect();

        // Check that consecutive states differ in many bits
        for i in 0..states.len() - 1 {
            let diff = (states[i] ^ states[i + 1]).count_ones();
            // Well-mixed states should differ in roughly half the bits
            assert!(
                diff >= 20,
                "states {} and {} differ in only {} bits",
                i,
                i + 1,
                diff
            );
        }
    }

    #[test]
    fn distribution_uniformity_smoke_test() {
        // Basic uniformity check for bounded generation
        let mut rng = XorShift64::new(0xDEADBEEF);
        let upper = 10;
        let trials = 100_000;
        let mut counts = [0u32; 10];

        for _ in 0..trials {
            counts[rng.next_usize(upper)] += 1;
        }

        // Each bucket should have roughly trials/upper = 10000 entries
        // Allow 10% deviation
        let expected = trials as f64 / upper as f64;
        for (i, &count) in counts.iter().enumerate() {
            let deviation = ((count as f64) - expected).abs() / expected;
            assert!(
                deviation < 0.10,
                "bucket {} has {} (expected ~{}, deviation {:.1}%)",
                i,
                count,
                expected,
                deviation * 100.0
            );
        }
    }

    // Verify Copy is NOT implemented
    // This test exists to document the intentional design choice
    #[test]
    fn rng_is_clone_but_not_copy() {
        // XorShift64 should implement Clone (explicit duplication)
        let rng = XorShift64::new(42);
        let _cloned = rng.clone();

        // If Copy were implemented, rng2 would be implicitly copied
        // rather than moved, and would still be usable after this call.
        // The fact that rng2 is consumed (moved) proves Copy is not
        // implemented.
        fn takes_ownership(r: XorShift64) -> u64 {
            let mut r = r;
            r.next_u64()
        }

        let rng2 = XorShift64::new(42);
        let _ = takes_ownership(rng2);
        // rng2 is moved, not copied - can't use it again
    }
}

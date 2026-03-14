//! Deterministic RNG for simulation scheduling and fault injection.
//!
//! Uses xorshift64* for speed and stable output across platforms.
//! This is not cryptographically secure and must never be used for secrets.

/// Deterministic RNG with a single 64-bit state.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SimRng {
    state: u64,
}

impl SimRng {
    /// Create a new RNG. A zero seed is remapped to a non-zero constant to
    /// avoid the xorshift lockup state.
    pub fn new(seed: u64) -> Self {
        let s = if seed == 0 { 0x9E3779B97F4A7C15 } else { seed };
        Self { state: s }
    }

    /// Next 64-bit value from xorshift64*.
    #[inline(always)]
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }

    /// Generate a value in `[lo, hi_exclusive)`.
    #[inline(always)]
    pub fn gen_range(&mut self, lo: u32, hi_exclusive: u32) -> u32 {
        debug_assert!(lo < hi_exclusive);
        let span = (hi_exclusive - lo) as u64;
        (lo as u64 + (self.next_u64() % span)) as u32
    }

    /// Generate a boolean with probability `numerator / denominator`.
    #[inline(always)]
    pub fn gen_bool(&mut self, numerator: u32, denominator: u32) -> bool {
        debug_assert!(denominator > 0);
        debug_assert!(numerator <= denominator);
        (self.next_u64() % (denominator as u64)) < (numerator as u64)
    }
}

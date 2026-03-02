//! Monotonic simulated clock for deterministic scheduling.
//!
//! The clock only advances when the simulation explicitly moves time forward —
//! there is no wall-clock dependency. This makes all time-based logic
//! (rate limiters, backoff, TTLs) deterministic and replayable from a seed.
//!
//! Ticks are unitless; callers assign meaning (e.g. 1 tick = 1 ms of
//! simulated time). The only guarantee is monotonicity: `now_ticks()`
//! never decreases.

/// Tick-based simulated clock.
///
/// Invariant: the internal counter is monotonically non-decreasing.
/// `advance_to` enforces this with a debug assertion; `advance_by`
/// saturates at `u64::MAX` instead of wrapping.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SimClock {
    now: u64,
}

impl SimClock {
    /// Create a new clock at tick 0.
    pub fn new() -> Self {
        Self { now: 0 }
    }

    /// Current time in ticks.
    #[inline(always)]
    pub fn now_ticks(&self) -> u64 {
        self.now
    }

    /// Advance to an absolute tick.
    ///
    /// # Panics
    ///
    /// Debug-asserts that `t >= self.now` (monotonicity). In release
    /// builds the assertion is elided and the clock jumps unconditionally.
    #[inline(always)]
    pub fn advance_to(&mut self, t: u64) {
        debug_assert!(t >= self.now);
        self.now = t;
    }

    /// Advance by a relative delta, saturating at `u64::MAX`.
    #[inline(always)]
    pub fn advance_by(&mut self, dt: u64) {
        self.now = self.now.saturating_add(dt);
    }
}

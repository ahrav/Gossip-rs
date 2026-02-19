//! Deterministic simulation infrastructure for the coordination subsystem.
//!
//! Provides a seeded PRNG ([`SimContext`]), fault injection ([`FaultConfig`],
//! [`FaultLevel`]), simulated workers ([`SimWorker`]), external invariant
//! checking ([`InvariantChecker`], [`InvariantViolation`]), and a full
//! simulation harness ([`CoordinationSim`], [`SimOp`], [`SimEvent`],
//! [`SimReport`]).
//!
//! # Architecture
//!
//! The module is split into four layers:
//!
//! - **`mod.rs`** (this file) — [`SimContext`] (PRNG + clock) and
//!   [`FaultConfig`]/[`FaultLevel`] (fault injection rates). These are the
//!   building blocks; everything else composes them.
//! - **`worker`** — [`SimWorker`], a per-worker bookkeeping struct that tracks
//!   lease claims, op-ID generation (partitioned for cross-worker uniqueness),
//!   pause state, and cursor progress.
//! - **`invariants`** — [`InvariantChecker`], an external observer that verifies
//!   seven safety properties (S1–S7) against coordinator ground truth at every
//!   simulation step. It never trusts worker-side bookkeeping.
//! - **`harness`** — [`CoordinationSim`], the top-level driver. Runs a
//!   two-phase simulation (safety then liveness) with weighted random op
//!   generation, fault injection, and full invariant checking.
//!
//! # Determinism model
//!
//! All randomness flows through a single [`ChaCha8Rng`] seeded from a `u64`.
//! `ChaCha8Rng` is algorithm-specified (RFC 8439) and designed for portable
//! reproducibility (unlike `StdRng` which is explicitly non-portable).
//! Cargo.lock provides sufficient pinning.
//!
//! **Ordering matters**: the PRNG is a single stream. Any change to the order
//! or number of `rng` calls changes all subsequent random decisions for a
//! given seed. When adding new randomized logic, append calls rather than
//! inserting them between existing ones.
//!
//! Fault rates use integer parts-per-million (PPM) instead of `f64` to
//! eliminate IEEE 754 rounding variance across platforms and prevent invalid
//! probability construction.
//!
//! # Usage
//!
//! ```rust,no_run
//! use gossip_contracts::sim::{CoordinationSim, FaultLevel};
//! let report = CoordinationSim::new(42, FaultLevel::Stormy)
//!     .with_workers_and_shards(3, 5)
//!     .run(500, 200);
//! assert!(report.violations.is_empty());
//! ```
//!
//! # References
//!
//! - FoundationDB simulation (Zhou et al., SIGMOD 2021)
//! - TigerBeetle VOPR (deterministic simulation testing)
//! - sled simulation harness

pub mod backend;
pub mod fault_injector;
mod harness;
mod invariants;
mod worker;

pub use backend::{SimIntrospection, SimulationBackend};
pub use fault_injector::FaultInjectingIntrospector;
pub use harness::{CoordinationSim, RejectionKind, SimEvent, SimEventKind, SimOp, SimReport};
pub use invariants::{InvariantChecker, InvariantViolation};
pub use worker::SimWorker;

use rand::Rng;
use rand_chacha::ChaCha8Rng;
use rand_chacha::rand_core::SeedableRng;

use crate::identity::LogicalTime;

// ---------------------------------------------------------------------------
// SimContext
// ---------------------------------------------------------------------------

/// Seeded simulation context providing deterministic PRNG and logical clock.
///
/// All random decisions in a simulation run flow through the single
/// [`ChaCha8Rng`] owned here, ensuring reproducibility from a `u64` seed.
///
/// # Invariants
///
/// - **Clock monotonicity**: `clock` never moves backward. Both [`advance`](Self::advance)
///   and [`advance_to`](Self::advance_to) enforce this with panics, preventing
///   immortal leases or time-travel bugs.
/// - **Single PRNG stream**: the `rng` field is the sole source of randomness.
///   Forking or cloning the RNG would break determinism.
pub struct SimContext {
    rng: ChaCha8Rng,
    clock: LogicalTime,
    seed: u64,
}

impl SimContext {
    /// Create a new simulation context from a seed.
    ///
    /// The clock starts at [`LogicalTime::ZERO`].
    pub fn new(seed: u64) -> Self {
        let ctx = Self {
            rng: ChaCha8Rng::seed_from_u64(seed),
            clock: LogicalTime::ZERO,
            seed,
        };
        debug_assert_eq!(ctx.clock, LogicalTime::ZERO);
        debug_assert_eq!(ctx.seed, seed);
        ctx
    }

    /// Current logical time.
    #[must_use]
    pub fn now(&self) -> LogicalTime {
        self.clock
    }

    /// Advance the clock by `ticks`.
    ///
    /// # Panics
    ///
    /// Panics on overflow (prevents immortal leases).
    pub fn advance(&mut self, ticks: u64) {
        self.clock = self
            .clock
            .checked_add(ticks)
            .expect("SimContext::advance: LogicalTime overflow");
    }

    /// Advance the clock to an absolute time (forward-only).
    ///
    /// # Panics
    ///
    /// Panics if `time < self.clock` -- the clock is monotonic.
    pub fn advance_to(&mut self, time: LogicalTime) {
        assert!(
            time >= self.clock,
            "SimContext::advance_to: cannot move clock backward ({} -> {})",
            self.clock.as_raw(),
            time.as_raw(),
        );
        self.clock = time;
    }

    /// Mutable reference to the seeded PRNG.
    ///
    /// **Determinism note**: the PRNG is a sequential stream. Every call to
    /// `rng().random()`, `rng().random_range()`, etc. consumes state and
    /// advances the stream position. Adding, removing, or reordering calls
    /// changes all downstream random decisions for a given seed. Treat the
    /// call sequence as part of the simulation's contract.
    pub fn rng(&mut self) -> &mut ChaCha8Rng {
        &mut self.rng
    }

    /// The seed this context was created with.
    #[must_use]
    pub fn seed(&self) -> u64 {
        self.seed
    }
}

// ---------------------------------------------------------------------------
// FaultLevel
// ---------------------------------------------------------------------------

/// Fault injection severity level.
///
/// Discriminants are stable; match exhaustively only with `_` fallback
/// (`#[non_exhaustive]`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
#[repr(u8)]
pub enum FaultLevel {
    /// No faults injected.
    SunnyDay = 1,
    /// Moderate fault rate -- ~10% time jump, ~10% lease expiry, ~5% pause.
    Stormy = 2,
    /// Aggressive fault rate -- ~20% time jump, ~20% lease expiry, ~10% pause.
    Radioactive = 3,
}

// Tiger-style discriminant assertion.
const _: () = {
    assert!(FaultLevel::SunnyDay as u8 == 1);
    assert!(FaultLevel::Stormy as u8 == 2);
    assert!(FaultLevel::Radioactive as u8 == 3);
};

// ---------------------------------------------------------------------------
// FaultConfig
// ---------------------------------------------------------------------------

/// Maximum value for PPM rates (parts-per-million).
const PPM_MAX: u32 = 1_000_000;

/// Fault injection configuration using integer PPM rates.
///
/// Rates are expressed as parts-per-million (0–1 000 000) to eliminate
/// floating-point non-determinism across platforms. Private fields enforce
/// validity; use [`FaultConfig::for_level`] to construct.
///
/// # Building blocks vs. built-in harness
///
/// The public methods on this struct ([`should_expire_lease`](Self::should_expire_lease),
/// [`should_pause`](Self::should_pause), [`should_time_jump`](Self::should_time_jump),
/// [`pause_ticks`](Self::pause_ticks), [`time_jump_ticks`](Self::time_jump_ticks)) are
/// building blocks for custom simulation drivers. The built-in
/// [`CoordinationSim::run`](CoordinationSim::run) does **not** call
/// `should_expire_lease` or `should_pause` directly — it generates operations via
/// weighted random op selection and injects faults through `should_time_jump` only.
/// If you are writing your own simulation loop, you can call any of these methods
/// to tailor fault injection to your scenario.
///
/// # Fields (sealed)
///
/// | Field | Semantics |
/// |-------|-----------|
/// | `lease_expiry_ppm` | Probability of force-expiring the current lease holder each step. |
/// | `pause_ppm` | Probability of stalling a worker (simulates GC pause / network partition). |
/// | `pause_range` | Tick duration range for a pause fault. |
/// | `time_jump_ppm` | Probability of an unannounced clock jump (simulates NTP skew / VM migration). |
/// | `time_jump_range` | Tick magnitude range for a time-jump fault. |
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FaultConfig {
    lease_expiry_ppm: u32,
    pause_ppm: u32,
    pause_range: core::ops::RangeInclusive<u64>,
    time_jump_ppm: u32,
    time_jump_range: core::ops::RangeInclusive<u64>,
}

impl FaultConfig {
    /// Construct a `FaultConfig` for the given severity level.
    #[must_use]
    pub fn for_level(level: FaultLevel) -> Self {
        match level {
            FaultLevel::SunnyDay => Self {
                lease_expiry_ppm: 0,
                pause_ppm: 0,
                pause_range: 0..=0,
                time_jump_ppm: 0,
                time_jump_range: 0..=0,
            },
            FaultLevel::Stormy => Self {
                lease_expiry_ppm: 100_000, // 10%
                pause_ppm: 50_000,         // 5%
                pause_range: 1..=5,
                time_jump_ppm: 100_000, // 10%
                time_jump_range: 50..=200,
            },
            FaultLevel::Radioactive => Self {
                lease_expiry_ppm: 200_000, // 20%
                pause_ppm: 100_000,        // 10%
                pause_range: 1..=10,
                time_jump_ppm: 200_000, // 20%
                time_jump_range: 100..=500,
            },
        }
    }

    /// Whether to inject a lease-expiry fault this step.
    ///
    /// Available for custom simulation drivers; the built-in
    /// [`CoordinationSim::run`](CoordinationSim::run)
    /// does not call this method directly.
    pub fn should_expire_lease(&self, rng: &mut ChaCha8Rng) -> bool {
        should_inject(rng, self.lease_expiry_ppm)
    }

    /// Whether to inject a worker-pause fault this step.
    ///
    /// Available for custom simulation drivers; the built-in
    /// [`CoordinationSim::run`](CoordinationSim::run)
    /// does not call this method directly.
    pub fn should_pause(&self, rng: &mut ChaCha8Rng) -> bool {
        should_inject(rng, self.pause_ppm)
    }

    /// Random pause duration within the configured range.
    pub fn pause_ticks(&self, rng: &mut ChaCha8Rng) -> u64 {
        if self.pause_range.is_empty() {
            return 0;
        }
        rng.random_range(self.pause_range.clone())
    }

    /// Whether to inject a time-jump fault this step.
    pub fn should_time_jump(&self, rng: &mut ChaCha8Rng) -> bool {
        should_inject(rng, self.time_jump_ppm)
    }

    /// Random time-jump duration within the configured range.
    pub fn time_jump_ticks(&self, rng: &mut ChaCha8Rng) -> u64 {
        if self.time_jump_range.is_empty() {
            return 0;
        }
        rng.random_range(self.time_jump_range.clone())
    }
}

/// Deterministic fault injection: returns `true` with probability `ppm / 1_000_000`.
///
/// The draw is uniform over `[0, 1_000_000)` (exclusive upper bound), so
/// `ppm = 0` never fires and `ppm = 1_000_000` always fires. The
/// `assert` rejects out-of-range values that would silently skew
/// injection rates.
fn should_inject(rng: &mut ChaCha8Rng, ppm: u32) -> bool {
    if ppm == 0 {
        return false;
    }
    assert!(ppm <= PPM_MAX, "PPM rate {ppm} exceeds maximum {PPM_MAX}");
    rng.random_range(0u32..PPM_MAX) < ppm
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // -- SimContext: kept unit tests ------------------------------------------

    #[test]
    fn sim_context_different_seeds_differ() {
        let mut a = SimContext::new(1);
        let mut b = SimContext::new(2);
        let vals_a: Vec<u32> = (0..100).map(|_| a.rng().random()).collect();
        let vals_b: Vec<u32> = (0..100).map(|_| b.rng().random()).collect();
        assert_ne!(vals_a, vals_b);
    }

    #[test]
    #[should_panic(expected = "LogicalTime overflow")]
    fn sim_context_advance_overflow_panics() {
        let mut ctx = SimContext::new(0);
        ctx.advance(u64::MAX);
        ctx.advance(1);
    }

    #[test]
    #[should_panic(expected = "cannot move clock backward")]
    fn sim_context_advance_to_backward_panics() {
        let mut ctx = SimContext::new(0);
        ctx.advance(10);
        ctx.advance_to(LogicalTime::from_raw(5));
    }

    #[test]
    fn sim_context_seed_round_trip() {
        let ctx = SimContext::new(12345);
        assert_eq!(ctx.seed(), 12345);
    }

    // -- FaultLevel / FaultConfig: kept unit tests ----------------------------

    #[test]
    fn fault_level_ordering() {
        assert!(FaultLevel::SunnyDay < FaultLevel::Stormy);
        assert!(FaultLevel::Stormy < FaultLevel::Radioactive);
    }

    #[test]
    fn fault_config_ppm_values_valid() {
        for level in [
            FaultLevel::SunnyDay,
            FaultLevel::Stormy,
            FaultLevel::Radioactive,
        ] {
            let cfg = FaultConfig::for_level(level);
            assert!(cfg.lease_expiry_ppm <= PPM_MAX);
            assert!(cfg.pause_ppm <= PPM_MAX);
            assert!(cfg.time_jump_ppm <= PPM_MAX);
        }
    }

    // -- Property-based tests -------------------------------------------------

    proptest! {
        #![proptest_config(crate::test_util::miri_proptest_config())]

        /// Same seed always produces identical PRNG sequences.
        #[test]
        fn prop_deterministic_for_any_seed(seed: u64) {
            let mut a = SimContext::new(seed);
            let mut b = SimContext::new(seed);
            let vals_a: Vec<u32> = (0..100).map(|_| a.rng().random()).collect();
            let vals_b: Vec<u32> = (0..100).map(|_| b.rng().random()).collect();
            prop_assert_eq!(vals_a, vals_b);
        }

        /// Clock equals the sum of all advances; `advance_to` reaches target.
        #[test]
        fn prop_clock_advances_are_additive(
            steps in proptest::collection::vec(0..500u64, 1..10),
            jump_offset in 1..500u64,
        ) {
            let mut ctx = SimContext::new(0);
            let mut total = 0u64;
            for &s in &steps {
                ctx.advance(s);
                total += s;
            }
            prop_assert_eq!(ctx.now(), LogicalTime::from_raw(total));

            let target = total + jump_offset;
            ctx.advance_to(LogicalTime::from_raw(target));
            prop_assert_eq!(ctx.now(), LogicalTime::from_raw(target));
        }

        /// Fault rates are monotonic: SunnyDay(0) <= Stormy <= Radioactive.
        #[test]
        fn prop_fault_rates_monotonic_across_levels(seed: u64) {
            let cfgs = [
                FaultConfig::for_level(FaultLevel::SunnyDay),
                FaultConfig::for_level(FaultLevel::Stormy),
                FaultConfig::for_level(FaultLevel::Radioactive),
            ];
            let n = 1_000;

            // lease-expiry
            let counts: Vec<usize> = cfgs.iter().map(|cfg| {
                let mut ctx = SimContext::new(seed);
                (0..n).filter(|_| cfg.should_expire_lease(ctx.rng())).count()
            }).collect();
            prop_assert_eq!(counts[0], 0, "SunnyDay must never inject");
            prop_assert!(counts[1] > 0, "Stormy must inject at least once over {n} draws");
            prop_assert!(
                counts[2] >= counts[1],
                "Radioactive ({}) must be >= Stormy ({})",
                counts[2], counts[1],
            );

            // pause
            let pause_counts: Vec<usize> = cfgs.iter().map(|cfg| {
                let mut ctx = SimContext::new(seed);
                (0..n).filter(|_| cfg.should_pause(ctx.rng())).count()
            }).collect();
            prop_assert_eq!(pause_counts[0], 0);
            prop_assert!(pause_counts[1] > 0, "Stormy pause must fire at least once");
            prop_assert!(pause_counts[2] >= pause_counts[1]);

            // time-jump
            let jump_counts: Vec<usize> = cfgs.iter().map(|cfg| {
                let mut ctx = SimContext::new(seed);
                (0..n).filter(|_| cfg.should_time_jump(ctx.rng())).count()
            }).collect();
            prop_assert_eq!(jump_counts[0], 0);
            prop_assert!(jump_counts[1] > 0, "Stormy time-jump must fire at least once");
            prop_assert!(jump_counts[2] >= jump_counts[1]);
        }
    }
}

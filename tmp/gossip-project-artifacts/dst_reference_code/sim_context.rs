//! Deterministic simulation testing (DST) primitives.
//!
//! Provides [`SimContext`] — a deterministic execution context that bundles a
//! seeded PRNG, a simulated logical clock, and fault injection configuration.
//! This is the foundation for simulation-testable coordination code, following
//! the FoundationDB pattern of making time and randomness explicit inputs.
//!
//! # Evidence
//!
//! - FoundationDB (SIGMOD 2021): abstract IO, seeded PRNG, time as input
//! - TigerBeetle VOPR: progressive difficulty levels for fault injection
//! - sled (simulation.html): discrete-event simulation with priority queue
//!
//! # Feature gate
//!
//! This module is only available when the `test-support` feature is enabled.

use rand::SeedableRng;
use rand::rngs::StdRng;

use crate::coordination::LogicalTime;

/// Deterministic execution context for simulation testing.
///
/// Bundles a seeded PRNG and simulated clock so that all randomness and
/// time-dependent decisions are reproducible given the same seed.
///
/// # Reproduction
///
/// To reproduce a simulation failure, create a `SimContext` with the same
/// `seed` value. All operations that draw from `rng` or read `clock` will
/// produce identical results.
///
/// # Example
///
/// ```
/// use gossip_contracts::sim::SimContext;
///
/// let mut ctx = SimContext::new(42);
/// assert_eq!(ctx.now().0, 0);
///
/// ctx.advance(10);
/// assert_eq!(ctx.now().0, 10);
/// ```
pub struct SimContext {
    rng: StdRng,
    clock: LogicalTime,
    seed: u64,
}

impl SimContext {
    /// Create a new simulation context with the given seed.
    ///
    /// The clock starts at `LogicalTime::ZERO` and the PRNG is seeded
    /// deterministically from `seed`.
    pub fn new(seed: u64) -> Self {
        Self {
            rng: StdRng::seed_from_u64(seed),
            clock: LogicalTime::ZERO,
            seed,
        }
    }

    /// Return the current simulated time.
    #[inline]
    pub fn now(&self) -> LogicalTime {
        self.clock
    }

    /// Advance the simulated clock by `ticks`.
    #[inline]
    pub fn advance(&mut self, ticks: u64) {
        self.clock = self.clock.advance(ticks);
    }

    /// Set the clock to a specific time.
    ///
    /// # Panics
    ///
    /// Panics in debug builds if `time` is less than the current clock
    /// (time must not go backwards).
    #[inline]
    pub fn set_time(&mut self, time: LogicalTime) {
        debug_assert!(
            time >= self.clock,
            "SimContext::set_time: time must not go backwards ({:?} < {:?})",
            time,
            self.clock,
        );
        self.clock = time;
    }

    /// Access the seeded PRNG for deterministic randomness.
    #[inline]
    pub fn rng(&mut self) -> &mut StdRng {
        &mut self.rng
    }

    /// Return the seed used to create this context.
    ///
    /// Use this value in failure reports so that the simulation can be
    /// reproduced exactly.
    #[inline]
    pub fn seed(&self) -> u64 {
        self.seed
    }
}

/// Fault injection severity levels, following TigerBeetle's VOPR pattern.
///
/// | Level | Name | Description |
/// |-------|------|-------------|
/// | 1 | Sunny Day | No faults — perfect conditions |
/// | 2 | Stormy | Network partitions, lease expiry, message loss, clock skew |
/// | 3 | Radioactive | Storage corruption, cascading failures, Byzantine faults |
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FaultLevel {
    /// No faults injected — perfect conditions.
    SunnyDay = 1,
    /// Network partitions, lease expiry, message loss/reorder, clock skew.
    Stormy = 2,
    /// Storage corruption, cascading failures, Byzantine faults, all Level 2 combined.
    Radioactive = 3,
}

/// Configuration for fault injection in simulation harnesses.
///
/// Each field controls a specific class of faults. Set all to zero/empty
/// for [`FaultLevel::SunnyDay`].
#[derive(Debug, Clone, Default)]
pub struct FaultConfig {
    /// Message/effect drop probability (0.0 = none, 1.0 = all).
    pub drop_rate: f64,
    /// Maximum message delivery delay in logical ticks (0 = instant).
    pub max_delay: u64,
    /// Whether to inject process pauses (freeze clock for a node).
    pub inject_pauses: bool,
    /// Pause duration range in ticks `[min, max]`.
    pub pause_range: (u64, u64),
    /// Whether to inject lease expiry by advancing time past deadline.
    pub inject_lease_expiry: bool,
    /// Whether to inject storage corruption (backend returns garbage).
    pub inject_storage_corruption: bool,
}

impl FaultConfig {
    /// Create a fault config for the given severity level.
    pub fn for_level(level: FaultLevel) -> Self {
        match level {
            FaultLevel::SunnyDay => Self::default(),
            FaultLevel::Stormy => Self {
                drop_rate: 0.1,
                max_delay: 50,
                inject_pauses: true,
                pause_range: (10, 100),
                inject_lease_expiry: true,
                inject_storage_corruption: false,
            },
            FaultLevel::Radioactive => Self {
                drop_rate: 0.3,
                max_delay: 200,
                inject_pauses: true,
                pause_range: (10, 500),
                inject_lease_expiry: true,
                inject_storage_corruption: true,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sim_context_deterministic() {
        use rand::Rng;

        let mut ctx1 = SimContext::new(42);
        let mut ctx2 = SimContext::new(42);

        let v1: u64 = ctx1.rng().random();
        let v2: u64 = ctx2.rng().random();
        assert_eq!(v1, v2, "same seed must produce same random values");
    }

    #[test]
    fn sim_context_clock_advance() {
        let mut ctx = SimContext::new(0);
        assert_eq!(ctx.now(), LogicalTime::ZERO);

        ctx.advance(10);
        assert_eq!(ctx.now(), LogicalTime(10));

        ctx.advance(5);
        assert_eq!(ctx.now(), LogicalTime(15));
    }

    #[test]
    fn sim_context_set_time() {
        let mut ctx = SimContext::new(0);
        ctx.set_time(LogicalTime(100));
        assert_eq!(ctx.now(), LogicalTime(100));
    }

    #[test]
    #[should_panic(expected = "time must not go backwards")]
    fn sim_context_set_time_backwards_panics() {
        let mut ctx = SimContext::new(0);
        ctx.advance(50);
        ctx.set_time(LogicalTime(10));
    }

    #[test]
    fn sim_context_seed_recovery() {
        let ctx = SimContext::new(12345);
        assert_eq!(ctx.seed(), 12345);
    }

    #[test]
    fn fault_config_levels() {
        let sunny = FaultConfig::for_level(FaultLevel::SunnyDay);
        assert_eq!(sunny.drop_rate, 0.0);
        assert!(!sunny.inject_pauses);
        assert!(!sunny.inject_storage_corruption);

        let stormy = FaultConfig::for_level(FaultLevel::Stormy);
        assert!(stormy.drop_rate > 0.0);
        assert!(stormy.inject_pauses);
        assert!(!stormy.inject_storage_corruption);

        let radioactive = FaultConfig::for_level(FaultLevel::Radioactive);
        assert!(radioactive.drop_rate > stormy.drop_rate);
        assert!(radioactive.inject_storage_corruption);
    }

    #[test]
    fn different_seeds_produce_different_values() {
        use rand::Rng;

        let mut ctx1 = SimContext::new(1);
        let mut ctx2 = SimContext::new(2);

        let v1: u64 = ctx1.rng().random();
        let v2: u64 = ctx2.rng().random();
        // Extremely unlikely to be equal with different seeds.
        assert_ne!(v1, v2);
    }
}

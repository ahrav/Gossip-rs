//! Deterministic simulation harness for [`InMemoryDoneLedger`].
//!
//! Generates random `batch_upsert`/`batch_get` sequences via seeded
//! [`ChaCha8Rng`], injects persistence faults at configurable PPM rates,
//! and verifies invariants I1–I10 after every operation.
//!
//! # Architecture
//!
//! Follows the same layered pattern as the coordination sim:
//!
//! | Layer | Module | Contents |
//! |-------|--------|----------|
//! | Foundation | `mod.rs` | `SimContext`, `FaultConfig`, `FaultLevel`, op/event types, `PersistenceSim` trait |
//! | Invariants | `invariants.rs` | `DoneLedgerInvariantChecker`, per-step I1–I10 checking |
//! | Oracle | `oracle.rs` | `DoneLedgerOracle`, HashMap-based model for convergence verification |
//! | Driver | `harness.rs` | `DoneLedgerSim`, weighted op generation, safety/liveness phases |
//!
//! # Determinism
//!
//! All randomness flows through a single `ChaCha8Rng` stream seeded at
//! construction. Appending new PRNG draws at the end of a step is safe;
//! inserting draws in the middle changes all downstream decisions. This
//! matches the coordination sim's determinism contract.
//!
//! [`InMemoryDoneLedger`]: crate::InMemoryDoneLedger
//! [`ChaCha8Rng`]: rand_chacha::ChaCha8Rng

mod harness;
mod invariants;
mod oracle;
#[cfg(test)]
mod tests;

pub use harness::{DoneLedgerFaultConfig, DoneLedgerSim, DoneLedgerSimReport};
pub use invariants::{DoneLedgerInvariantChecker, DoneLedgerInvariantViolation};
pub use oracle::DoneLedgerOracle;

use gossip_contracts::persistence::{DoneLedgerCommitReceipt, DoneLedgerRecord};
use rand::Rng;
use rand_chacha::ChaCha8Rng;

use crate::{CompletionOrder, PendingWriteId};

// ── PPM constants ────────────────────────────────────────────────────

/// Parts-per-million ceiling. Integer PPM rates avoid IEEE 754 rounding
/// variance across platforms.
const PPM_MAX: u32 = 1_000_000;

/// Returns `true` with probability `ppm / 1_000_000`.
fn should_inject(rng: &mut ChaCha8Rng, ppm: u32) -> bool {
    if ppm == 0 {
        return false;
    }
    assert!(ppm <= PPM_MAX);
    rng.random_range(0u32..PPM_MAX) < ppm
}

// ── SimContext ────────────────────────────────────────────────────────

/// Deterministic PRNG wrapper. All randomness in a simulation run flows
/// through a single `ChaCha8Rng` seeded at construction time.
#[derive(Debug)]
pub struct SimContext {
    rng: ChaCha8Rng,
    seed: u64,
    step_counter: u64,
}

impl SimContext {
    /// Create a new context from a seed.
    pub fn new(seed: u64) -> Self {
        use rand::SeedableRng;
        Self {
            rng: ChaCha8Rng::seed_from_u64(seed),
            seed,
            step_counter: 0,
        }
    }

    /// The seed used to construct this context.
    pub fn seed(&self) -> u64 {
        self.seed
    }

    /// Monotonic step counter, incremented by the harness after each op.
    pub fn step_counter(&self) -> u64 {
        self.step_counter
    }

    /// Advance the step counter by one.
    pub fn tick(&mut self) {
        self.step_counter = self
            .step_counter
            .checked_add(1)
            .expect("step counter overflow");
    }

    /// Sole randomness source for the simulation.
    pub fn rng(&mut self) -> &mut ChaCha8Rng {
        &mut self.rng
    }
}

// ── FaultLevel ───────────────────────────────────────────────────────

/// Fault severity presets following the TigerBeetle VOPR pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum FaultLevel {
    /// No faults injected.
    SunnyDay = 1,
    /// Moderate fault rates (~10% each counter).
    Stormy = 2,
    /// Aggressive fault rates (~20% each counter).
    Radioactive = 3,
}

// Validate that discriminants match expectations.
const _: () = {
    assert!(FaultLevel::SunnyDay as u8 == 1);
    assert!(FaultLevel::Stormy as u8 == 2);
    assert!(FaultLevel::Radioactive as u8 == 3);
};

// ── DoneLedgerSimOp ──────────────────────────────────────────────────

/// Operations the harness can execute against the ledger.
#[derive(Debug, Clone)]
pub enum DoneLedgerSimOp {
    /// Submit a batch of records via `batch_upsert`.
    BatchUpsert { records: Vec<DoneLedgerRecord> },

    /// Read records via `batch_get`.
    BatchGet { ovid_indices: Vec<usize> },

    /// Release the oldest pending delayed write.
    ReleaseOldest,

    /// Release the newest pending delayed write.
    ReleaseNewest,

    /// Release a specific pending write by ID.
    ReleaseSpecific { op_id: PendingWriteId },

    /// Release all pending writes in the given order.
    ReleaseAll { order: CompletionOrder },

    /// Configure N upcoming submissions to fail.
    InjectSubmitFailure { count: usize },

    /// Configure N upcoming commits to fail.
    InjectCommitFailure { count: usize },

    /// Configure N upcoming writes to be delayed.
    InjectDelay { count: usize },
}

impl DoneLedgerSimOp {
    /// Returns `true` for ops that configure fault injection counters
    /// (as opposed to data or release operations).
    pub fn is_fault_injection(&self) -> bool {
        matches!(
            self,
            Self::InjectSubmitFailure { .. }
                | Self::InjectCommitFailure { .. }
                | Self::InjectDelay { .. }
        )
    }
}

// ── DoneLedgerSimEvent ───────────────────────────────────────────────

/// Outcomes produced by executing a [`DoneLedgerSimOp`].
#[derive(Debug, Clone)]
pub enum DoneLedgerSimEvent {
    /// `batch_upsert` succeeded and commit completed immediately.
    UpsertCommitted {
        op_id: PendingWriteId,
        receipt: DoneLedgerCommitReceipt,
    },

    /// `batch_upsert` succeeded but write is delayed (pending release).
    UpsertPending { op_id: PendingWriteId },

    /// `batch_upsert` failed at submission time (injected failure).
    UpsertSubmitFailed,

    /// `batch_upsert` succeeded but commit failed at auto-complete time.
    UpsertCommitFailed { op_id: PendingWriteId },

    /// `batch_get` returned results.
    GetOk {
        results: Vec<Option<DoneLedgerRecord>>,
    },

    /// A specific pending write was released and committed.
    Released {
        op_id: PendingWriteId,
        receipt: DoneLedgerCommitReceipt,
    },

    /// A specific pending write was released but commit failed.
    ReleasedCommitFailed { op_id: PendingWriteId },

    /// All pending writes were released.
    ReleasedAll {
        count: usize,
        committed: usize,
        failed: usize,
    },

    /// No pending writes to release.
    ReleaseNoop,

    /// Fault injection counter was configured.
    FaultConfigured,
}

// ── DoneLedgerSimEventKind ───────────────────────────────────────────

/// Allocation-free discriminant for event histogram tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DoneLedgerSimEventKind {
    UpsertCommitted,
    UpsertPending,
    UpsertSubmitFailed,
    UpsertCommitFailed,
    GetOk,
    Released,
    ReleasedCommitFailed,
    ReleasedAll,
    ReleaseNoop,
    FaultConfigured,
}

impl DoneLedgerSimEventKind {
    /// All event kinds emitted by [`DoneLedgerSimEvent::kind`].
    pub const ALL: [Self; 10] = [
        Self::UpsertCommitted,
        Self::UpsertPending,
        Self::UpsertSubmitFailed,
        Self::UpsertCommitFailed,
        Self::GetOk,
        Self::Released,
        Self::ReleasedCommitFailed,
        Self::ReleasedAll,
        Self::ReleaseNoop,
        Self::FaultConfigured,
    ];
}

impl DoneLedgerSimEvent {
    /// Map to the histogram discriminant.
    pub fn kind(&self) -> DoneLedgerSimEventKind {
        match self {
            Self::UpsertCommitted { .. } => DoneLedgerSimEventKind::UpsertCommitted,
            Self::UpsertPending { .. } => DoneLedgerSimEventKind::UpsertPending,
            Self::UpsertSubmitFailed => DoneLedgerSimEventKind::UpsertSubmitFailed,
            Self::UpsertCommitFailed { .. } => DoneLedgerSimEventKind::UpsertCommitFailed,
            Self::GetOk { .. } => DoneLedgerSimEventKind::GetOk,
            Self::Released { .. } => DoneLedgerSimEventKind::Released,
            Self::ReleasedCommitFailed { .. } => DoneLedgerSimEventKind::ReleasedCommitFailed,
            Self::ReleasedAll { .. } => DoneLedgerSimEventKind::ReleasedAll,
            Self::ReleaseNoop => DoneLedgerSimEventKind::ReleaseNoop,
            Self::FaultConfigured => DoneLedgerSimEventKind::FaultConfigured,
        }
    }
}

// ── PersistenceSim trait ─────────────────────────────────────────────

/// Integration hook for composing persistence simulation with the
/// coordination sim. No consumers yet — this establishes the interface
/// contract for future composition.
pub trait PersistenceSim {
    /// The operation type driven by the harness.
    type Op;
    /// The event type produced after execution.
    type Event;
    /// The violation type emitted by the invariant checker.
    type Violation;

    /// Execute one operation, run invariant checks, return the outcome
    /// and any violations detected.
    fn step(&mut self, op: Self::Op) -> (Self::Event, Vec<Self::Violation>);
}

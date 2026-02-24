//! Overload scenario definitions and helpers for scripted stress runs.
//!
//! These workloads are intentionally **deterministic scripts** rather than
//! pure random generation: when an overload regression appears, we want a
//! short, reproducible sequence that isolates one pressure pattern
//! (`BurstClaim`, `CapacityDrop`, or `BurstShards`) and is easy to replay
//! under a fixed seed.
//!
//! The harness wraps these scripts with warmup and recovery phases. This
//! module only defines:
//!
//! - scenario descriptors (`OverloadKind`, `OverloadScenario`)
//! - lightweight liveness/diagnostic telemetry (`GoodputTracker`,
//!   `D1Observation`, `OverloadReport`)
//! - operation burst generators consumed by `CoordinationSim::run_overload`

use std::collections::BTreeMap;

use crate::identity::{LogicalTime, ShardKey, WorkerId};

use super::harness::{SimEvent, SimEventKind, SimOp};
use super::invariants::InvariantViolation;

/// Scripted overload workload kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverloadKind {
    /// All workers attempt to claim in a burst.
    BurstClaim,
    /// Pause half the workers, then advance time to force lease churn.
    CapacityDrop,
    /// Attempt split-replace on all currently held shards.
    BurstShards,
}

/// Scenario configuration for overload runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OverloadScenario {
    /// Which scripted pressure pattern to execute each round.
    pub kind: OverloadKind,
    /// Number of scripted rounds to execute.
    ///
    /// `0` is valid and means "warmup + recovery only" (no overload rounds).
    pub rounds: u32,
}

impl OverloadScenario {
    /// Create an overload scenario descriptor.
    #[must_use]
    pub const fn new(kind: OverloadKind, rounds: u32) -> Self {
        Self { kind, rounds }
    }
}

/// Tracks completion goodput during scripted overload rounds.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct GoodputTracker {
    completions: u64,
    total_ops: u64,
}

impl GoodputTracker {
    /// Record one executed event.
    ///
    /// This counter is phase-agnostic; callers decide which events to feed in.
    /// `run_overload` records only scripted overload events to keep the
    /// goodput metric focused on pressure behavior rather than warmup/recovery.
    pub fn record(&mut self, event: &SimEvent) {
        self.total_ops = self
            .total_ops
            .checked_add(1)
            .expect("goodput total_ops overflow");
        if matches!(event, SimEvent::CompleteOk) {
            self.completions = self
                .completions
                .checked_add(1)
                .expect("goodput completions overflow");
        }
    }

    /// Completion ratio in `[0.0, 1.0]`.
    #[must_use]
    pub fn rate(&self) -> f64 {
        if self.total_ops == 0 {
            0.0
        } else {
            self.completions as f64 / self.total_ops as f64
        }
    }
}

/// D1 diagnostic sample at a point in simulated time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct D1Observation {
    /// Logical time at which the sample was captured.
    pub at: LogicalTime,
    /// Availability reported by the coordinator API (`count_available_for_run`).
    pub reported: u32,
    /// Ground truth availability from a full shard scan.
    pub ground_truth: u32,
}

/// Report returned by `CoordinationSim::run_overload`.
#[must_use]
#[derive(Debug, Clone)]
pub struct OverloadReport {
    /// Total operations executed across zombie preamble, warmup, overload,
    /// and recovery.
    pub ops_executed: usize,
    /// All invariant violations observed during the run.
    pub violations: Vec<InvariantViolation>,
    /// Histogram of payload-free event kinds.
    pub event_counts: BTreeMap<SimEventKind, usize>,
    /// Seed used by the run (for deterministic replay).
    pub seed: u64,
    /// Logical time at run completion.
    pub end_time: LogicalTime,
    /// Completion ratio during scripted overload rounds.
    pub overload_goodput: f64,
    /// D1 samples comparing reported availability to full-scan truth.
    pub d1_observations: Vec<D1Observation>,
    /// L1 sentinel: at least one shard completed during recovery.
    pub l1_any_completed: bool,
}

/// Scripted overload op burst: every worker issues `ClaimNext`.
pub(super) fn generate_burst_claim(workers: &[WorkerId]) -> Vec<SimOp> {
    workers
        .iter()
        .copied()
        .map(|worker| SimOp::ClaimNext { worker })
        .collect()
}

/// Scripted capacity-drop burst: pause half the workers, then jump time.
pub(super) fn generate_capacity_drop(workers: &[WorkerId]) -> Vec<SimOp> {
    let mut ops = Vec::new();
    // Integer division intentionally rounds down: with odd worker counts we
    // keep one extra worker active, modeling partial (not total) capacity loss.
    for worker in workers.iter().take(workers.len() / 2) {
        ops.push(SimOp::PauseWorker { worker: *worker });
    }
    ops.push(SimOp::AdvanceTime { ticks: 200 });
    ops
}

/// Scripted split burst: issue `SplitReplace` on all currently held shards.
pub(super) fn generate_burst_shards(
    _workers: &[WorkerId],
    held_shards: &[(WorkerId, ShardKey)],
) -> Vec<SimOp> {
    held_shards
        .iter()
        .map(|(worker, key)| SimOp::SplitReplace {
            worker: *worker,
            key: *key,
        })
        .collect()
}

#[cfg(test)]
#[path = "overload_tests.rs"]
mod tests;

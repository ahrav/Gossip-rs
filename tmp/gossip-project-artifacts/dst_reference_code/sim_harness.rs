//! Top-level coordination simulation harness.
//!
//! Orchestrates workers, backend, and fault injection into a single
//! simulation that can be driven step-by-step or run to completion.
//! Follows TigerBeetle's VOPR progressive difficulty pattern.

use std::collections::{BTreeMap, BTreeSet};

use rand::Rng;

use gossip_contracts::coordination::{FenceEpoch, LogicalTime, ShardId, WorkerId};
use gossip_contracts::sim::{FaultConfig, FaultLevel, SimContext};

use super::backend::{OpResult, SimBackend};
use super::invariants::InvariantChecker;
use super::worker::SimWorker;

/// Operations that can be applied in the simulation.
#[derive(Debug, Clone)]
pub enum SimOp {
    /// Worker attempts to acquire a shard.
    Acquire { worker_idx: usize, shard: ShardId },
    /// Worker checkpoints progress on a held shard.
    Checkpoint { worker_idx: usize, shard: ShardId },
    /// Worker completes a shard (terminal).
    Complete { worker_idx: usize, shard: ShardId },
    /// Worker releases a shard back to Open.
    Release { worker_idx: usize, shard: ShardId },
    /// Advance time by N ticks.
    AdvanceTime { ticks: u64 },
    /// Pause a worker (simulate GC pause / network isolation).
    PauseWorker { worker_idx: usize },
    /// Resume a paused worker.
    ResumeWorker { worker_idx: usize },
}

/// Record of an operation and its result for trace logging.
#[derive(Debug, Clone)]
pub struct TraceEntry {
    /// Logical time when the operation was executed.
    pub time: LogicalTime,
    /// The operation that was executed.
    pub op: SimOp,
    /// The result of the operation.
    pub result: OpResult,
}

/// Top-level coordination simulation harness.
///
/// # Example
///
/// ```
/// use gossip_coordination::sim::{CoordinationSim, SimWorker};
/// use gossip_contracts::coordination::{ShardId, WorkerId};
/// use gossip_contracts::sim::FaultLevel;
///
/// let mut sim = CoordinationSim::new(42, FaultLevel::SunnyDay);
/// sim.add_worker(WorkerId(1));
/// sim.add_worker(WorkerId(2));
/// sim.register_shard(ShardId(1));
/// sim.register_shard(ShardId(2));
///
/// // Run random operations and check invariants.
/// let report = sim.run_random(100);
/// assert!(report.violations.is_empty(), "invariant violations: {:?}", report.violations);
/// ```
pub struct CoordinationSim {
    pub ctx: SimContext,
    pub backend: SimBackend,
    pub workers: Vec<SimWorker>,
    pub fault_config: FaultConfig,
    pub trace: Vec<TraceEntry>,
    shards: Vec<ShardId>,
    // Invariant tracking state.
    prev_epochs: BTreeMap<u64, u64>,
    prev_terminal: BTreeSet<u64>,
}

/// Report from a simulation run.
#[derive(Debug)]
pub struct SimReport {
    /// Total number of operations executed.
    pub ops_executed: usize,
    /// Invariant violations found (empty = all invariants passed).
    pub violations: Vec<String>,
    /// Count of each operation result type.
    pub result_counts: BTreeMap<String, usize>,
    /// Seed used (for reproduction).
    pub seed: u64,
    /// Logical time at end of simulation.
    pub end_time: LogicalTime,
}

impl CoordinationSim {
    /// Create a new simulation with the given seed and fault level.
    pub fn new(seed: u64, level: FaultLevel) -> Self {
        Self {
            ctx: SimContext::new(seed),
            backend: SimBackend::new(100), // 100-tick leases
            workers: Vec::new(),
            fault_config: FaultConfig::for_level(level),
            trace: Vec::new(),
            shards: Vec::new(),
            prev_epochs: BTreeMap::new(),
            prev_terminal: BTreeSet::new(),
        }
    }

    /// Add a worker to the simulation.
    pub fn add_worker(&mut self, id: WorkerId) {
        self.workers.push(SimWorker::new(id));
    }

    /// Register a shard in the backend.
    pub fn register_shard(&mut self, id: ShardId) {
        self.backend.register_shard(id);
        self.shards.push(id);
    }

    /// Execute a single operation and check invariants.
    ///
    /// Returns the operation result and any invariant violations.
    pub fn step(&mut self, op: SimOp) -> (OpResult, Vec<String>) {
        let now = self.ctx.now();
        let result = self.execute_op(&op, now);

        self.trace.push(TraceEntry {
            time: now,
            op: op.clone(),
            result: result.clone(),
        });

        let violations = self.check_all_invariants();
        (result, violations)
    }

    /// Run N random operations and return a report.
    pub fn run_random(&mut self, num_ops: usize) -> SimReport {
        let mut result_counts: BTreeMap<String, usize> = BTreeMap::new();
        let mut all_violations = Vec::new();

        for _ in 0..num_ops {
            let op = self.generate_random_op();
            let (result, violations) = self.step(op);

            let result_name = format!("{result:?}")
                .split_whitespace()
                .next()
                .unwrap_or("Unknown")
                .to_string();
            *result_counts.entry(result_name).or_default() += 1;

            all_violations.extend(violations);

            // Advance time slightly between operations.
            let ticks = self.ctx.rng().random_range(1..=10);
            self.ctx.advance(ticks);
        }

        SimReport {
            ops_executed: num_ops,
            violations: all_violations,
            result_counts,
            seed: self.ctx.seed(),
            end_time: self.ctx.now(),
        }
    }

    fn execute_op(&mut self, op: &SimOp, now: LogicalTime) -> OpResult {
        match op {
            SimOp::Acquire { worker_idx, shard } => {
                let worker = &mut self.workers[*worker_idx];
                if worker.paused {
                    return OpResult::StaleEpoch {
                        presented: FenceEpoch(0),
                        current: FenceEpoch(0),
                    };
                }
                let op_id = worker.next_op_id();
                let worker_id = worker.id;
                let result = self.backend.acquire(*shard, worker_id, op_id, now);
                if let OpResult::Acquired { epoch } = &result {
                    // Remove stale claims from any other worker who previously
                    // held this shard (their lease expired, so the backend
                    // allowed re-acquisition).
                    for (i, w) in self.workers.iter_mut().enumerate() {
                        if i != *worker_idx {
                            w.record_release(*shard);
                        }
                    }
                    self.workers[*worker_idx].record_acquire(*shard, *epoch);
                }
                result
            }
            SimOp::Checkpoint { worker_idx, shard } => {
                let worker = &mut self.workers[*worker_idx];
                if worker.paused {
                    return OpResult::LeaseExpired {
                        deadline: LogicalTime::ZERO,
                        now,
                    };
                }
                let epoch = worker.epoch_for(*shard).unwrap_or(FenceEpoch(0));
                let op_id = worker.next_op_id();
                let worker_id = worker.id;
                self.backend
                    .checkpoint(*shard, worker_id, epoch, op_id, now)
            }
            SimOp::Complete { worker_idx, shard } => {
                let worker = &mut self.workers[*worker_idx];
                if worker.paused {
                    return OpResult::LeaseExpired {
                        deadline: LogicalTime::ZERO,
                        now,
                    };
                }
                let epoch = worker.epoch_for(*shard).unwrap_or(FenceEpoch(0));
                let op_id = worker.next_op_id();
                let worker_id = worker.id;
                let result = self.backend.complete(*shard, worker_id, epoch, op_id, now);
                if result == OpResult::Ok {
                    self.workers[*worker_idx].record_release(*shard);
                }
                result
            }
            SimOp::Release { worker_idx, shard } => {
                let worker = &mut self.workers[*worker_idx];
                if worker.paused {
                    return OpResult::LeaseExpired {
                        deadline: LogicalTime::ZERO,
                        now,
                    };
                }
                let epoch = worker.epoch_for(*shard).unwrap_or(FenceEpoch(0));
                let op_id = worker.next_op_id();
                let worker_id = worker.id;
                let result = self.backend.release(*shard, worker_id, epoch, op_id, now);
                if result == OpResult::Ok {
                    self.workers[*worker_idx].record_release(*shard);
                }
                result
            }
            SimOp::AdvanceTime { ticks } => {
                self.ctx.advance(*ticks);
                OpResult::Ok
            }
            SimOp::PauseWorker { worker_idx } => {
                self.workers[*worker_idx].paused = true;
                OpResult::Ok
            }
            SimOp::ResumeWorker { worker_idx } => {
                self.workers[*worker_idx].paused = false;
                OpResult::Ok
            }
        }
    }

    fn generate_random_op(&mut self) -> SimOp {
        if self.workers.is_empty() || self.shards.is_empty() {
            return SimOp::AdvanceTime { ticks: 10 };
        }

        let worker_idx = self.ctx.rng().random_range(0..self.workers.len());
        let shard_idx = self.ctx.rng().random_range(0..self.shards.len());
        let shard = self.shards[shard_idx];

        // Inject faults based on fault config.
        if self.fault_config.inject_pauses && !self.workers[worker_idx].paused {
            let pause_chance: f64 = self.ctx.rng().random();
            if pause_chance < 0.05 {
                return SimOp::PauseWorker { worker_idx };
            }
        }

        // Resume paused workers occasionally.
        if self.workers[worker_idx].paused {
            let resume_chance: f64 = self.ctx.rng().random();
            if resume_chance < 0.3 {
                return SimOp::ResumeWorker { worker_idx };
            }
        }

        // Inject time jumps (lease expiry).
        if self.fault_config.inject_lease_expiry {
            let time_jump_chance: f64 = self.ctx.rng().random();
            if time_jump_chance < 0.1 {
                let ticks = self.ctx.rng().random_range(50..=200);
                return SimOp::AdvanceTime { ticks };
            }
        }

        // Normal operation distribution.
        let op_choice: u32 = self.ctx.rng().random_range(0..100);
        match op_choice {
            0..30 => SimOp::Acquire { worker_idx, shard },
            30..60 => SimOp::Checkpoint { worker_idx, shard },
            60..80 => SimOp::Complete { worker_idx, shard },
            80..90 => SimOp::Release { worker_idx, shard },
            _ => {
                let ticks = self.ctx.rng().random_range(1..=20);
                SimOp::AdvanceTime { ticks }
            }
        }
    }

    fn check_all_invariants(&mut self) -> Vec<String> {
        let mut violations = Vec::new();

        // S1: Mutual exclusion.
        if let Err(v) = InvariantChecker::check_mutual_exclusion(&self.workers) {
            violations.push(v);
        }

        // S2: Fence monotonicity.
        if let Err(v) =
            InvariantChecker::check_fence_monotonicity(&self.backend, &mut self.prev_epochs)
        {
            violations.push(v);
        }

        // S3: Terminal irreversibility.
        if let Err(v) =
            InvariantChecker::check_terminal_irreversibility(&self.backend, &mut self.prev_terminal)
        {
            violations.push(v);
        }

        // Active shards have valid leases.
        if let Err(v) = InvariantChecker::check_active_shards_have_leases(&self.backend) {
            violations.push(v);
        }

        violations
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sunny_day_no_violations() {
        let mut sim = CoordinationSim::new(42, FaultLevel::SunnyDay);
        sim.add_worker(WorkerId(1));
        sim.add_worker(WorkerId(2));
        sim.register_shard(ShardId(1));
        sim.register_shard(ShardId(2));
        sim.register_shard(ShardId(3));

        let report = sim.run_random(200);
        assert!(
            report.violations.is_empty(),
            "Sunny day violations (seed=42): {:?}",
            report.violations,
        );
    }

    #[test]
    fn stormy_no_violations() {
        let mut sim = CoordinationSim::new(42, FaultLevel::Stormy);
        sim.add_worker(WorkerId(1));
        sim.add_worker(WorkerId(2));
        sim.add_worker(WorkerId(3));
        sim.register_shard(ShardId(1));
        sim.register_shard(ShardId(2));

        let report = sim.run_random(500);
        assert!(
            report.violations.is_empty(),
            "Stormy violations (seed=42): {:?}",
            report.violations,
        );
    }

    #[test]
    fn multiple_seeds_sunny_day() {
        for seed in 0..10 {
            let mut sim = CoordinationSim::new(seed, FaultLevel::SunnyDay);
            sim.add_worker(WorkerId(1));
            sim.add_worker(WorkerId(2));
            sim.register_shard(ShardId(1));
            sim.register_shard(ShardId(2));

            let report = sim.run_random(100);
            assert!(
                report.violations.is_empty(),
                "Violations with seed={}: {:?}",
                seed,
                report.violations,
            );
        }
    }

    #[test]
    fn multiple_seeds_stormy() {
        for seed in 0..10 {
            let mut sim = CoordinationSim::new(seed, FaultLevel::Stormy);
            sim.add_worker(WorkerId(1));
            sim.add_worker(WorkerId(2));
            sim.add_worker(WorkerId(3));
            sim.register_shard(ShardId(1));
            sim.register_shard(ShardId(2));
            sim.register_shard(ShardId(3));

            let report = sim.run_random(200);
            assert!(
                report.violations.is_empty(),
                "Violations with seed={}: {:?}",
                seed,
                report.violations,
            );
        }
    }

    #[test]
    fn deterministic_replay() {
        let run = |seed: u64| -> Vec<String> {
            let mut sim = CoordinationSim::new(seed, FaultLevel::Stormy);
            sim.add_worker(WorkerId(1));
            sim.add_worker(WorkerId(2));
            sim.register_shard(ShardId(1));

            let report = sim.run_random(50);
            report
                .result_counts
                .into_iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect()
        };

        let r1 = run(42);
        let r2 = run(42);
        assert_eq!(r1, r2, "Same seed must produce identical results");
    }

    #[test]
    fn report_includes_result_counts() {
        let mut sim = CoordinationSim::new(42, FaultLevel::SunnyDay);
        sim.add_worker(WorkerId(1));
        sim.register_shard(ShardId(1));

        let report = sim.run_random(50);
        assert!(report.ops_executed == 50);
        assert!(!report.result_counts.is_empty());
    }
}

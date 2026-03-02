//! Deterministic Simulator for Scheduler Invariant Verification
//!
//! # Purpose
//!
//! This module provides a deterministic simulation harness that explores
//! out-of-order I/O completions and task scheduling to verify scheduler
//! invariants hold under randomly sampled interleavings.
//!
//! # Why Simulation Over Multi-Threading?
//!
//! True multi-threaded tests are non-deterministic:
//! - Race conditions manifest only under specific timings
//! - Failures are hard to reproduce
//! - Can't systematically explore edge cases
//!
//! The simulator provides:
//! - Deterministic execution from seed
//! - Replayable action traces
//! - Systematic exploration of completion orders
//!
//! # Modeled Components
//!
//! - Object discovery with `max_in_flight_objects` cap
//! - Buffer pool with bounded capacity
//! - Per-object I/O depth (prefetch limit)
//! - Out-of-order I/O completions
//! - Out-of-order scan task execution
//!
//! # Budget Enforcement Modes
//!
//! - `None`: Bug mode - proves sharp edge exists without enforcement
//! - `AtScan`: Clamp scanned bytes (allows wasteful I/O past budget)
//! - `AtFetch`: Never submit I/O past budget (most efficient)
//!
//! # Architecture: Unified State Machine
//!
//! Both `run_sim` and `replay_sim` use the same `SimState::apply()` method
//! to ensure behavior is identical. This eliminates drift between random
//! exploration and deterministic replay.

use super::rng::XorShift64;

// ============================================================================
// Configuration
// ============================================================================

/// Specification for a single object to scan.
#[derive(Clone, Copy, Debug)]
pub struct ObjectSpec {
    /// Total size in bytes.
    pub size: u64,
    /// Maximum bytes to scan (budget limit).
    pub budget_limit: u64,
}

/// How budget limits are enforced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BudgetEnforcement {
    /// No enforcement - for testing that violations occur without it.
    None,
    /// Enforce at scan time - I/O may fetch past budget, but scan clamps.
    /// Wasteful but correct.
    AtScan,
    /// Enforce at fetch time - never submit I/O past budget.
    /// Most efficient, no wasted I/O.
    AtFetch,
}

/// Configuration for a simulation run.
#[derive(Clone, Debug)]
pub struct SimConfig {
    /// Random seed for deterministic execution.
    pub seed: u64,
    /// Objects to scan.
    pub objects: Vec<ObjectSpec>,
    /// Maximum objects in flight concurrently.
    pub max_in_flight_objects: u32,
    /// Total buffers in pool.
    pub pool_buffers: u32,
    /// Maximum concurrent I/O operations per object.
    pub per_object_io_depth: u32,
    /// Chunk size for scanning.
    pub chunk_size: u32,
    /// Overlap between chunks.
    pub overlap: u32,
    /// Budget enforcement mode.
    pub enforcement: BudgetEnforcement,
}

impl SimConfig {
    /// Create a simple config for testing.
    pub fn simple(objects: Vec<ObjectSpec>) -> Self {
        Self {
            seed: 12345,
            objects,
            max_in_flight_objects: 4,
            pool_buffers: 8,
            per_object_io_depth: 2,
            chunk_size: 256,
            overlap: 16,
            enforcement: BudgetEnforcement::AtFetch,
        }
    }

    /// Validate configuration invariants.
    ///
    /// # Panics
    ///
    /// Panics if configuration is invalid.
    pub fn validate(&self) {
        assert!(!self.objects.is_empty(), "must have at least one object");
        assert!(
            self.max_in_flight_objects > 0,
            "max_in_flight_objects must be > 0"
        );
        assert!(self.pool_buffers > 0, "pool_buffers must be > 0");
        assert!(
            self.per_object_io_depth > 0,
            "per_object_io_depth must be > 0"
        );
        assert!(self.chunk_size > 0, "chunk_size must be > 0");

        // Overlap must be less than chunk size
        assert!(
            (self.overlap as u64) < (self.chunk_size as u64),
            "overlap ({}) must be less than chunk_size ({})",
            self.overlap,
            self.chunk_size
        );

        // Need at least one buffer per in-flight object to avoid trivial deadlock
        assert!(
            self.pool_buffers >= self.max_in_flight_objects,
            "pool_buffers ({}) must be >= max_in_flight_objects ({}) to avoid deadlock",
            self.pool_buffers,
            self.max_in_flight_objects
        );

        for (i, o) in self.objects.iter().enumerate() {
            assert!(o.size > 0, "object {} size must be > 0", i);
            assert!(
                o.budget_limit > 0,
                "object {} budget_limit must be > 0 (use size if no limit)",
                i
            );
        }
    }
}

// ============================================================================
// Actions (for tracing)
// ============================================================================

/// Actions that can be taken in the simulation.
///
/// Uses stable IDs (not indices) so traces remain valid across runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// Start processing a new object.
    StartObject { obj: u32 },
    /// Submit an I/O operation for an object.
    SubmitIo { obj: u32 },
    /// Complete a pending I/O operation.
    CompleteIo { op: u32 },
    /// Run a scan task.
    RunScan { task: u32 },
}

// ============================================================================
// Simulation State
// ============================================================================

/// Per-object state during simulation.
///
/// # State Machine
///
/// ```text
/// [pending] --StartObject--> [started] --scanned>=want--> [done]
///                               |
///                               v
///                          io_in_flight tracks concurrent I/O
///                          scanned_payload accumulates coverage
/// ```
#[derive(Clone, Debug)]
struct ObjState {
    /// Total object size in bytes.
    size: u64,
    /// Maximum bytes to scan (may be less than size).
    budget_limit: u64,
    /// True once StartObject action has been applied.
    started: bool,
    /// True once scanned_payload >= min(size, budget_limit).
    done: bool,
    /// File offset for next I/O submission (advances with each SubmitIo).
    next_payload_off: u64,
    /// Count of I/O operations currently in flight for this object.
    io_in_flight: u32,
    /// Cumulative bytes scanned (may exceed budget under BudgetEnforcement::None).
    scanned_payload: u64,
}

impl ObjState {
    fn new(spec: &ObjectSpec) -> Self {
        Self {
            size: spec.size,
            budget_limit: spec.budget_limit,
            started: false,
            done: false,
            next_payload_off: 0,
            io_in_flight: 0,
            scanned_payload: 0,
        }
    }

    /// Bytes we want to scan for this object.
    fn want(&self) -> u64 {
        self.size.min(self.budget_limit)
    }

    /// Check if more I/O can be submitted for this object.
    fn can_submit_io(&self, cfg: &SimConfig) -> bool {
        if !self.started || self.done {
            return false;
        }
        if self.io_in_flight >= cfg.per_object_io_depth {
            return false;
        }

        // Check if there's more data to fetch
        let _chunk = cfg.chunk_size as u64;
        let payload_off = self.next_payload_off;

        // Under AtFetch, don't submit if we've reached budget
        if cfg.enforcement == BudgetEnforcement::AtFetch && payload_off >= self.budget_limit {
            return false;
        }

        // Check if there's more size to read
        payload_off < self.size
    }
}

/// Pending I/O operation.
///
/// Represents an in-flight read that consumes one buffer slot.
/// Transitions to `ScanTask` upon `CompleteIo`.
#[derive(Clone, Debug)]
struct IoOp {
    /// Unique operation ID (monotonically increasing, for trace stability).
    id: u32,
    /// Index into `SimState::objs` for the owning object.
    obj: u32,
    /// File offset where this read starts.
    payload_off: u64,
    /// Bytes to read (clamped by budget under AtFetch enforcement).
    payload_len: u32,
}

/// Pending scan task.
///
/// Created when an I/O operation completes. Holds the buffer until
/// `RunScan` releases it back to the pool.
#[derive(Clone, Debug)]
struct ScanTask {
    /// Unique task ID (monotonically increasing, for trace stability).
    id: u32,
    /// Index into `SimState::objs` for the owning object.
    obj: u32,
    /// File offset of the data in this task.
    payload_off: u64,
    /// Bytes available for scanning (may be clamped at scan time under AtScan).
    payload_len: u32,
}

/// Unified simulation state.
///
/// Both `run_sim` and `replay_sim` use this struct and its `apply()` method
/// to ensure identical behavior.
///
/// # Resource Accounting
///
/// ```text
/// Buffers:     buffers_available + |active_ops| + |active_tasks| == total_buffers
/// Permits:     in_flight_objects == count of started && !done objects
/// Coverage:    sum(obj.scanned_payload) tracks total bytes processed
/// ```
///
/// # Key Invariants (verified at end)
///
/// 1. No buffer leaks: `buffers_available == total_buffers`
/// 2. No permit leaks: `in_flight_objects == 0`
/// 3. All complete: `completed_objects == objs.len()`
/// 4. Exact coverage (with enforcement): `scanned == min(size, budget)`
struct SimState {
    /// Per-object tracking (indexed by object ID).
    objs: Vec<ObjState>,

    /// Object IDs not yet started (drain as StartObject actions fire).
    pending: Vec<u32>,

    /// I/O operations awaiting completion (each holds one buffer).
    active_ops: Vec<IoOp>,
    /// Next I/O operation ID to assign.
    next_op_id: u32,

    /// Scan tasks awaiting execution (each holds one buffer).
    active_tasks: Vec<ScanTask>,
    /// Next scan task ID to assign.
    next_task_id: u32,

    /// Objects currently being processed (started but not done).
    in_flight_objects: u32,
    /// Free buffer slots (decremented on SubmitIo, incremented on RunScan).
    buffers_available: u32,
    /// Total buffer capacity (constant after init).
    total_buffers: u32,

    /// Count of objects that have been started.
    started_objects: u32,
    /// Count of objects that have completed scanning.
    completed_objects: u32,

    /// Monotonic step counter (one increment per apply()).
    step: u64,
}

impl SimState {
    fn new(cfg: &SimConfig) -> Self {
        let objs: Vec<ObjState> = cfg.objects.iter().map(ObjState::new).collect();
        let pending: Vec<u32> = (0..objs.len() as u32).collect();

        Self {
            objs,
            pending,
            active_ops: Vec::with_capacity(cfg.pool_buffers as usize),
            next_op_id: 0,
            active_tasks: Vec::with_capacity(cfg.pool_buffers as usize),
            next_task_id: 0,
            in_flight_objects: 0,
            buffers_available: cfg.pool_buffers,
            total_buffers: cfg.pool_buffers,
            started_objects: 0,
            completed_objects: 0,
            step: 0,
        }
    }

    /// Collect all valid actions for current state.
    fn available_actions(&self, cfg: &SimConfig, out: &mut Vec<Action>) {
        out.clear();

        // StartObject: if pending objects and under in-flight limit
        if !self.pending.is_empty() && self.in_flight_objects < cfg.max_in_flight_objects {
            for &obj in &self.pending {
                out.push(Action::StartObject { obj });
            }
        }

        // SubmitIo: for each started object that can accept more I/O
        if self.buffers_available > 0 {
            for (i, o) in self.objs.iter().enumerate() {
                if o.can_submit_io(cfg) {
                    out.push(Action::SubmitIo { obj: i as u32 });
                }
            }
        }

        // CompleteIo: any active operation
        for op in &self.active_ops {
            out.push(Action::CompleteIo { op: op.id });
        }

        // RunScan: any active task
        for task in &self.active_tasks {
            out.push(Action::RunScan { task: task.id });
        }
    }

    /// Apply an action to the state.
    ///
    /// This is the SINGLE implementation of state transitions, used by both
    /// `run_sim` and `replay_sim` to ensure identical behavior.
    fn apply(&mut self, cfg: &SimConfig, action: Action) -> Result<(), SimError> {
        self.step += 1;

        match action {
            Action::StartObject { obj } => self.apply_start_object(obj, action),
            Action::SubmitIo { obj } => self.apply_submit_io(cfg, obj, action),
            Action::CompleteIo { op } => self.apply_complete_io(op, action),
            Action::RunScan { task } => self.apply_run_scan(cfg, task, action),
        }
    }

    fn apply_start_object(&mut self, obj: u32, action: Action) -> Result<(), SimError> {
        let pos = self.pending.iter().position(|&x| x == obj).ok_or_else(|| {
            SimError::with_context("StartObject: object not in pending list", action, self.step)
        })?;

        self.pending.swap_remove(pos);

        let o = &mut self.objs[obj as usize];

        debug_assert!(!o.started, "object already started");
        o.started = true;
        self.started_objects += 1;
        self.in_flight_objects += 1;

        Ok(())
    }

    fn apply_submit_io(
        &mut self,
        cfg: &SimConfig,
        obj: u32,
        action: Action,
    ) -> Result<(), SimError> {
        if self.buffers_available == 0 {
            return Err(SimError::with_context(
                "SubmitIo: no buffers available",
                action,
                self.step,
            ));
        }

        let o = &mut self.objs[obj as usize];

        if !o.started || o.done {
            return Err(SimError::with_context(
                "SubmitIo: object not active",
                action,
                self.step,
            ));
        }
        if o.io_in_flight >= cfg.per_object_io_depth {
            return Err(SimError::with_context(
                "SubmitIo: io_depth limit reached",
                action,
                self.step,
            ));
        }

        let chunk = cfg.chunk_size as u64;
        let payload_off = o.next_payload_off;

        // Under AtFetch, reject if past budget
        if cfg.enforcement == BudgetEnforcement::AtFetch && payload_off >= o.budget_limit {
            return Err(SimError::with_context(
                "SubmitIo: AtFetch enforcement - past budget",
                action,
                self.step,
            ));
        }

        // Calculate payload length
        let max_payload = (o.size.saturating_sub(payload_off)).min(chunk);

        let payload_len = if cfg.enforcement == BudgetEnforcement::AtFetch {
            // Clamp to budget
            let remaining_budget = o.budget_limit.saturating_sub(payload_off);
            max_payload.min(remaining_budget)
        } else {
            max_payload
        };

        if payload_len == 0 {
            return Err(SimError::with_context(
                "SubmitIo: zero-length payload",
                action,
                self.step,
            ));
        }

        // Consume buffer
        self.buffers_available -= 1;
        o.io_in_flight += 1;

        // Advance offset for next submission
        let advance = if cfg.enforcement == BudgetEnforcement::AtFetch {
            payload_len
        } else {
            max_payload // May advance past budget under None/AtScan
        };
        o.next_payload_off = payload_off.saturating_add(advance);

        // Create I/O operation
        let op = IoOp {
            id: self.next_op_id,
            obj,
            payload_off,
            payload_len: payload_len as u32,
        };
        self.next_op_id += 1;
        self.active_ops.push(op);

        // Assertions
        debug_assert!(o.io_in_flight <= cfg.per_object_io_depth);
        debug_assert!(self.buffers_available < self.total_buffers);

        Ok(())
    }

    fn apply_complete_io(&mut self, op_id: u32, action: Action) -> Result<(), SimError> {
        let pos = self
            .active_ops
            .iter()
            .position(|o| o.id == op_id)
            .ok_or_else(|| {
                SimError::with_context("CompleteIo: operation not found", action, self.step)
            })?;

        let op = self.active_ops.swap_remove(pos);
        let o = &mut self.objs[op.obj as usize];

        // Decrement in-flight counter (with underflow check)
        if o.io_in_flight == 0 {
            return Err(SimError::with_context(
                "CompleteIo: io_in_flight underflow",
                action,
                self.step,
            ));
        }
        o.io_in_flight -= 1;

        // Create scan task (buffer transfers from I/O to scan)
        let task = ScanTask {
            id: self.next_task_id,
            obj: op.obj,
            payload_off: op.payload_off,
            payload_len: op.payload_len,
        };
        self.next_task_id += 1;
        self.active_tasks.push(task);

        Ok(())
    }

    fn apply_run_scan(
        &mut self,
        cfg: &SimConfig,
        task_id: u32,
        action: Action,
    ) -> Result<(), SimError> {
        let pos = self
            .active_tasks
            .iter()
            .position(|t| t.id == task_id)
            .ok_or_else(|| SimError::with_context("RunScan: task not found", action, self.step))?;

        let task = self.active_tasks.swap_remove(pos);
        let o = &mut self.objs[task.obj as usize];

        // Calculate how much we actually scan (budget enforcement at scan time)
        let allowed_payload = if cfg.enforcement == BudgetEnforcement::None {
            // No enforcement - scan everything (may violate budget)
            task.payload_len as u64
        } else {
            // AtScan or AtFetch - clamp to budget
            let remaining = o.budget_limit.saturating_sub(task.payload_off);
            (task.payload_len as u64).min(remaining)
        };

        o.scanned_payload += allowed_payload;

        // Release buffer
        self.buffers_available += 1;

        // Check if object is complete
        let want = o.want();
        if !o.done && o.scanned_payload >= want {
            // Assert exact coverage (not just >=)
            if o.scanned_payload != want && cfg.enforcement != BudgetEnforcement::None {
                return Err(SimError::with_context(
                    format!(
                        "RunScan: coverage mismatch - scanned {} but expected exactly {}",
                        o.scanned_payload, want
                    ),
                    action,
                    self.step,
                ));
            }

            o.done = true;
            self.completed_objects += 1;

            // Release in-flight permit (with underflow check)
            if self.in_flight_objects == 0 {
                return Err(SimError::with_context(
                    "RunScan: in_flight_objects underflow",
                    action,
                    self.step,
                ));
            }
            self.in_flight_objects -= 1;
        }

        // Assertions
        debug_assert!(self.buffers_available <= self.total_buffers);

        Ok(())
    }

    /// Check if simulation is complete.
    ///
    /// Complete when:
    /// 1. All objects have been fully scanned
    /// 2. All in-flight I/O operations have completed
    /// 3. All scan tasks have run (buffers returned)
    fn is_complete(&self) -> bool {
        self.completed_objects == self.objs.len() as u32
            && self.active_ops.is_empty()
            && self.active_tasks.is_empty()
    }

    /// Verify final invariants.
    fn verify_final_invariants(&self, cfg: &SimConfig) -> Result<(), SimError> {
        // Invariant 1: No buffer leaks
        if self.buffers_available != self.total_buffers {
            return Err(SimError::new(format!(
                "Buffer leak: {} available but {} total",
                self.buffers_available, self.total_buffers
            )));
        }

        // Invariant 2: No permit leaks
        if self.in_flight_objects != 0 {
            return Err(SimError::new(format!(
                "Permit leak: {} objects still in flight",
                self.in_flight_objects
            )));
        }

        // Invariant 3: All objects complete
        if self.completed_objects != self.objs.len() as u32 {
            return Err(SimError::new(format!(
                "Incomplete: {} of {} objects done",
                self.completed_objects,
                self.objs.len()
            )));
        }

        // Invariant 4: Coverage correctness per object
        for (i, o) in self.objs.iter().enumerate() {
            let want = o.want();

            if cfg.enforcement == BudgetEnforcement::None {
                // No enforcement - may have scanned past budget (this is the bug we're testing)
                // Just check we scanned at least want
                if o.scanned_payload < want {
                    return Err(SimError::new(format!(
                        "Object {} undercoverage: scanned {} but want {}",
                        i, o.scanned_payload, want
                    )));
                }
            } else {
                // With enforcement - must be exact
                if o.scanned_payload != want {
                    return Err(SimError::new(format!(
                        "Object {} coverage mismatch: scanned {} but want {}",
                        i, o.scanned_payload, want
                    )));
                }
            }
        }

        // Invariant 5: No active operations/tasks
        if !self.active_ops.is_empty() {
            return Err(SimError::new(format!(
                "{} I/O operations still active",
                self.active_ops.len()
            )));
        }
        if !self.active_tasks.is_empty() {
            return Err(SimError::new(format!(
                "{} scan tasks still active",
                self.active_tasks.len()
            )));
        }

        Ok(())
    }

    /// Generate report from final state.
    fn into_report(self, trace: SimTrace) -> SimReport {
        SimReport {
            steps: self.step,
            scanned_per_object: self.objs.iter().map(|o| o.scanned_payload).collect(),
            trace,
        }
    }
}

// ============================================================================
// Errors
// ============================================================================

/// Simulation error with context.
#[derive(Clone, Debug)]
pub struct SimError {
    pub message: String,
    pub action: Option<Action>,
    pub step: Option<u64>,
}

impl SimError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            action: None,
            step: None,
        }
    }

    pub fn with_context(message: impl Into<String>, action: Action, step: u64) -> Self {
        Self {
            message: message.into(),
            action: Some(action),
            step: Some(step),
        }
    }
}

impl std::fmt::Display for SimError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)?;
        if let Some(action) = &self.action {
            write!(f, " (action: {:?})", action)?;
        }
        if let Some(step) = self.step {
            write!(f, " (step: {})", step)?;
        }
        Ok(())
    }
}

impl std::error::Error for SimError {}

// ============================================================================
// Trace
// ============================================================================

/// Replayable trace of simulation actions.
#[derive(Clone, Debug, Default)]
pub struct SimTrace {
    pub seed: u64,
    pub actions: Vec<Action>,
}

impl SimTrace {
    fn new(seed: u64) -> Self {
        Self {
            seed,
            actions: Vec::with_capacity(1024),
        }
    }

    fn push(&mut self, action: Action) {
        self.actions.push(action);
    }
}

// ============================================================================
// Report
// ============================================================================

/// Results from a simulation run.
#[derive(Clone, Debug)]
pub struct SimReport {
    /// Total steps executed.
    pub steps: u64,
    /// Bytes scanned per object.
    pub scanned_per_object: Vec<u64>,
    /// Action trace for replay.
    pub trace: SimTrace,
}

// ============================================================================
// Main Entry Points
// ============================================================================

/// Run a simulation with random action selection.
///
/// Explores the state space by randomly choosing among valid actions
/// at each step. Uses the seed from config for deterministic execution.
pub fn run_sim(cfg: SimConfig) -> Result<SimReport, SimError> {
    cfg.validate();

    let mut state = SimState::new(&cfg);
    let mut trace = SimTrace::new(cfg.seed);
    let mut rng = XorShift64::new(cfg.seed);

    // Reusable buffer for available actions (hoisted outside loop)
    let mut possible: Vec<Action> =
        Vec::with_capacity((cfg.max_in_flight_objects + cfg.pool_buffers + 2) as usize);

    let max_steps = 10_000_000u64;

    while !state.is_complete() {
        if state.step >= max_steps {
            return Err(SimError::new(format!(
                "exceeded {} steps without completion",
                max_steps
            )));
        }

        state.available_actions(&cfg, &mut possible);

        if possible.is_empty() {
            return Err(SimError::new("deadlock: no actions possible"));
        }

        // Random selection
        let idx = rng.next_usize(possible.len());
        let action = possible[idx];
        trace.push(action);

        state.apply(&cfg, action)?;
    }

    state.verify_final_invariants(&cfg)?;
    Ok(state.into_report(trace))
}

/// Replay a simulation from a recorded trace.
///
/// Executes the exact sequence of actions from the trace, verifying
/// that the same invariants hold. Used for debugging failures.
pub fn replay_sim(cfg: SimConfig, trace: &SimTrace) -> Result<SimReport, SimError> {
    cfg.validate();

    let mut state = SimState::new(&cfg);
    let mut new_trace = SimTrace::new(trace.seed);

    for (i, &action) in trace.actions.iter().enumerate() {
        state.apply(&cfg, action).map_err(|mut e| {
            e.message = format!("replay step {}: {}", i, e.message);
            e
        })?;
        new_trace.push(action);
    }

    state.verify_final_invariants(&cfg)?;
    Ok(state.into_report(new_trace))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(all(test, feature = "scheduler-sim"))]
mod tests {
    use super::*;

    #[test]
    fn simple_single_object() {
        let cfg = SimConfig::simple(vec![ObjectSpec {
            size: 100,
            budget_limit: 100,
        }]);

        let report = run_sim(cfg).expect("should complete");
        assert_eq!(report.scanned_per_object.len(), 1);
        assert_eq!(report.scanned_per_object[0], 100);
    }

    #[test]
    fn budget_limits_scanning() {
        let cfg = SimConfig {
            enforcement: BudgetEnforcement::AtFetch,
            ..SimConfig::simple(vec![ObjectSpec {
                size: 1000,
                budget_limit: 256, // Less than size
            }])
        };

        let report = run_sim(cfg).expect("should complete");
        assert_eq!(report.scanned_per_object[0], 256); // Capped at budget
    }

    #[test]
    fn size_limits_scanning() {
        let cfg = SimConfig::simple(vec![ObjectSpec {
            size: 100,
            budget_limit: 1000, // More than size
        }]);

        let report = run_sim(cfg).expect("should complete");
        assert_eq!(report.scanned_per_object[0], 100); // Capped at size
    }

    #[test]
    fn at_fetch_enforcement_holds() {
        // Multiple objects with various budget limits
        let cfg = SimConfig {
            enforcement: BudgetEnforcement::AtFetch,
            seed: 99999,
            ..SimConfig::simple(vec![
                ObjectSpec {
                    size: 500,
                    budget_limit: 200,
                },
                ObjectSpec {
                    size: 300,
                    budget_limit: 300,
                },
                ObjectSpec {
                    size: 1000,
                    budget_limit: 512,
                },
            ])
        };

        let report = run_sim(cfg).expect("should complete");
        assert_eq!(report.scanned_per_object[0], 200);
        assert_eq!(report.scanned_per_object[1], 300);
        assert_eq!(report.scanned_per_object[2], 512);
    }

    #[test]
    fn at_scan_enforcement_holds() {
        // Stress test with many objects
        let objects: Vec<ObjectSpec> = (0..32)
            .map(|i| ObjectSpec {
                size: 1000 + i * 100,
                budget_limit: 500 + i * 50,
            })
            .collect();

        let cfg = SimConfig {
            enforcement: BudgetEnforcement::AtScan,
            seed: 77777,
            max_in_flight_objects: 8,
            pool_buffers: 16,
            ..SimConfig::simple(objects.clone())
        };

        let report = run_sim(cfg).expect("should complete");

        for (i, spec) in objects.iter().enumerate() {
            let want = spec.size.min(spec.budget_limit);
            assert_eq!(report.scanned_per_object[i], want, "object {} mismatch", i);
        }
    }

    #[test]
    fn no_enforcement_detects_budget_violation() {
        // This test proves the sharp edge exists:
        // With high prefetch and no enforcement, we can scan past budget
        let cfg = SimConfig {
            enforcement: BudgetEnforcement::None,
            per_object_io_depth: 16, // High prefetch
            pool_buffers: 32,
            seed: 42,
            ..SimConfig::simple(vec![ObjectSpec {
                size: 10_000,
                budget_limit: 512, // Much smaller than size
            }])
        };

        let result = run_sim(cfg);

        // Should either:
        // 1. Error during invariant check (scanned != want)
        // 2. Succeed but with over-scanning (scanned > budget)
        match result {
            Ok(report) => {
                // If it succeeded, we must have over-scanned
                assert!(
                    report.scanned_per_object[0] > 512,
                    "no enforcement should allow over-scanning, got {}",
                    report.scanned_per_object[0]
                );
            }
            Err(_) => {
                // Error is also valid - proves the bug exists
            }
        }
    }

    #[test]
    fn replay_reproduces_results() {
        let cfg = SimConfig {
            seed: 12345,
            ..SimConfig::simple(vec![
                ObjectSpec {
                    size: 500,
                    budget_limit: 500,
                },
                ObjectSpec {
                    size: 300,
                    budget_limit: 200,
                },
            ])
        };

        let report1 = run_sim(cfg.clone()).expect("first run");
        let report2 = replay_sim(cfg, &report1.trace).expect("replay");

        assert_eq!(report1.scanned_per_object, report2.scanned_per_object);
        assert_eq!(report1.steps, report2.steps);
    }

    #[test]
    fn many_small_objects() {
        let objects: Vec<ObjectSpec> = (0..100)
            .map(|_| ObjectSpec {
                size: 64,
                budget_limit: 64,
            })
            .collect();

        let cfg = SimConfig {
            max_in_flight_objects: 16,
            pool_buffers: 32,
            ..SimConfig::simple(objects)
        };

        let report = run_sim(cfg).expect("should complete");
        assert_eq!(report.scanned_per_object.len(), 100);
        assert!(report.scanned_per_object.iter().all(|&s| s == 64));
    }

    #[test]
    fn one_huge_object() {
        let cfg = SimConfig::simple(vec![ObjectSpec {
            size: 1_000_000,
            budget_limit: 1_000_000,
        }]);

        let report = run_sim(cfg).expect("should complete");
        assert_eq!(report.scanned_per_object[0], 1_000_000);
    }

    #[test]
    fn buffer_pool_constraint() {
        // Few buffers, many objects - tests backpressure
        let cfg = SimConfig {
            max_in_flight_objects: 4,
            pool_buffers: 4, // Minimum allowed
            per_object_io_depth: 1,
            ..SimConfig::simple(vec![
                ObjectSpec {
                    size: 1000,
                    budget_limit: 1000,
                },
                ObjectSpec {
                    size: 1000,
                    budget_limit: 1000,
                },
                ObjectSpec {
                    size: 1000,
                    budget_limit: 1000,
                },
                ObjectSpec {
                    size: 1000,
                    budget_limit: 1000,
                },
            ])
        };

        let report = run_sim(cfg).expect("should complete despite constrained buffers");
        assert!(report.scanned_per_object.iter().all(|&s| s == 1000));
    }

    #[test]
    fn trace_action_count() {
        let cfg = SimConfig::simple(vec![ObjectSpec {
            size: 256,
            budget_limit: 256,
        }]);

        let report = run_sim(cfg).expect("should complete");

        // Should have at least: StartObject + SubmitIo + CompleteIo + RunScan
        assert!(report.trace.actions.len() >= 4);
    }

    #[test]
    #[should_panic(expected = "overlap")]
    fn validate_rejects_overlap_ge_chunk() {
        let cfg = SimConfig {
            overlap: 256,
            chunk_size: 256,
            ..SimConfig::simple(vec![ObjectSpec {
                size: 100,
                budget_limit: 100,
            }])
        };
        cfg.validate();
    }

    #[test]
    #[should_panic(expected = "pool_buffers")]
    fn validate_rejects_insufficient_buffers() {
        let cfg = SimConfig {
            max_in_flight_objects: 8,
            pool_buffers: 4, // Less than max_in_flight
            ..SimConfig::simple(vec![ObjectSpec {
                size: 100,
                budget_limit: 100,
            }])
        };
        cfg.validate();
    }

    #[test]
    #[should_panic(expected = "budget_limit must be > 0")]
    fn validate_rejects_zero_budget() {
        let cfg = SimConfig::simple(vec![ObjectSpec {
            size: 100,
            budget_limit: 0,
        }]);
        cfg.validate();
    }

    #[test]
    fn budget_exactly_on_chunk_boundary() {
        let cfg = SimConfig {
            chunk_size: 256,
            enforcement: BudgetEnforcement::AtFetch,
            ..SimConfig::simple(vec![ObjectSpec {
                size: 1000,
                budget_limit: 256, // Exactly one chunk
            }])
        };

        let report = run_sim(cfg).expect("boundary case should work");
        assert_eq!(report.scanned_per_object[0], 256);
    }

    #[test]
    fn determinism_across_runs() {
        let cfg = SimConfig {
            seed: 55555,
            ..SimConfig::simple(vec![
                ObjectSpec {
                    size: 500,
                    budget_limit: 300,
                },
                ObjectSpec {
                    size: 400,
                    budget_limit: 400,
                },
            ])
        };

        let report1 = run_sim(cfg.clone()).expect("run 1");
        let report2 = run_sim(cfg).expect("run 2");

        // Same seed = same results
        assert_eq!(report1.scanned_per_object, report2.scanned_per_object);
        assert_eq!(report1.trace.actions, report2.trace.actions);
    }
}

//! Deterministic, step-driven executor model for the scheduler harness.
//!
//! This module mirrors the production scheduling policy (LIFO locals, FIFO
//! injector, FIFO steals, wake-on-hoard, round-robin unpark) without using
//! OS threads. It is intended for exhaustive and seeded simulation runs.
//!
//! # Invariants
//!
//! - `state` stores the combined `(in_flight << 1) | accepting` word.
//! - Local queues are LIFO for the owning worker; steals are FIFO.
//! - `unpark_one` uses round-robin selection to match production fairness.
//! - `done` is monotonic: once set, it remains true for the run.
//!
//! # Design Notes
//!
//! - `SimExecutor` implements [`WorkerCtxLike`] directly so the core
//!   [`worker_step`] logic runs unchanged.
//! - Park/unpark is modeled with a single boolean token per worker, mirroring
//!   the production parker semantics closely enough for scheduling validation.
//! - The harness intentionally avoids OS sleep; the driver chooses the next
//!   enabled action when a worker reports `ShouldPark`.

#![cfg(any(test, feature = "scheduler-sim"))]
#![allow(dead_code)]

use std::any::Any;
use std::collections::VecDeque;
use std::time::Duration;

use super::executor::ExecutorConfig;
use super::executor_core::{
    in_flight, is_accepting, worker_step, ExecTraceEvent, IdleAction, IdleHooks, NoopTrace,
    PopSource, TraceHooks, WorkerCtxLike, WorkerStepResult, ACCEPTING_BIT, COUNT_UNIT,
    WAKE_ON_HOARD_THRESHOLD,
};
use super::rng::XorShift64;

/// Simulation configuration for the executor policy.
#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize)]
pub struct SimExecCfg {
    /// Number of simulated workers.
    pub workers: usize,
    /// Steal attempts per idle cycle.
    pub steal_tries: u32,
    /// Seed for deterministic victim selection.
    pub seed: u64,
    /// Wake-on-hoard threshold (defaults to the production constant).
    pub wake_on_hoard_threshold: u32,
}

impl SimExecCfg {
    pub(crate) fn new(workers: usize, seed: u64) -> Self {
        Self {
            workers,
            steal_tries: 4,
            seed,
            wake_on_hoard_threshold: WAKE_ON_HOARD_THRESHOLD,
        }
    }

    pub(crate) fn to_executor_config(self) -> ExecutorConfig {
        // Spin/park values are placeholders: simulation does not sleep,
        // but the shared `worker_step` requires a config.
        ExecutorConfig {
            workers: self.workers,
            seed: self.seed,
            steal_tries: self.steal_tries,
            spin_iters: 1,
            park_timeout: Duration::from_micros(1),
            pin_threads: false,
        }
    }

    pub(crate) fn validate(self) {
        assert!(self.workers > 0, "workers must be > 0");
        assert!(self.steal_tries > 0, "steal_tries must be > 0");
    }
}

/// Per-worker simulation state.
#[derive(Debug)]
pub(crate) struct SimWorker<T, S> {
    /// Local deque: LIFO pop for owner, FIFO steal for victims.
    pub(crate) local: VecDeque<T>,
    /// True once the worker has parked (until unpark token is consumed).
    pub(crate) parked: bool,
    /// Park token that allows one wake-up to proceed.
    pub(crate) unpark_token: bool,
    /// Wake-on-hoard counter for local spawns.
    pub(crate) local_spawns_since_wake: u32,
    /// Per-worker RNG for victim selection.
    pub(crate) rng: XorShift64,
    /// Per-worker scratch used by the task runner.
    pub(crate) scratch: S,
}

impl<T, S> SimWorker<T, S> {
    fn new(worker_id: usize, seed: u64, scratch: S) -> Self {
        let rng_seed = seed ^ (worker_id as u64).wrapping_mul(0x9E3779B97F4A7C15);
        Self {
            local: VecDeque::new(),
            parked: false,
            unpark_token: false,
            local_spawns_since_wake: 0,
            rng: XorShift64::new(rng_seed),
            scratch,
        }
    }
}

/// Deterministic executor model used by the scheduler harness.
#[derive(Debug)]
pub(crate) struct SimExecutor<T, S> {
    /// Global injector queue (FIFO).
    pub(crate) injector: VecDeque<T>,
    /// Per-worker state (locals, RNG, park tokens).
    pub(crate) workers: Vec<SimWorker<T, S>>,
    /// Combined `(in_flight << 1) | accepting` state word.
    pub(crate) state: usize,
    /// Shutdown flag mirroring the production executor.
    pub(crate) done: bool,
    /// Round-robin counter for unpark selection.
    pub(crate) next_unpark: usize,
    /// First panic captured by the harness.
    pub(crate) panic: Option<Box<dyn Any + Send + 'static>>,

    exec_cfg: ExecutorConfig,
    wake_on_hoard_threshold: u32,
    /// Active worker index for context-sensitive operations (spawn_local, RNG).
    current_worker: usize,
}

impl<T: Send + 'static, S> SimExecutor<T, S> {
    /// Construct a new simulator from config and per-worker scratch factory.
    ///
    /// # Panics
    ///
    /// Panics if the config is invalid.
    pub(crate) fn new(cfg: SimExecCfg, scratch_init: impl Fn(usize) -> S) -> Self {
        cfg.validate();
        let exec_cfg = cfg.to_executor_config();

        let mut workers = Vec::with_capacity(cfg.workers);
        for worker_id in 0..cfg.workers {
            workers.push(SimWorker::new(worker_id, cfg.seed, scratch_init(worker_id)));
        }

        Self {
            injector: VecDeque::new(),
            workers,
            state: ACCEPTING_BIT,
            done: false,
            next_unpark: 0,
            panic: None,
            exec_cfg,
            wake_on_hoard_threshold: cfg.wake_on_hoard_threshold,
            current_worker: 0,
        }
    }

    pub(crate) fn spawn_local(&mut self, task: T) {
        let wid = self.current_worker;
        self.spawn_local_for(wid, task);
    }

    /// Spawn a task into a specific worker's local queue.
    pub(crate) fn spawn_local_for(&mut self, wid: usize, task: T) {
        // Internal spawns always increment in-flight count.
        self.state = self.state.wrapping_add(COUNT_UNIT);
        let worker = &mut self.workers[wid];
        worker.local.push_back(task);

        worker.local_spawns_since_wake = worker.local_spawns_since_wake.saturating_add(1);
        if worker.local_spawns_since_wake >= self.wake_on_hoard_threshold {
            worker.local_spawns_since_wake = 0;
            self.unpark_one();
        }
    }

    pub(crate) fn spawn_global(&mut self, task: T) {
        // Global spawns always wake a sibling to reduce hoarding.
        self.state = self.state.wrapping_add(COUNT_UNIT);
        self.injector.push_back(task);
        self.unpark_one();
    }

    pub(crate) fn spawn_external(&mut self, task: T) -> Result<(), T> {
        // External spawns must respect the accepting gate.
        if !is_accepting(self.state) {
            return Err(task);
        }
        self.state = self.state.wrapping_add(COUNT_UNIT);
        self.injector.push_back(task);
        self.unpark_one();
        Ok(())
    }

    pub(crate) fn close_gate(&mut self) -> usize {
        let prev = self.state;
        self.state &= !ACCEPTING_BIT;
        prev
    }

    pub(crate) fn in_flight(&self) -> usize {
        in_flight(self.state)
    }

    /// Execute a single step for one worker.
    ///
    /// The caller must handle `ShouldPark` by choosing another enabled action.
    pub(crate) fn step_worker<Runner, Idle, Trace>(
        &mut self,
        wid: usize,
        runner: &mut Runner,
        idle: &mut Idle,
        trace: &mut Trace,
    ) -> WorkerStepResult<Trace::TaskTag>
    where
        Runner: FnMut(T, &mut SimExecutor<T, S>),
        Idle: IdleHooks,
        Trace: TraceHooks<T>,
    {
        // Simulate park token semantics: a parked worker only proceeds if it
        // has an unpark token available.
        let worker = &mut self.workers[wid];
        if worker.parked {
            if !worker.unpark_token {
                return WorkerStepResult::NoWork;
            }
            worker.unpark_token = false;
            worker.parked = false;
        }

        self.current_worker = wid;
        let exec_cfg = self.exec_cfg;
        let res = worker_step(&exec_cfg, runner, self, idle, trace);

        if matches!(res, WorkerStepResult::ShouldPark { .. }) {
            self.workers[wid].parked = true;
        }

        res
    }

    pub(crate) fn step_worker_no_trace<Runner>(
        &mut self,
        wid: usize,
        runner: &mut Runner,
    ) -> WorkerStepResult<<NoopTrace as TraceHooks<T>>::TaskTag>
    where
        Runner: FnMut(T, &mut SimExecutor<T, S>),
    {
        let mut idle = SimIdle;
        let mut trace = NoopTrace;
        self.step_worker(wid, runner, &mut idle, &mut trace)
    }
}

impl<T: Send + 'static, S> WorkerCtxLike<T, S> for SimExecutor<T, S> {
    fn worker_id(&self) -> usize {
        self.current_worker
    }

    fn worker_count(&self) -> usize {
        self.workers.len()
    }

    fn scratch_mut(&mut self) -> &mut S {
        &mut self.workers[self.current_worker].scratch
    }

    fn pop_local(&mut self) -> Option<T> {
        self.workers[self.current_worker].local.pop_back()
    }

    fn push_local(&mut self, task: T) {
        self.workers[self.current_worker].local.push_back(task);
    }

    fn push_injector(&mut self, task: T) {
        self.injector.push_back(task);
    }

    fn steal_from_injector(&mut self) -> Option<T> {
        self.injector.pop_front()
    }

    fn steal_from_victim(&mut self, victim: usize) -> Option<T> {
        self.workers[victim].local.pop_front()
    }

    fn shared_state_load(&self) -> usize {
        self.state
    }

    fn shared_state_fetch_sub(&mut self, delta: usize) -> usize {
        let prev = self.state;
        self.state = self.state.wrapping_sub(delta);
        prev
    }

    fn shared_state_close_gate(&mut self) -> usize {
        self.close_gate()
    }

    fn shared_state_increment(&mut self) -> Result<(), ()> {
        if !is_accepting(self.state) {
            return Err(());
        }
        self.state = self.state.wrapping_add(COUNT_UNIT);
        Ok(())
    }

    fn initiate_done(&mut self) {
        self.done = true;
        self.unpark_all();
    }

    fn done_flag(&self) -> bool {
        self.done
    }

    fn unpark_one(&mut self) {
        let n = self.workers.len();
        if n == 0 {
            return;
        }

        let idx = self.next_unpark % n;
        self.next_unpark = self.next_unpark.wrapping_add(1);

        let worker = &mut self.workers[idx];
        worker.unpark_token = true;
        worker.parked = false;
    }

    fn unpark_all(&mut self) {
        for worker in &mut self.workers {
            worker.unpark_token = true;
            worker.parked = false;
        }
    }

    fn record_panic(&mut self, payload: Box<dyn Any + Send + 'static>) {
        if self.panic.is_none() {
            self.panic = Some(payload);
        }
        self.done = true;
        self.unpark_all();
    }

    fn rng_next_usize(&mut self, upper: usize) -> usize {
        self.workers[self.current_worker].rng.next_usize(upper)
    }
}

struct SimIdle;

impl IdleHooks for SimIdle {
    fn on_work(&mut self) {}

    fn on_idle(&mut self, _cfg: &ExecutorConfig) -> IdleAction {
        // Simulation never sleeps; a "park" means the driver must pick
        // another enabled action to make progress.
        IdleAction::Park {
            timeout: Duration::from_micros(1),
        }
    }
}

// ============================================================================
// Task VM + resources
// ============================================================================

pub(crate) type ProgramId = u32;
pub(crate) type TaskId = u32;
pub(crate) type ResourceId = u16;
pub(crate) type IoToken = u32;

/// Static task program definition.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct TaskProgram {
    pub name: String,
    pub code: Vec<Instruction>,
}

/// Where a run-token should be enqueued.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SpawnPlacement {
    Local,
    Global,
    External,
}

/// Scheduler-relevant bytecode instruction set.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Instruction {
    Yield {
        placement: SpawnPlacement,
    },
    Spawn {
        program: ProgramId,
        placement: SpawnPlacement,
    },
    Sleep {
        ticks: u32,
    },
    WaitIo {
        token: IoToken,
    },
    TryAcquire {
        res: ResourceId,
        units: u32,
        ok: u16,
        fail: u16,
    },
    Release {
        res: ResourceId,
        units: u32,
    },
    Jump {
        target: u16,
    },
    Complete,
    Panic,
}

/// Initial task state used to seed a simulation case.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct LogicalTaskInit {
    pub tid: TaskId,
    pub program: ProgramId,
    pub pc: u16,
}

/// Blocking reason for a logical task.
///
/// `Resource` is reserved for future blocking semantics; current bytecode
/// uses `TryAcquire` instead of blocking on resources.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum BlockReason {
    SleepUntil(u64),
    Io(IoToken),
    Resource(ResourceId),
}

#[derive(Clone, Debug)]
struct LogicalTask {
    program: ProgramId,
    pc: u16,
    blocked: Option<BlockReason>,
    held: std::collections::BTreeMap<ResourceId, u32>,
    completed: bool,
}

pub(crate) trait TaskTraceHooks {
    /// Called before an instruction is executed for a task.
    fn on_task_instr(&mut self, tid: TaskId, pc: u16, instr: &Instruction);

    /// Called when a spawn successfully enqueues a new run-token.
    fn on_task_spawn(&mut self, _parent: TaskId, _child: TaskId, _placement: SpawnPlacement) {}
}

/// No-op task tracing (production default).
pub(crate) struct NoopTaskTrace;

impl TaskTraceHooks for NoopTaskTrace {
    fn on_task_instr(&mut self, _tid: TaskId, _pc: u16, _instr: &Instruction) {}
}

/// Bytecode VM for scheduler simulations.
///
/// # Execution Model
///
/// ```text
///   LogicalTask                    Executor Queue
///   ┌─────────────┐               ┌───────────────┐
///   │ program: 0  │               │               │
///   │ pc: 0       │  ◄────────────│  run-token    │
///   │ blocked: No │               │  (TaskId=42)  │
///   └─────────────┘               └───────────────┘
///         │
///         │ exec_one(tid=42)
///         ▼
///   ┌─────────────┐
///   │ Execute     │
///   │ programs[0] │
///   │   .code[0]  │
///   └─────────────┘
///         │
///         │ Yield { Local }
///         ▼
///   ┌─────────────┐               ┌───────────────┐
///   │ pc: 1       │               │  new token    │
///   │ blocked: No │  ────────────►│  (TaskId=42)  │
///   └─────────────┘               └───────────────┘
/// ```
///
/// # Semantics
///
/// - A logical task persists across run-tokens (it has identity).
/// - Each executor step consumes one token and advances exactly one instruction.
/// - `Yield` and `Spawn` create new run-tokens via the executor queues.
/// - `Sleep`/`WaitIo` block without enqueuing a token until an external event.
///
/// # Invariants
///
/// - A task never has two run-tokens in flight simultaneously (enforced by blocking).
/// - Completed tasks never re-enter the runnable set.
/// - `pc` advances monotonically except for `Jump` and `TryAcquire` branch instructions.
pub(crate) struct TaskVm {
    programs: Vec<TaskProgram>,
    tasks: std::collections::BTreeMap<TaskId, LogicalTask>,
    io_waiters: std::collections::BTreeMap<IoToken, std::collections::BTreeSet<TaskId>>,
    sleepers: std::collections::BTreeMap<u64, Vec<TaskId>>,
    next_tid: TaskId,
}

impl TaskVm {
    pub(crate) fn new(programs: Vec<TaskProgram>, tasks: Vec<LogicalTaskInit>) -> Self {
        let mut map = std::collections::BTreeMap::new();
        let mut max_tid = 0;
        for t in tasks {
            max_tid = max_tid.max(t.tid);
            map.insert(
                t.tid,
                LogicalTask {
                    program: t.program,
                    pc: t.pc,
                    blocked: None,
                    held: std::collections::BTreeMap::new(),
                    completed: false,
                },
            );
        }
        Self {
            programs,
            tasks: map,
            io_waiters: std::collections::BTreeMap::new(),
            sleepers: std::collections::BTreeMap::new(),
            next_tid: max_tid.saturating_add(1),
        }
    }

    /// Execute a single instruction for the given task id.
    ///
    /// If the task is blocked or completed, this is a no-op.
    pub(crate) fn exec_one<S, Trace>(
        &mut self,
        tid: TaskId,
        wid: usize,
        now: u64,
        ex: &mut SimExecutor<TaskId, S>,
        res: &mut ResourceModel,
        trace: &mut Trace,
    ) where
        Trace: TaskTraceHooks,
    {
        let before_state = ex.state;
        let before_avail: Vec<(ResourceId, u32)> = res
            .totals
            .keys()
            .map(|rid| (*rid, res.avail(*rid)))
            .collect();

        let (program, pc, blocked, completed) = match self.tasks.get(&tid) {
            Some(task) => (
                task.program,
                task.pc,
                task.blocked.is_some(),
                task.completed,
            ),
            None => panic!("unknown task id {tid}"),
        };
        if completed || blocked {
            return;
        }

        let instr = self
            .programs
            .get(program as usize)
            .and_then(|prog| prog.code.get(pc as usize))
            .cloned()
            .unwrap_or(Instruction::Complete);

        trace.on_task_instr(tid, pc, &instr);

        match instr {
            Instruction::Yield { placement } => {
                let task = self.tasks.get_mut(&tid).expect("task exists");
                task.pc = task.pc.saturating_add(1);
                self.enqueue_run_token(ex, wid, tid, placement);
            }
            Instruction::Spawn { program, placement } => {
                let child_tid = self.allocate_task(program);
                let enqueued = self.enqueue_run_token(ex, wid, child_tid, placement);
                if enqueued {
                    trace.on_task_spawn(tid, child_tid, placement);
                }
                let task = self.tasks.get_mut(&tid).expect("task exists");
                task.pc = task.pc.saturating_add(1);
            }
            Instruction::Sleep { ticks } => {
                let wake = now.saturating_add(ticks as u64);
                let task = self.tasks.get_mut(&tid).expect("task exists");
                task.blocked = Some(BlockReason::SleepUntil(wake));
                self.sleepers.entry(wake).or_default().push(tid);
                task.pc = task.pc.saturating_add(1);
            }
            Instruction::WaitIo { token } => {
                let task = self.tasks.get_mut(&tid).expect("task exists");
                task.blocked = Some(BlockReason::Io(token));
                self.io_waiters.entry(token).or_default().insert(tid);
                task.pc = task.pc.saturating_add(1);
            }
            Instruction::TryAcquire {
                res: rid,
                units,
                ok,
                fail,
            } => {
                let task = self.tasks.get_mut(&tid).expect("task exists");
                if res.try_acquire(rid, units) {
                    *task.held.entry(rid).or_insert(0) += units;
                    task.pc = ok;
                } else {
                    task.pc = fail;
                }
            }
            Instruction::Release { res: rid, units } => {
                let task = self.tasks.get_mut(&tid).expect("task exists");
                let held = task
                    .held
                    .get_mut(&rid)
                    .unwrap_or_else(|| panic!("release without hold on {rid}"));
                assert!(*held >= units, "release underflow");
                *held -= units;
                if *held == 0 {
                    task.held.remove(&rid);
                }
                res.release(rid, units);
                task.pc = task.pc.saturating_add(1);
            }
            Instruction::Jump { target } => {
                let task = self.tasks.get_mut(&tid).expect("task exists");
                task.pc = target;
            }
            Instruction::Complete => {
                let task = self.tasks.get_mut(&tid).expect("task exists");
                task.completed = true;
            }
            Instruction::Panic => {
                panic!("task panic requested");
            }
        }

        // In simulation mode, always check invariants to catch concurrency bugs.
        // These would be debug_assert in production, but the harness exists to find bugs.
        assert!(
            ex.state >= before_state.saturating_sub(COUNT_UNIT),
            "executor state underflow"
        );
        for (rid, before) in before_avail {
            assert!(
                res.avail(rid) <= before + res.totals.get(&rid).copied().unwrap_or(0),
                "resource accounting overflow for {rid}"
            );
        }
    }

    fn enqueue_run_token<S>(
        &self,
        ex: &mut SimExecutor<TaskId, S>,
        wid: usize,
        tid: TaskId,
        placement: SpawnPlacement,
    ) -> bool {
        match placement {
            SpawnPlacement::Local => {
                ex.spawn_local_for(wid, tid);
                true
            }
            SpawnPlacement::Global => {
                ex.spawn_global(tid);
                true
            }
            SpawnPlacement::External => ex.spawn_external(tid).is_ok(),
        }
    }

    fn allocate_task(&mut self, program: ProgramId) -> TaskId {
        let tid = self.next_tid;
        self.next_tid = self.next_tid.saturating_add(1);
        self.tasks.insert(
            tid,
            LogicalTask {
                program,
                pc: 0,
                blocked: None,
                held: std::collections::BTreeMap::new(),
                completed: false,
            },
        );
        tid
    }

    /// Deliver an IO completion, unblocking any waiting tasks.
    ///
    /// # Panics
    ///
    /// Panics if the executor gate is closed when trying to spawn a waiting task.
    /// This indicates a simulation bug where IO completion races with gate closure.
    pub(crate) fn deliver_io<S>(&mut self, token: IoToken, ex: &mut SimExecutor<TaskId, S>) {
        let Some(waiters) = self.io_waiters.remove(&token) else {
            return;
        };
        for tid in waiters {
            if let Some(task) = self.tasks.get_mut(&tid) {
                task.blocked = None;
                ex.spawn_external(tid)
                    .expect("spawn_external failed during IO delivery - gate unexpectedly closed");
            }
        }
    }

    /// Wake sleepers whose deadlines are <= `now`.
    ///
    /// # Panics
    ///
    /// Panics if the executor gate is closed when trying to spawn a sleeping task.
    /// This indicates a simulation bug where sleep wakeup races with gate closure.
    pub(crate) fn wake_sleepers<S>(&mut self, now: u64, ex: &mut SimExecutor<TaskId, S>) {
        let keys: Vec<u64> = self.sleepers.range(..=now).map(|(k, _)| *k).collect();
        for k in keys {
            if let Some(tids) = self.sleepers.remove(&k) {
                for tid in tids {
                    if let Some(task) = self.tasks.get_mut(&tid) {
                        task.blocked = None;
                        ex.spawn_external(tid).expect(
                            "spawn_external failed during sleep wakeup - gate unexpectedly closed",
                        );
                    }
                }
            }
        }
    }

    pub(crate) fn next_sleep_deadline(&self) -> Option<u64> {
        self.sleepers.keys().next().copied()
    }
}

/// Resource specification for simulation.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ResourceSpec {
    pub id: ResourceId,
    pub total: u32,
}

/// Deterministic resource accounting model.
///
/// This model is intentionally minimal: it never blocks. `TryAcquire` is
/// a conditional check; `Release` asserts against over-release.
pub(crate) struct ResourceModel {
    totals: std::collections::BTreeMap<ResourceId, u32>,
    avail: std::collections::BTreeMap<ResourceId, u32>,
}

impl ResourceModel {
    pub(crate) fn new(specs: &[ResourceSpec]) -> Self {
        let mut totals = std::collections::BTreeMap::new();
        let mut avail = std::collections::BTreeMap::new();
        for s in specs {
            totals.insert(s.id, s.total);
            avail.insert(s.id, s.total);
        }
        Self { totals, avail }
    }

    pub(crate) fn check_invariants(&self, step: u64) -> Result<(), FailureInfo> {
        for (rid, total) in &self.totals {
            let avail = *self.avail.get(rid).unwrap_or(&0);
            if avail > *total {
                return Err(FailureInfo {
                    kind: FailureKind::Violation(ViolationKind::ResourceOverflow),
                    step,
                    message: format!("resource {rid} avail {avail} > total {total}"),
                });
            }
        }
        Ok(())
    }

    pub(crate) fn try_acquire(&mut self, rid: ResourceId, units: u32) -> bool {
        let a = *self.avail.get(&rid).unwrap_or(&0);
        if a < units {
            return false;
        }
        self.avail.insert(rid, a - units);
        true
    }

    pub(crate) fn avail(&self, rid: ResourceId) -> u32 {
        *self.avail.get(&rid).unwrap_or(&0)
    }

    pub(crate) fn release(&mut self, rid: ResourceId, units: u32) {
        let a = *self.avail.get(&rid).unwrap_or(&0);
        let t = *self.totals.get(&rid).unwrap_or(&0);
        let new = a + units;
        assert!(new <= t, "resource over-release");
        self.avail.insert(rid, new);
    }
}

/// External events delivered by the simulation driver.
///
/// `CloseGateJoin` models `Executor::join()` closing the accepting gate.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ExternalEvent {
    IoComplete { token: IoToken },
    CloseGateJoin,
}

/// Scheduled external event for deterministic replay.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ScheduledEvent {
    pub at_step: u64,
    pub event: ExternalEvent,
}

/// Simulation case definition for deterministic driver runs.
///
/// The driver uses this to build a `SimState` with a fixed executor policy,
/// static programs, and a deterministic external event schedule.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SimCase {
    pub exec_cfg: SimExecCfg,
    pub resources: Vec<ResourceSpec>,
    pub programs: Vec<TaskProgram>,
    pub tasks: Vec<LogicalTaskInit>,
    pub initial_runnable: Vec<TaskId>,
    pub external_events: Vec<ScheduledEvent>,
    /// Hard cap on driver steps (prevents infinite runs).
    pub max_steps: u64,
}

impl SimCase {
    pub(crate) fn validate(&self) {
        self.exec_cfg.validate();
        assert!(!self.programs.is_empty(), "programs must be non-empty");
        assert!(self.max_steps > 0, "max_steps must be > 0");
    }
}

/// Actions the deterministic driver can choose at each step.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum DriverAction {
    /// Execute a single worker step.
    StepWorker { wid: usize },
    /// Deliver a scheduled external event whose time has arrived.
    DeliverEvent { index: usize },
    /// Advance simulated time to the next deadline.
    AdvanceTimeTo { now: u64 },
}

/// Choice encoding for replay: index into the enabled action list.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DriverChoice {
    pub idx: u16,
}

/// Trace header for deterministic replay.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TraceHeader {
    pub schema_version: u32,
    pub seed: u64,
}

/// Trace of driver actions and scheduler events.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Trace {
    pub header: TraceHeader,
    pub events: Vec<TraceEvent>,
    pub final_digest: StateDigest,
}

/// Trace events emitted during a simulation run.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum TraceEvent {
    Step {
        n: u64,
        action: DriverAction,
    },
    Exec {
        event: ExecTraceEventSimple,
    },
    TaskInstr {
        tid: TaskId,
        pc: u16,
        instr: Instruction,
    },
    External {
        event: ExternalEvent,
    },
    InvariantViolation {
        kind: ViolationKind,
        message: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StateDigest {
    pub in_flight: usize,
    pub accepting: bool,
    pub done: bool,
    pub worker_locals: Vec<usize>,
    pub injector_len: usize,
}

/// Public-safe executor trace summary for serialization.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ExecTraceEventSimple {
    Pop {
        wid: usize,
        source: ExecTraceSource,
        victim: Option<usize>,
        tid: TaskId,
    },
    SpawnLocal {
        wid: usize,
    },
    SpawnGlobal {
        wid: usize,
    },
    SpawnExternal,
    UnparkOne {
        target: usize,
    },
    InitiateDone,
    PanicRecorded,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ExecTraceSource {
    Local,
    Injector,
    Steal,
}

impl From<&ExecTraceEvent<TaskId>> for ExecTraceEventSimple {
    fn from(event: &ExecTraceEvent<TaskId>) -> Self {
        match event {
            ExecTraceEvent::Pop {
                wid,
                source,
                victim,
                tag,
            } => ExecTraceEventSimple::Pop {
                wid: *wid,
                source: match source {
                    PopSource::Local => ExecTraceSource::Local,
                    PopSource::Injector => ExecTraceSource::Injector,
                    PopSource::Steal => ExecTraceSource::Steal,
                },
                victim: *victim,
                tid: *tag,
            },
            ExecTraceEvent::SpawnLocal { wid } => ExecTraceEventSimple::SpawnLocal { wid: *wid },
            ExecTraceEvent::SpawnGlobal { wid } => ExecTraceEventSimple::SpawnGlobal { wid: *wid },
            ExecTraceEvent::SpawnExternal => ExecTraceEventSimple::SpawnExternal,
            ExecTraceEvent::UnparkOne { target } => {
                ExecTraceEventSimple::UnparkOne { target: *target }
            }
            ExecTraceEvent::InitiateDone => ExecTraceEventSimple::InitiateDone,
            ExecTraceEvent::PanicRecorded => ExecTraceEventSimple::PanicRecorded,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ViolationKind {
    InFlightMismatch,
    /// Reserved for future run-token tracking; not emitted by current oracles.
    DoubleRun,
    TaskStateOverlap,
    GateViolation,
    ResourceOverflow,
    LostWakeup,
    RunnableStarvation,
    IllegalUnblock,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum FailureKind {
    Violation(ViolationKind),
    Panic,
    Timeout,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FailureInfo {
    pub kind: FailureKind,
    pub step: u64,
    pub message: String,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ReproArtifact {
    pub schema_version: u32,
    pub seed: u64,
    pub case: SimCase,
    pub driver_choices: Vec<DriverChoice>,
    pub expected_trace_hash: u64,
    pub failure: FailureInfo,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct MinimizeConfig {
    pub max_checks: usize,
}

/// Compute a stable 64-bit hash of the trace events.
///
/// This is used to sanity-check replay determinism without storing the
/// entire trace in the repro artifact.
pub fn trace_hash(trace: &Trace) -> u64 {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    for event in &trace.events {
        hasher.update(format!("{event:?}").as_bytes());
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest[..8]);
    u64::from_le_bytes(out)
}

pub fn minimize(
    mut artifact: ReproArtifact,
    cfg: MinimizeConfig,
    check: impl Fn(&ReproArtifact) -> Result<(), FailureInfo>,
) -> ReproArtifact {
    let mut checks = 0usize;

    loop {
        if checks >= cfg.max_checks {
            break;
        }

        let mut changed = false;

        // Reduce workers.
        for w in 1..artifact.case.exec_cfg.workers {
            if checks >= cfg.max_checks {
                break;
            }
            let mut cand = artifact.clone();
            cand.case.exec_cfg.workers = w;
            checks += 1;
            if check(&cand).is_err() {
                artifact = cand;
                changed = true;
                break;
            }
        }

        // Reduce external events (ddmin-like: try dropping halves).
        if !artifact.case.external_events.is_empty() {
            let mut keep = artifact.case.external_events.clone();
            let mut n = keep.len();
            let mut step_size = n / 2;
            while step_size > 0 {
                let mut i = 0;
                while i < n {
                    if checks >= cfg.max_checks {
                        break;
                    }
                    let mut cand = artifact.clone();
                    let mut filtered = Vec::with_capacity(keep.len());
                    for (idx, ev) in keep.iter().enumerate() {
                        if idx < i || idx >= i + step_size {
                            filtered.push(ev.clone());
                        }
                    }
                    cand.case.external_events = filtered;
                    checks += 1;
                    if check(&cand).is_err() {
                        artifact = cand;
                        keep = artifact.case.external_events.clone();
                        n = keep.len();
                        changed = true;
                        break;
                    }
                    i += step_size;
                }
                if !changed {
                    step_size /= 2;
                } else {
                    break;
                }
            }
        }

        // Reduce driver choices by truncating.
        if !artifact.driver_choices.is_empty() {
            let mut cut = artifact.driver_choices.len() / 2;
            while cut > 0 {
                if checks >= cfg.max_checks {
                    break;
                }
                let mut cand = artifact.clone();
                cand.driver_choices.truncate(cut);
                checks += 1;
                if check(&cand).is_err() {
                    artifact = cand;
                    changed = true;
                    break;
                }
                cut /= 2;
            }
        }

        if !changed {
            break;
        }
    }

    artifact
}

/// Internal state used by the driver loop.
struct SimState {
    now: u64,
    ex: SimExecutor<TaskId, ()>,
    vm: TaskVm,
    res: ResourceModel,
    events: Vec<ScheduledEvent>,
    delivered: Vec<bool>,
}

impl SimState {
    fn from_case(case: &SimCase) -> Self {
        case.validate();
        let mut ex = SimExecutor::new(case.exec_cfg, |_| ());
        let vm = TaskVm::new(case.programs.clone(), case.tasks.clone());
        let res = ResourceModel::new(&case.resources);

        for tid in &case.initial_runnable {
            ex.spawn_external(*tid)
                .expect("initial spawn should never fail - executor starts in accepting state");
        }

        Self {
            now: 0,
            ex,
            vm,
            res,
            events: case.external_events.clone(),
            delivered: vec![false; case.external_events.len()],
        }
    }

    fn digest(&self) -> StateDigest {
        StateDigest {
            in_flight: self.ex.in_flight(),
            accepting: is_accepting(self.ex.state),
            done: self.ex.done,
            worker_locals: self.ex.workers.iter().map(|w| w.local.len()).collect(),
            injector_len: self.ex.injector.len(),
        }
    }
}

/// Step-wise oracle checks for determinism, safety, and liveness.
///
/// # Checked Invariants
///
/// | Invariant | Violation Kind | Description |
/// |-----------|----------------|-------------|
/// | No starvation | `RunnableStarvation` | Runnable tasks execute within bounded steps |
/// | Resource accounting | `ResourceOverflow` | Available ≤ total for each resource |
/// | Gate consistency | `GateViolation` | `done` set when gate closes at count=0 |
///
/// # Starvation Bound
///
/// A task enqueued at step `S` with backlog `B` must execute by step:
/// `S + max_starvation + B` where `max_starvation = workers * (steal_tries + 2) * 4`.
///
/// This bound is deliberately loose to avoid false positives from driver
/// scheduling choices that don't represent scheduler bugs.
///
/// # Design Notes
///
/// These checks are deliberately simple: they run on every step and surface
/// violations as structured trace events rather than panicking, so the
/// harness can serialize a repro and continue to shrink it.
///
/// Note: run-token level double-run detection is not enforced because the
/// simulator does not track explicit run-token identifiers yet.
struct OracleChecker {
    runnable_age: std::collections::BTreeMap<TaskId, RunnableAge>,
    max_starvation: u64,
    last_step: u64,
}

#[derive(Clone, Copy, Debug)]
struct RunnableAge {
    since: u64,
    backlog: u64,
}

impl OracleChecker {
    fn new(workers: usize, steal_tries: u32) -> Self {
        let k = (workers as u64)
            .saturating_mul(steal_tries as u64 + 2)
            .saturating_mul(4);
        Self {
            runnable_age: std::collections::BTreeMap::new(),
            max_starvation: k.max(1),
            last_step: 0,
        }
    }

    /// Validate invariants after a single driver step.
    fn check_step(
        &mut self,
        state: &SimState,
        exec_events: &[super::executor_core::ExecTraceEvent<TaskId>],
        task_events: &[(TaskId, u16, Instruction)],
        spawn_events: &[(TaskId, TaskId, SpawnPlacement)],
        step: u64,
    ) -> Result<(), FailureInfo> {
        self.last_step = step;

        // Track runnable age for re-enqueued tasks and spawned children.
        for ev in exec_events {
            if let super::executor_core::ExecTraceEvent::Pop { tag, .. } = ev {
                self.runnable_age.remove(tag);
            }
        }

        let backlog = state.ex.in_flight() as u64;
        for (tid, _, instr) in task_events {
            if matches!(instr, Instruction::Yield { .. }) {
                self.runnable_age.entry(*tid).or_insert(RunnableAge {
                    since: step,
                    backlog,
                });
            }
        }

        for (_, child, _) in spawn_events {
            self.runnable_age.entry(*child).or_insert(RunnableAge {
                since: step,
                backlog,
            });
        }

        // Starvation: runnable task should execute within bound, scaled by
        // the backlog at the time the task became runnable.
        for (tid, age) in &self.runnable_age {
            let bound = self.max_starvation.saturating_add(age.backlog);
            if step.saturating_sub(age.since) > bound {
                return Err(FailureInfo {
                    kind: FailureKind::Violation(ViolationKind::RunnableStarvation),
                    step,
                    message: format!(
                        "task {tid} runnable since step {} (backlog {})",
                        age.since, age.backlog
                    ),
                });
            }
        }

        state.res.check_invariants(step).map_err(|mut info| {
            info.step = step;
            info
        })?;

        // In-flight counter should be >= runnable + running (approx check).
        if state.ex.in_flight() == 0 && !is_accepting(state.ex.state) && !state.ex.done {
            return Err(FailureInfo {
                kind: FailureKind::Violation(ViolationKind::GateViolation),
                step,
                message: "gate closed with zero in-flight but done not set".to_string(),
            });
        }

        Ok(())
    }
}

/// Deterministic driver with optional pre-recorded choices.
struct Driver {
    choices: Vec<DriverChoice>,
    cursor: usize,
}

impl Driver {
    fn new(choices: &[DriverChoice]) -> Self {
        Self {
            choices: choices.to_vec(),
            cursor: 0,
        }
    }

    /// Choose the next enabled action.
    ///
    /// If choices are exhausted or out of range, defaults to the first action
    /// to keep replay deterministic and total.
    fn choose(&mut self, enabled: &[DriverAction]) -> DriverAction {
        let idx = if self.cursor < self.choices.len() {
            self.choices[self.cursor].idx as usize
        } else {
            0
        };
        self.cursor = self.cursor.saturating_add(1);
        enabled
            .get(idx)
            .cloned()
            .unwrap_or_else(|| enabled[0].clone())
    }
}

/// Collects executor-side trace events during a single step.
struct ExecEventSink {
    events: Vec<super::executor_core::ExecTraceEvent<TaskId>>,
}

impl ExecEventSink {
    fn new() -> Self {
        Self { events: Vec::new() }
    }
}

impl TraceHooks<TaskId> for ExecEventSink {
    type TaskTag = TaskId;

    fn is_enabled(&self) -> bool {
        true
    }

    fn tag_task(&mut self, task: &TaskId) -> Self::TaskTag {
        *task
    }

    fn on_event(&mut self, event: super::executor_core::ExecTraceEvent<Self::TaskTag>) {
        self.events.push(event);
    }
}

/// Collects task instruction events during a single step.
struct TaskEventSink {
    events: Vec<(TaskId, u16, Instruction)>,
    spawn_events: Vec<(TaskId, TaskId, SpawnPlacement)>,
}

impl TaskEventSink {
    fn new() -> Self {
        Self {
            events: Vec::new(),
            spawn_events: Vec::new(),
        }
    }
}

impl TaskTraceHooks for TaskEventSink {
    fn on_task_instr(&mut self, tid: TaskId, pc: u16, instr: &Instruction) {
        self.events.push((tid, pc, instr.clone()));
    }

    fn on_task_spawn(&mut self, parent: TaskId, child: TaskId, placement: SpawnPlacement) {
        self.spawn_events.push((parent, child, placement));
    }
}

/// Compute the next time jump candidate from future events or sleepers.
fn next_time(state: &SimState) -> Option<u64> {
    let mut next: Option<u64> = None;
    for (idx, ev) in state.events.iter().enumerate() {
        if state.delivered[idx] {
            continue;
        }
        if ev.at_step > state.now {
            next = Some(match next {
                Some(cur) => cur.min(ev.at_step),
                None => ev.at_step,
            });
        }
    }

    if let Some(sleep) = state.vm.next_sleep_deadline() {
        if sleep > state.now {
            next = Some(match next {
                Some(cur) => cur.min(sleep),
                None => sleep,
            });
        }
    }

    next
}

/// Enumerate enabled actions in a stable order for deterministic replay.
fn enabled_actions(state: &SimState) -> Vec<DriverAction> {
    if state.ex.done {
        return Vec::new();
    }

    let mut actions = Vec::new();
    for (idx, ev) in state.events.iter().enumerate() {
        if !state.delivered[idx] && ev.at_step <= state.now {
            actions.push(DriverAction::DeliverEvent { index: idx });
        }
    }

    let all_parked = state.ex.workers.iter().all(|w| w.parked && !w.unpark_token);

    if !all_parked {
        for wid in 0..state.ex.workers.len() {
            actions.push(DriverAction::StepWorker { wid });
        }
    }

    if actions.is_empty() {
        if let Some(next) = next_time(state) {
            actions.push(DriverAction::AdvanceTimeTo { now: next });
        }
    }

    actions
}

/// Run a simulation using a custom driver policy.
///
/// # Driver Contract
///
/// The `choose` callback receives the enabled actions for the current step and
/// must return one of them. If it returns an action not in the enabled set, the
/// harness falls back to the first enabled action to preserve determinism.
///
/// # Action Priority (`enabled_actions` order)
///
/// ```text
/// 1. DeliverEvent   - scheduled events whose time has arrived
/// 2. StepWorker     - workers that are not parked (or have unpark token)
/// 3. AdvanceTimeTo  - only when no other actions are enabled
/// ```
///
/// # Termination
///
/// The simulation terminates when:
/// - `case.max_steps` is reached (timeout)
/// - `enabled_actions` returns empty (natural completion)
/// - An oracle check fails (invariant violation recorded in trace)
/// - A task panics (`ExitPanicked` result)
///
/// # Trace Output
///
/// The returned `Trace` contains all driver steps, executor events, and task
/// instructions. Use `trace_hash()` to compute a stable fingerprint for
/// regression testing.
pub fn run_with_driver<F>(case: &SimCase, mut choose: F) -> Trace
where
    F: FnMut(&[DriverAction]) -> DriverAction,
{
    let mut state = SimState::from_case(case);
    let mut oracles = OracleChecker::new(case.exec_cfg.workers, case.exec_cfg.steal_tries);
    let mut trace = Trace {
        header: TraceHeader {
            schema_version: 1,
            seed: case.exec_cfg.seed,
        },
        events: Vec::new(),
        final_digest: StateDigest {
            in_flight: 0,
            accepting: false,
            done: false,
            worker_locals: Vec::new(),
            injector_len: 0,
        },
    };

    for step in 0..case.max_steps {
        let enabled = enabled_actions(&state);
        if enabled.is_empty() {
            break;
        }

        let mut action = choose(&enabled);
        if !enabled.contains(&action) {
            action = enabled[0].clone();
        }

        trace.events.push(TraceEvent::Step {
            n: step,
            action: action.clone(),
        });

        match action {
            DriverAction::StepWorker { wid } => {
                let now = state.now;
                let mut exec_trace = ExecEventSink::new();
                let mut task_trace = TaskEventSink::new();
                let mut idle = SimIdle;

                let mut runner = |tid: TaskId, ex: &mut SimExecutor<TaskId, ()>| {
                    state
                        .vm
                        .exec_one(tid, wid, now, ex, &mut state.res, &mut task_trace);
                };

                let res = state
                    .ex
                    .step_worker(wid, &mut runner, &mut idle, &mut exec_trace);

                for event in &exec_trace.events {
                    trace.events.push(TraceEvent::Exec {
                        event: ExecTraceEventSimple::from(event),
                    });
                }
                for (tid, pc, instr) in &task_trace.events {
                    trace.events.push(TraceEvent::TaskInstr {
                        tid: *tid,
                        pc: *pc,
                        instr: instr.clone(),
                    });
                }

                if let Err(info) = oracles.check_step(
                    &state,
                    &exec_trace.events,
                    &task_trace.events,
                    &task_trace.spawn_events,
                    step,
                ) {
                    trace.events.push(TraceEvent::InvariantViolation {
                        kind: match info.kind {
                            FailureKind::Violation(kind) => kind,
                            _ => ViolationKind::InFlightMismatch,
                        },
                        message: info.message,
                    });
                    return trace;
                }

                if matches!(res, WorkerStepResult::ExitPanicked) {
                    break;
                }
            }
            DriverAction::DeliverEvent { index } => {
                state.delivered[index] = true;
                let event = state.events[index].event.clone();
                trace.events.push(TraceEvent::External {
                    event: event.clone(),
                });
                match event {
                    ExternalEvent::IoComplete { token } => {
                        state.vm.deliver_io(token, &mut state.ex);
                    }
                    ExternalEvent::CloseGateJoin => {
                        let prev = state.ex.close_gate();
                        if in_flight(prev) == 0 {
                            state.ex.initiate_done();
                        }
                    }
                }
            }
            DriverAction::AdvanceTimeTo { now } => {
                state.now = now;
                state.vm.wake_sleepers(state.now, &mut state.ex);
            }
        }
    }

    trace.final_digest = state.digest();
    trace
}

/// Run a simulation using explicit driver choices (or default-first selection).
pub fn run_with_choices(case: &SimCase, choices: &[DriverChoice]) -> Trace {
    let mut driver = Driver::new(choices);
    run_with_driver(case, |enabled| driver.choose(enabled))
}

/// Assert that a case + choices produce identical traces across runs.
pub fn assert_deterministic(case: &SimCase, choices: &[DriverChoice]) {
    let t1 = run_with_choices(case, choices);
    let t2 = run_with_choices(case, choices);
    assert_eq!(t1, t2, "non-deterministic trace");
}

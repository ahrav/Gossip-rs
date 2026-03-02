//! Work-Stealing CPU Executor
//!
//! # Architecture
//!
//! ```text
//!                    ┌─────────────────────────────────────────────────────────────┐
//!                    │                        Executor                             │
//!                    │                                                             │
//!  External ─────────┼────► Injector ──────┬──────────────────────────────────────┤
//!  Producers         │      (Crossbeam)    │                                       │
//!                    │                     ▼                                       │
//!                    │     ┌─────────────────────────────────────────────────┐     │
//!                    │     │   Worker 0    │   Worker 1    │   Worker N     │     │
//!                    │     │  ┌─────────┐  │  ┌─────────┐  │  ┌─────────┐  │     │
//!                    │     │  │ Deque   │◄─┼─►│ Deque   │◄─┼─►│ Deque   │  │     │
//!                    │     │  │ (LIFO)  │  │  │ (LIFO)  │  │  │ (LIFO)  │  │     │
//!                    │     │  └────┬────┘  │  └────┬────┘  │  └────┬────┘  │     │
//!                    │     │       │       │       │       │       │       │     │
//!                    │     │  ┌────▼────┐  │  ┌────▼────┐  │  ┌────▼────┐  │     │
//!                    │     │  │WorkerCtx│  │  │WorkerCtx│  │  │WorkerCtx│  │     │
//!                    │     │  │+ scratch│  │  │+ scratch│  │  │+ scratch│  │     │
//!                    │     │  │+ metrics│  │  │+ metrics│  │  │+ metrics│  │     │
//!                    │     │  └─────────┘  │  └─────────┘  │  └─────────┘  │     │
//!                    │     └───────────────┴───────────────┴───────────────┘     │
//!                    │                           ▲                                │
//!                    │          Shared: state, done, unparkers                   │
//!                    └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! - N worker threads (optionally pinned to cores)
//! - Per-worker Chase-Lev deque (LIFO local, FIFO steal)
//! - Per-worker scratch space via [`WorkerCtx<T, S>`]
//! - Global injector for external producers
//! - Tiered idle strategy: spin → park (with occasional yields)
//!
//! # Correctness Invariants
//!
//! - **Work-conserving**: once spawned, a task will execute
//! - **Termination detection**: `in_flight` counter tracks live tasks
//! - **Panic isolation**: panics caught and propagated on join
//! - **No lost wakeups**: Parker/Unparker pattern
//!
//! # Performance Invariants
//!
//! - **Local-first spawn**: reduces contention, improves locality
//! - **Randomized stealing**: avoids correlated contention
//! - **Batch steal from injector**: reduces global queue contention
//!
//! # What This Does NOT Guarantee Yet
//!
//! - **Bounded task queues**: crossbeam queues are unbounded.
//!   Use `TokenBudget` to cap the number of queued tasks.
//! - **I/O completion integration**: the seam exists via [`ExecutorHandle::spawn()`].

use super::executor_core::{
    close_gate, in_flight, increment_count, is_accepting, worker_step, IdleAction, IdleHooks,
    NoopTrace, WorkerCtxLike, WorkerStepResult, ACCEPTING_BIT, COUNT_UNIT, WAKE_ON_HOARD_THRESHOLD,
};
use super::metrics::WorkerMetricsLocal;
use super::rng::XorShift64;
use crate::perf_stats;
use crossbeam_deque::{Injector, Steal, Stealer, Worker};
use crossbeam_utils::sync::{Parker, Unparker};
use std::any::Any;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

// ============================================================================
// Configuration
// ============================================================================

/// Executor configuration.
///
/// All defaults are conservative. Profile with your workload before tuning.
///
/// # Measurement Required Before Tuning
///
/// | Knob         | Workload Sensitivity                    |
/// |--------------|-----------------------------------------|
/// | workers      | CPU count, task CPU-boundedness         |
/// | steal_tries  | Task fanout pattern, worker count       |
/// | spin_iters   | Task latency distribution               |
/// | park_timeout | External spawn frequency                |
#[derive(Clone, Copy, Debug)]
pub struct ExecutorConfig {
    /// Number of worker threads.
    pub workers: usize,

    /// Seed for deterministic victim selection.
    ///
    /// Same seed + same task spawn order = reproducible steal pattern (modulo timing).
    pub seed: u64,

    /// Steal attempts before giving up per idle cycle.
    ///
    /// Higher = less parking, more CPU when idle.
    /// Lower = faster sleep, less steal overhead.
    pub steal_tries: u32,

    /// Spin iterations before yielding/parking.
    ///
    /// Higher = better latency for bursty work.
    /// Lower = less CPU waste when truly idle.
    pub spin_iters: u32,

    /// Park timeout after spinning/yielding.
    ///
    /// Shorter = more responsive to external spawns.
    /// Longer = less OS scheduling overhead.
    pub park_timeout: Duration,

    /// Try to pin each worker to a core (Linux only).
    pub pin_threads: bool,
}

impl ExecutorConfig {
    /// Validate configuration. Panics on invalid values.
    pub fn validate(&self) {
        assert!(self.workers > 0, "workers must be > 0");
        assert!(self.steal_tries > 0, "steal_tries must be > 0");
        assert!(self.spin_iters > 0, "spin_iters must be > 0");
        assert!(
            self.park_timeout > Duration::ZERO,
            "park_timeout must be > 0"
        );
    }
}

impl Default for ExecutorConfig {
    fn default() -> Self {
        Self {
            workers: 1,
            seed: 0x853c49e6748fea9b,
            steal_tries: 4,
            spin_iters: 200,
            park_timeout: Duration::from_micros(200),
            pin_threads: super::affinity::default_pin_threads(),
        }
    }
}

// ============================================================================
// ExecutorHandle (the thin seam for external producers)
// ============================================================================

/// Handle for external producers (I/O threads, API callers).
///
/// This is the seam between I/O and CPU engines: I/O completion handlers
/// enqueue CPU work via this handle without knowing executor internals.
///
/// # Thread Safety
///
/// `Clone` and `Send + Sync`. Multiple producers can call `spawn` concurrently.
pub struct ExecutorHandle<T> {
    shared: Arc<Shared<T>>,
}

// Manual Clone impl to avoid requiring T: Clone
impl<T> Clone for ExecutorHandle<T> {
    fn clone(&self) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
        }
    }
}

impl<T: Send + 'static> ExecutorHandle<T> {
    /// Spawn a task from outside the worker threads.
    ///
    /// # Errors
    ///
    /// Returns `Err(task)` if the executor is shutting down (i.e., `join()` has
    /// been called). The task is returned so the caller can handle it.
    ///
    /// # Correctness
    ///
    /// Uses CAS to atomically check accepting + increment count, eliminating
    /// the TOCTOU race between spawn and join. See [`ACCEPTING_BIT`] for details.
    ///
    /// # Performance
    ///
    /// | Aspect | Cost |
    /// |--------|------|
    /// | CAS loop | 1-3 iterations typical (contention-dependent) |
    /// | Injector push | O(1) amortized (Crossbeam MPMC) |
    /// | Unpark | 1 Condvar notify (pthread on POSIX) |
    ///
    /// For high-frequency external spawns, consider batching to amortize
    /// the per-spawn syscall overhead.
    #[inline]
    pub fn spawn(&self, task: T) -> Result<(), T> {
        // CAS loop: atomically check accepting AND increment count
        let mut s = self.shared.state.load(Ordering::Acquire);
        loop {
            if !is_accepting(s) {
                return Err(task);
            }
            // Try to increment count (add 2 because count is in bits 1+)
            match self.shared.state.compare_exchange_weak(
                s,
                s.wrapping_add(COUNT_UNIT),
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(actual) => s = actual,
            }
        }

        self.shared.injector.push(task);
        self.shared.unpark_one();
        Ok(())
    }

    /// Spawn a batch of tasks from outside the worker threads.
    ///
    /// This amortizes the CAS loop and unpark overhead across many tasks.
    /// The batch is all-or-nothing: if the executor is not accepting,
    /// the original `tasks` are returned unchanged.
    ///
    /// # Guarantees
    ///
    /// - Either all tasks are accepted and enqueued, or none are.
    /// - Wakeups are bounded to at most the number of workers.
    ///
    /// # Errors
    ///
    /// Returns `Err(tasks)` if the executor is shutting down or if the
    /// in-flight task count would overflow.
    #[inline]
    pub fn spawn_batch(&self, tasks: Vec<T>) -> Result<(), Vec<T>> {
        if tasks.is_empty() {
            return Ok(());
        }
        let task_count = tasks.len();
        let add = match task_count.checked_mul(COUNT_UNIT) {
            Some(v) => v,
            None => return Err(tasks),
        };

        let mut s = self.shared.state.load(Ordering::Acquire);
        loop {
            if !is_accepting(s) {
                return Err(tasks);
            }
            match self.shared.state.compare_exchange_weak(
                s,
                s.wrapping_add(add),
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(actual) => s = actual,
            }
        }

        for task in tasks {
            self.shared.injector.push(task);
        }

        self.shared.unpark_n(task_count);
        Ok(())
    }

    /// Check if the executor is still accepting external work.
    #[inline]
    pub fn is_accepting(&self) -> bool {
        is_accepting(self.shared.state.load(Ordering::Acquire))
    }

    /// Cooperatively stop workers and reject future external spawns.
    ///
    /// This is an abandonment signal (for example on lease loss), not a
    /// graceful drain request. In-flight tasks may be dropped.
    #[inline]
    pub fn shutdown(&self) {
        close_gate(&self.shared.state);
        self.shared.initiate_done();
    }
}

// ============================================================================
// Shared state
// ============================================================================

/// Combined executor state: `(in_flight_count << 1) | accepting_bit`
///
/// # Problem: TOCTOU Race in Spawn/Join
///
/// A naive implementation might use separate atomics for "accepting" and "count":
/// ```text
/// // BROKEN: Race between steps 1 and 2
/// if accepting.load() {          // (1) check
///     count.fetch_add(1);        // (2) increment
///     // Another thread calls join() between (1) and (2)
///     // → Task spawned after join "closed the gate"
/// }
/// ```
///
/// # Solution: Combined Atomic State
///
/// ```text
/// State = (in_flight_count << 1) | accepting_bit
///
///        63                              1   0
///       ┌─────────────────────────────┬─────┐
///       │      in_flight_count        │ A   │
///       └─────────────────────────────┴─────┘
///                                       │
///                                       └── accepting bit (1=open, 0=closed)
/// ```
///
/// # State Transitions
///
/// ```text
///                      ┌─────────────────────────────────────────┐
///                      │                                         │
///                      ▼                                         │
///  init ──► state=0x01 ──────────────────────────────────────────┤
///           (accepting, count=0)                                 │
///                │                                               │
///                │ external spawn                                │
///                │ CAS: if accepting, count++                    │
///                ▼                                               │
///           state=0x03 ────────► ... ────────► state=(2n+1)      │
///           (accepting, count=1)               (accepting, n)    │
///                │                                  │            │
///                │ completion                       │ join()     │
///                │ fetch_sub(2)                     │ fetch_and(!1)
///                ▼                                  ▼            │
///           state=0x01 ◄──────────────────── state=2n            │
///           (accepting, count=0)             (closed, count=n)   │
///                │                                  │            │
///                │ join() when count=0             │ completions
///                ▼                                  ▼            │
///           state=0x00 ◄──────────────────── state=0x00          │
///           (closed, count=0)                (closed, count=0)   │
///                │                                               │
///                └───────────────────────────────────────────────┘
///                  initiate_done() → workers exit
/// ```
///
/// # Operations
///
/// | Operation | Atomic | Effect |
/// |-----------|--------|--------|
/// | init | store | `state = 1` (accepting, count=0) |
/// | external spawn | CAS loop | if accepting: count++ |
/// | internal spawn | `fetch_add(2)` | count++ (workers only run when open) |
/// | completion | `fetch_sub(2)` | count--; if result==0 && !accepting: done |
/// | join/close | `fetch_and(!1)` | clear accepting bit |
/// Shared state between all workers and the executor owner.
///
/// # Ownership Model
///
/// ```text
///   Executor                          Worker threads
///      │                                    │
///      │    Arc<Shared<T>>                 │
///      └────────┬───────────────────────────┘
///               │
///               ▼
///         ┌───────────────────────────────────────────────┐
///         │                  Shared<T>                    │
///         │                                               │
///         │  injector: Injector<T>    ◄── external spawn  │
///         │  stealers: Vec<Stealer>   ◄── cross-worker    │
///         │  state: AtomicUsize       ◄── spawn/join sync │
///         │  done: AtomicBool         ◄── shutdown signal │
///         │  unparkers: Vec<Unparker> ◄── wakeup handles  │
///         │  next_unpark: AtomicUsize ◄── round-robin idx │
///         │  panic: Mutex<Option<..>> ◄── error capture   │
///         └───────────────────────────────────────────────┘
/// ```
///
/// # Invariants
///
/// - `stealers.len() == unparkers.len() == config.workers`
/// - `state` encodes both accepting flag and in-flight count (see `ACCEPTING_BIT`)
/// - `done` is monotonic: once set to true, never cleared
/// - `panic` captures only the first panic; subsequent panics are discarded
struct Shared<T> {
    /// Global injector queue for external submissions.
    ///
    /// MPMC queue: any thread can push, workers batch-steal via `steal_batch_and_pop`.
    injector: Injector<T>,

    /// Stealers for each worker's local queue.
    ///
    /// `stealers[i]` steals from worker `i`'s local deque (FIFO steal order).
    /// Workers use randomized victim selection to reduce correlated contention.
    stealers: Vec<Stealer<T>>,

    /// Combined state: `(in_flight << 1) | accepting`
    ///
    /// This single atomic eliminates the shutdown race between spawn and join.
    /// See [`ACCEPTING_BIT`] for the encoding and state transition diagram.
    state: AtomicUsize,

    /// Stop flag. Once true, workers exit their main loop.
    ///
    /// Set by:
    /// - `initiate_done()` when count reaches 0 after gate closes
    /// - `record_panic()` on first worker panic
    done: AtomicBool,

    /// Unparkers for each worker.
    ///
    /// Used by `unpark_one()` (round-robin) and `unpark_all()` (shutdown).
    unparkers: Vec<Unparker>,

    /// Round-robin counter for wakeups.
    ///
    /// Distributes wakeup load across workers. Relaxed ordering is fine—
    /// we don't need precise round-robin, just approximate fairness.
    next_unpark: AtomicUsize,

    /// First panic captured from any worker.
    ///
    /// Only the first panic is stored; this simplifies error handling and
    /// ensures `join()` propagates a deterministic panic.
    panic: Mutex<Option<Box<dyn Any + Send + 'static>>>,
}

impl<T> Shared<T> {
    /// Wake one worker (round-robin).
    fn unpark_one(&self) {
        let n = self.unparkers.len();
        if n == 0 {
            return;
        }
        let raw = self.next_unpark.fetch_add(1, Ordering::Relaxed);
        // Use bitmask for power-of-2 worker counts (AND vs udiv+msub on ARM).
        let idx = if n.is_power_of_two() {
            raw & (n - 1)
        } else {
            raw % n
        };
        self.unparkers[idx].unpark();
    }

    /// Wake all workers.
    fn unpark_all(&self) {
        for u in &self.unparkers {
            u.unpark();
        }
    }

    /// Wake up to `n` workers (round-robin).
    fn unpark_n(&self, n: usize) {
        if n == 0 {
            return;
        }
        let workers = self.unparkers.len();
        if workers == 0 {
            return;
        }
        if n >= workers {
            self.unpark_all();
            return;
        }
        for _ in 0..n {
            self.unpark_one();
        }
    }

    /// Signal all workers to stop.
    fn initiate_done(&self) {
        self.done.store(true, Ordering::Release);
        self.unpark_all();
    }

    /// Record a panic and signal shutdown.
    fn record_panic(&self, p: Box<dyn Any + Send + 'static>) {
        let mut guard = self.panic.lock().expect("panic mutex poisoned");
        if guard.is_none() {
            *guard = Some(p);
        }
        self.initiate_done();
    }
}

// ============================================================================
// WorkerCtx (per-worker context passed to every task)
// ============================================================================

/// Per-worker context passed to every task execution.
///
/// # Overview
///
/// ```text
///     WorkerCtx<T, S>
///     ┌──────────────────────────────────────────────────────────────┐
///     │                                                              │
///     │  ┌─────────────────────┐    ┌────────────────────────────┐  │
///     │  │  User-Facing        │    │  Internal                  │  │
///     │  │                     │    │                            │  │
///     │  │  worker_id: usize   │    │  local: Worker<T>  (deque) │  │
///     │  │  scratch: S         │    │  parker: Parker            │  │
///     │  │  rng: XorShift64    │    │  shared: Arc<Shared<T>>    │  │
///     │  │  metrics: Local     │    │                            │  │
///     │  │                     │    │                            │  │
///     │  └─────────────────────┘    └────────────────────────────┘  │
///     │                                                              │
///     │  Methods:                                                    │
///     │    spawn_local()   - enqueue to own deque (fast)            │
///     │    spawn_global()  - enqueue to injector (slower)           │
///     │    handle()        - get ExecutorHandle for external use    │
///     │                                                              │
///     └──────────────────────────────────────────────────────────────┘
/// ```
///
/// # Typical Scratch Contents
///
/// - Scanner scratch buffers (regex match state, decode buffers)
/// - Per-worker memory pools (avoid global allocator contention)
/// - Thread-local caches (compiled regexes, lookup tables)
///
/// # Type Parameters
///
/// - `T`: Task type. Should be small (≤32 bytes) and `Copy` if possible.
/// - `S`: User-defined scratch type, initialized via `scratch_init`
pub struct WorkerCtx<T, S> {
    /// Worker ID (0..workers).
    pub worker_id: usize,
    /// User-defined per-worker scratch space.
    pub scratch: S,

    /// Per-worker RNG for randomized stealing.
    pub rng: XorShift64,
    /// Per-worker metrics (no cross-thread contention).
    pub metrics: WorkerMetricsLocal,

    local: Worker<T>,
    parker: Parker,
    shared: Arc<Shared<T>>,

    /// Counter for wake-on-hoard heuristic.
    /// Reset to 0 after waking a sibling.
    local_spawns_since_wake: u32,
}

impl<T: Send + 'static, S> WorkerCtx<T, S> {
    /// Spawn a task locally (preferred).
    ///
    /// Task goes to this worker's local queue. Other workers can steal it,
    /// but the local worker tries it first. Maximizes cache locality.
    ///
    /// # Performance
    ///
    /// Workers don't need CAS because they only run while executor is live.
    /// Single fetch_add on combined state. Occasionally wakes a sibling
    /// if we're hoarding too much work (wake-on-hoard optimization).
    #[inline]
    pub fn spawn_local(&mut self, task: T) {
        // Workers don't need to check accepting - they only run when executor is live
        increment_count(&self.shared.state);
        perf_stats::sat_add_u64(&mut self.metrics.tasks_enqueued, 1);
        self.local.push(task);

        // Wake-on-hoard: if we've spawned many tasks locally, wake a sibling
        // to help with stealing. This prevents one worker from hoarding work
        // while others sleep.
        self.local_spawns_since_wake += 1;
        if self.local_spawns_since_wake >= WAKE_ON_HOARD_THRESHOLD {
            self.local_spawns_since_wake = 0;
            self.shared.unpark_one();
        }
    }

    /// Spawn a task globally (use sparingly).
    ///
    /// Task goes to the global injector, visible to all workers immediately.
    /// Use for initial work distribution or explicit load balancing.
    ///
    /// # Performance
    ///
    /// Higher contention than local spawn. Includes an unpark call.
    #[inline]
    pub fn spawn_global(&mut self, task: T) {
        increment_count(&self.shared.state);
        perf_stats::sat_add_u64(&mut self.metrics.tasks_enqueued, 1);
        self.shared.injector.push(task);
        self.shared.unpark_one();
    }

    /// Get an external handle for spawning from outside workers.
    #[inline]
    pub fn handle(&self) -> ExecutorHandle<T> {
        ExecutorHandle {
            shared: Arc::clone(&self.shared),
        }
    }
}

// Bridges production `WorkerCtx` to the core step engine. This preserves
// all scheduling semantics: local LIFO, batch injector steals, FIFO victim steals,
// and accurate steal metrics.
impl<T, S> WorkerCtxLike<T, S> for WorkerCtx<T, S> {
    fn worker_id(&self) -> usize {
        self.worker_id
    }

    fn worker_count(&self) -> usize {
        self.shared.stealers.len()
    }

    fn scratch_mut(&mut self) -> &mut S {
        &mut self.scratch
    }

    fn pop_local(&mut self) -> Option<T> {
        self.local.pop()
    }

    fn push_local(&mut self, task: T) {
        self.local.push(task);
    }

    fn push_injector(&mut self, task: T) {
        self.shared.injector.push(task);
    }

    fn steal_from_injector(&mut self) -> Option<T> {
        match self.shared.injector.steal_batch_and_pop(&self.local) {
            Steal::Success(t) => Some(t),
            Steal::Retry | Steal::Empty => None,
        }
    }

    fn steal_from_victim(&mut self, victim: usize) -> Option<T> {
        match self.shared.stealers[victim].steal() {
            Steal::Success(t) => Some(t),
            Steal::Retry | Steal::Empty => None,
        }
    }

    fn shared_state_load(&self) -> usize {
        self.shared.state.load(Ordering::Acquire)
    }

    fn shared_state_fetch_sub(&mut self, delta: usize) -> usize {
        self.shared.state.fetch_sub(delta, Ordering::AcqRel)
    }

    fn shared_state_close_gate(&mut self) -> usize {
        close_gate(&self.shared.state)
    }

    fn shared_state_increment(&mut self) -> Result<(), ()> {
        let mut s = self.shared.state.load(Ordering::Acquire);
        loop {
            if !is_accepting(s) {
                return Err(());
            }
            match self.shared.state.compare_exchange_weak(
                s,
                s.wrapping_add(COUNT_UNIT),
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(()),
                Err(actual) => s = actual,
            }
        }
    }

    fn initiate_done(&mut self) {
        self.shared.initiate_done();
    }

    fn done_flag(&self) -> bool {
        self.shared.done.load(Ordering::Acquire)
    }

    fn unpark_one(&mut self) {
        self.shared.unpark_one();
    }

    fn unpark_all(&mut self) {
        self.shared.unpark_all();
    }

    fn record_panic(&mut self, payload: Box<dyn Any + Send + 'static>) {
        self.shared.record_panic(payload);
    }

    fn rng_next_usize(&mut self, upper: usize) -> usize {
        self.rng.next_usize(upper)
    }

    fn record_steal_attempt(&mut self) {
        perf_stats::sat_add_u64(&mut self.metrics.steal_attempts, 1);
    }

    fn record_steal_success(&mut self) {
        perf_stats::sat_add_u64(&mut self.metrics.steal_successes, 1);
    }
}

// ============================================================================
// Executor
// ============================================================================

/// Work-stealing executor.
///
/// # Type Parameters
///
/// - `T`: Task type. Should be small (≤32 bytes) and `Copy` if possible.
///   Avoid `Box<dyn FnOnce()>` - use an enum instead.
///
/// # Lifecycle
///
/// 1. Create with `Executor::new(config, scratch_init, runner)`
/// 2. Spawn initial work via `spawn_external()` or get a handle
/// 3. Call `join()` to wait for completion and get metrics
///
/// # Example
///
/// ```ignore
/// #[derive(Clone, Copy)]
/// enum Task { Scan(u32), Done }
///
/// let ex = Executor::<Task>::new(
///     config,
///     |worker_id| ScannerScratch::new(),
///     |task, ctx| match task {
///         Task::Scan(id) => { /* scan */ ctx.spawn_local(Task::Done); }
///         Task::Done => {}
///     },
/// );
/// ex.spawn_external(Task::Scan(0))?;
/// let metrics = ex.join();
/// ```
pub struct Executor<T> {
    shared: Arc<Shared<T>>,
    /// Worker thread handles indexed by worker ID.
    ///
    /// Joined in reverse order during `join()` to collect per-worker metrics.
    /// The first panic encountered is captured and re-thrown after all threads
    /// have been joined.
    threads: Vec<JoinHandle<WorkerMetricsLocal>>,
}

impl<T: Send + 'static> Executor<T> {
    /// Get an external handle for spawning.
    pub fn handle(&self) -> ExecutorHandle<T> {
        ExecutorHandle {
            shared: Arc::clone(&self.shared),
        }
    }

    /// Create and start the executor.
    ///
    /// # Parameters
    ///
    /// - `cfg`: Executor configuration
    /// - `scratch_init`: Called once per worker to create scratch space
    /// - `runner`: Called for each task to execute it
    ///
    /// Workers start immediately and idle (spin, then park) until work is spawned.
    pub fn new<S, ScratchInit, Runner>(
        cfg: ExecutorConfig,
        scratch_init: ScratchInit,
        runner: Runner,
    ) -> Self
    where
        S: 'static,
        ScratchInit: Fn(usize) -> S + Send + Sync + 'static,
        Runner: Fn(T, &mut WorkerCtx<T, S>) + Send + Sync + 'static,
    {
        cfg.validate();

        let injector = Injector::new();

        // Build per-worker Chase-Lev deques
        let mut locals = Vec::with_capacity(cfg.workers);
        let mut stealers = Vec::with_capacity(cfg.workers);
        for _ in 0..cfg.workers {
            let w = Worker::new_lifo();
            stealers.push(w.stealer());
            locals.push(w);
        }

        // Build Parker/Unparker pairs
        let mut parkers = Vec::with_capacity(cfg.workers);
        let mut unparkers = Vec::with_capacity(cfg.workers);
        for _ in 0..cfg.workers {
            let p = Parker::new();
            unparkers.push(p.unparker().clone());
            parkers.push(p);
        }

        let shared = Arc::new(Shared {
            injector,
            stealers,
            // Initial state: accepting=1, count=0
            state: AtomicUsize::new(ACCEPTING_BIT),
            done: AtomicBool::new(false),
            unparkers,
            next_unpark: AtomicUsize::new(0),
            panic: Mutex::new(None),
        });

        let runner = Arc::new(runner);
        let scratch_init = Arc::new(scratch_init);

        // Create core assigner for thread pinning (Linux only; None elsewhere).
        let core_assigner = if cfg.pin_threads {
            super::affinity::CoreAssigner::new().map(Arc::new)
        } else {
            None
        };

        let mut threads = Vec::with_capacity(cfg.workers);

        // Spawn workers in reverse so pop() gives correct worker_id
        for worker_id in (0..cfg.workers).rev() {
            let shared = Arc::clone(&shared);
            let runner = Arc::clone(&runner);
            let scratch_init = Arc::clone(&scratch_init);
            let local = locals.pop().expect("locals length mismatch");
            let parker = parkers.pop().expect("parkers length mismatch");
            let thread_cfg = cfg;
            let core_assigner_clone = core_assigner.clone();

            let th = thread::Builder::new()
                .name(format!("scanner-worker-{worker_id}"))
                .spawn(move || {
                    if let Some(ref assigner) = core_assigner_clone {
                        assigner.pin_current_thread();
                    }

                    let scratch = (scratch_init)(worker_id);
                    let rng_seed =
                        thread_cfg.seed ^ (worker_id as u64).wrapping_mul(0x9E3779B97F4A7C15);

                    let mut ctx = WorkerCtx {
                        worker_id,
                        scratch,
                        rng: XorShift64::new(rng_seed),
                        metrics: WorkerMetricsLocal::default(),
                        local,
                        parker,
                        shared,
                        local_spawns_since_wake: 0,
                    };

                    worker_loop(thread_cfg, &runner, &mut ctx);
                    ctx.metrics
                })
                .expect("failed to spawn worker thread");

            threads.push(th);
        }

        // Reverse so threads[0] is worker 0
        threads.reverse();

        Self { shared, threads }
    }

    /// Spawn a task from outside worker threads.
    ///
    /// Convenience for `self.handle().spawn(task)`.
    pub fn spawn_external(&self, task: T) -> Result<(), T> {
        self.handle().spawn(task)
    }

    /// Spawn a batch of tasks from outside worker threads.
    ///
    /// Convenience for `self.handle().spawn_batch(tasks)`.
    /// Prefer this when discovery can amortize wakeups across many tasks.
    pub fn spawn_external_batch(&self, tasks: Vec<T>) -> Result<(), Vec<T>> {
        self.handle().spawn_batch(tasks)
    }

    /// Cooperatively stop workers and reject future external spawns.
    ///
    /// This is equivalent to `self.handle().shutdown()`.
    pub fn shutdown(&self) {
        self.handle().shutdown();
    }

    /// Stop accepting external spawns and wait for all work to complete.
    ///
    /// Returns aggregated metrics from all workers.
    ///
    /// # Panics
    ///
    /// If any worker panicked, this re-panics on the calling thread.
    pub fn join(mut self) -> super::metrics::MetricsSnapshot {
        // Atomically close the gate (clear accepting bit)
        // This prevents new external spawns while we wait
        let prev_state = close_gate(&self.shared.state);

        // If count was already 0 when we closed, we're done
        if in_flight(prev_state) == 0 {
            self.shared.initiate_done();
        }

        let mut snapshot = super::metrics::MetricsSnapshot::default();

        while let Some(th) = self.threads.pop() {
            let m = th.join().unwrap_or_else(|p| {
                self.shared.record_panic(p);
                WorkerMetricsLocal::default()
            });
            snapshot.merge_worker(&m);
        }

        // Re-throw captured panic
        if let Some(p) = self
            .shared
            .panic
            .lock()
            .expect("panic mutex poisoned")
            .take()
        {
            std::panic::resume_unwind(p);
        }

        snapshot
    }
}

// ============================================================================
// Worker loop
// ============================================================================

/// Main worker loop.
///
/// # Algorithm
///
/// ```text
///                         ┌─────────────┐
///                         │  Start      │
///                         └──────┬──────┘
///                                │
///                                ▼
///                         ┌─────────────┐
///                    ┌────│ done flag?  │────┐
///                    │yes └─────────────┘ no │
///                    │                       │
///                    ▼                       ▼
///              ┌─────────┐           ┌─────────────┐
///              │  Exit   │           │  pop_task() │
///              └─────────┘           └──────┬──────┘
///                                           │
///                    ┌──────────────────────┼──────────────────────┐
///                    │ Some(task)           │ None                 │
///                    ▼                       ▼                      │
///             ┌─────────────┐        ┌─────────────┐               │
///             │ Execute     │        │ Check state │               │
///             │ runner(task)│        │ count==0 && │               │
///             └──────┬──────┘        │ !accepting? │               │
///                    │               └──────┬──────┘               │
///                    ▼                      │                       │
///             ┌─────────────┐        ┌──────┴──────┐               │
///             │ Decrement   │        │ yes      no │               │
///             │ in_flight   │        ▼             ▼               │
///             └──────┬──────┘   ┌─────────┐  ┌─────────────┐       │
///                    │          │ Done!   │  │ Tiered idle │       │
///                    │          │ Signal  │  │ spin→yield→ │       │
///                    │          │ shutdown│  │ park        │       │
///                    │          └─────────┘  └──────┬──────┘       │
///                    │                              │               │
///                    └──────────────────────────────┴───────────────┘
///                                      │
///                                      ▼
///                               (loop continues)
/// ```
///
/// # Tiered Idle Strategy
///
/// When no work is found, workers use a graduated backoff:
///
/// 1. **Spin** (`idle_rounds <= spin_iters`): CPU-bound spinning with `spin_loop()` hint.
///    Best for bursty workloads where work arrives within nanoseconds.
///
/// 2. **Park** (after spin threshold): `park_timeout()` sleeps until unparked or timeout.
///    Minimizes CPU waste during idle periods while remaining responsive.
///    Every 16th iteration past the spin threshold, `thread::yield_now()` is
///    called before parking to give other threads a chance.
///
/// # Complexity
///
/// - **Per-iteration**: O(steal_tries) worst case (randomized victim selection)
/// - **Termination**: O(1) check via combined atomic state
///
/// # Implementation Note
///
/// The loop delegates to [`worker_step`] to keep production and simulation
/// policy logic in lockstep. The step engine also owns the in-flight counter
/// decrement (including panic paths), so production must not duplicate that
/// accounting.
fn worker_loop<T, S, RunnerFn>(
    cfg: ExecutorConfig,
    runner: &Arc<RunnerFn>,
    ctx: &mut WorkerCtx<T, S>,
) where
    T: Send + 'static,
    RunnerFn: Fn(T, &mut WorkerCtx<T, S>) + Send + Sync + 'static,
{
    let mut idle = TieredIdle::new();
    let mut trace = NoopTrace;
    let mut run = |task: T, ctx: &mut WorkerCtx<T, S>| (runner)(task, ctx);

    loop {
        match worker_step(&cfg, &mut run, ctx, &mut idle, &mut trace) {
            WorkerStepResult::RanTask { .. } => {
                perf_stats::sat_add_u64(&mut ctx.metrics.tasks_executed, 1);
            }
            WorkerStepResult::NoWork => {
                ctx.metrics.idle_spins = ctx.metrics.idle_spins.saturating_add(1);
            }
            WorkerStepResult::ShouldPark { timeout } => {
                ctx.metrics.park_count = ctx.metrics.park_count.saturating_add(1);
                ctx.parker.park_timeout(timeout);
            }
            WorkerStepResult::ExitDone | WorkerStepResult::ExitPanicked => break,
        }
    }

    // Copy yield count from TieredIdle into worker metrics for reporting.
    ctx.metrics.yield_count = ctx.metrics.yield_count.saturating_add(idle.yield_count);
}

/// Tiered idle strategy used by the production worker loop.
///
/// The policy matches the previous inline behavior: spin → occasional yield →
/// park with timeout.
struct TieredIdle {
    idle_rounds: u32,
    yield_count: u64,
}

impl TieredIdle {
    fn new() -> Self {
        Self {
            idle_rounds: 0,
            yield_count: 0,
        }
    }
}

impl IdleHooks for TieredIdle {
    fn on_work(&mut self) {
        self.idle_rounds = 0;
    }

    fn on_idle(&mut self, cfg: &ExecutorConfig) -> IdleAction {
        self.idle_rounds = self.idle_rounds.saturating_add(1);

        if self.idle_rounds <= cfg.spin_iters {
            std::hint::spin_loop();
            return IdleAction::Continue;
        }

        // Yield every 16th iteration past the spin threshold.
        // 16 is a heuristic: frequent enough to avoid monopolising the core,
        // rare enough that the yield syscall doesn't dominate idle cost.
        if (self.idle_rounds & 0xF) == 0 {
            self.yield_count = self.yield_count.saturating_add(1);
            thread::yield_now();
        }

        IdleAction::Park {
            timeout: cfg.park_timeout,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    fn test_config(workers: usize) -> ExecutorConfig {
        ExecutorConfig {
            workers,
            seed: 12345,
            steal_tries: 4,
            spin_iters: 100,
            park_timeout: Duration::from_micros(100),
            pin_threads: false,
        }
    }

    fn assert_perf_metric_u64(actual: u64, expected: u64) {
        if cfg!(all(feature = "perf-stats", debug_assertions)) {
            assert_eq!(actual, expected);
        } else {
            assert_eq!(actual, 0);
        }
    }

    #[test]
    fn executor_runs_all_external_tasks() {
        let counter = Arc::new(AtomicUsize::new(0));
        let c2 = Arc::clone(&counter);

        let ex = Executor::<usize>::new(
            test_config(4),
            |_wid| (),
            move |_task, _ctx| {
                c2.fetch_add(1, Ordering::Relaxed);
            },
        );

        let n = 10_000usize;
        for i in 0..n {
            ex.spawn_external(i).unwrap();
        }

        let metrics = ex.join();
        assert_eq!(counter.load(Ordering::Relaxed), n);
        assert_perf_metric_u64(metrics.tasks_executed, n as u64);
    }

    #[test]
    fn executor_runs_all_external_tasks_batch() {
        let counter = Arc::new(AtomicUsize::new(0));
        let c2 = Arc::clone(&counter);

        let ex = Executor::<usize>::new(
            test_config(4),
            |_wid| (),
            move |_task, _ctx| {
                c2.fetch_add(1, Ordering::Relaxed);
            },
        );

        let n = 10_000usize;
        let tasks: Vec<usize> = (0..n).collect();
        ex.spawn_external_batch(tasks).unwrap();

        let metrics = ex.join();
        assert_eq!(counter.load(Ordering::Relaxed), n);
        assert_perf_metric_u64(metrics.tasks_executed, n as u64);
    }

    #[test]
    fn tasks_can_spawn_more_tasks_locally() {
        let counter = Arc::new(AtomicUsize::new(0));
        let c2 = Arc::clone(&counter);

        #[derive(Clone, Copy, Debug)]
        enum Task {
            Root(u32),
            Child,
        }

        let ex = Executor::<Task>::new(
            test_config(4),
            |_wid| (),
            move |task, ctx| match task {
                Task::Root(n) => {
                    c2.fetch_add(1, Ordering::Relaxed);
                    for _ in 0..n {
                        ctx.spawn_local(Task::Child);
                    }
                }
                Task::Child => {
                    c2.fetch_add(1, Ordering::Relaxed);
                }
            },
        );

        ex.spawn_external(Task::Root(10_000)).unwrap();
        let metrics = ex.join();

        // 1 root + 10_000 children
        assert_eq!(counter.load(Ordering::Relaxed), 10_001);
        assert_perf_metric_u64(metrics.tasks_executed, 10_001);
    }

    #[test]
    fn join_without_tasks_returns_immediately() {
        let ex = Executor::<()>::new(test_config(2), |_wid| (), |_t, _ctx| {});
        let metrics = ex.join();
        assert_eq!(metrics.tasks_executed, 0);
    }

    #[test]
    fn shutdown_rejects_future_spawns() {
        let ex = Executor::<u32>::new(test_config(2), |_wid| (), |_task, _ctx| {});
        let handle = ex.handle();
        handle.shutdown();

        assert!(handle.spawn(1).is_err());
        let metrics = ex.join();
        assert_eq!(metrics.tasks_executed, 0);
    }

    #[test]
    fn spawn_after_join_fails() {
        let ex = Executor::<u32>::new(test_config(2), |_wid| (), |_t, _ctx| {});
        let handle = ex.handle();
        let _metrics = ex.join();

        // Handle should reject spawns after join
        assert!(handle.spawn(42).is_err());
        let tasks = vec![1u32, 2, 3];
        let err = handle
            .spawn_batch(tasks)
            .expect_err("spawn_batch should fail after join");
        assert_eq!(err, vec![1u32, 2, 3]);
    }

    #[test]
    fn deterministic_with_same_seed_single_worker() {
        // Single worker for true determinism
        let cfg = ExecutorConfig {
            workers: 1,
            seed: 99999,
            ..test_config(1)
        };

        let results1 = Arc::new(Mutex::new(Vec::new()));
        let r1 = Arc::clone(&results1);

        let ex = Executor::<u32>::new(
            cfg,
            |_| (),
            move |task, _ctx| {
                r1.lock().unwrap().push(task);
            },
        );

        for i in 0..100u32 {
            ex.spawn_external(i).unwrap();
        }
        let _ = ex.join();

        let results2 = Arc::new(Mutex::new(Vec::new()));
        let r2 = Arc::clone(&results2);

        let ex = Executor::<u32>::new(
            cfg,
            |_| (),
            move |task, _ctx| {
                r2.lock().unwrap().push(task);
            },
        );

        for i in 0..100u32 {
            ex.spawn_external(i).unwrap();
        }
        let _ = ex.join();

        // Same seed + single worker = same execution order
        assert_eq!(*results1.lock().unwrap(), *results2.lock().unwrap());
    }

    #[test]
    fn scratch_space_per_worker() {
        let worker_ids = Arc::new(Mutex::new(Vec::new()));
        let w = Arc::clone(&worker_ids);

        let ex = Executor::<()>::new(
            test_config(4),
            |wid| wid, // scratch = worker_id
            move |_, ctx| {
                w.lock().unwrap().push(ctx.scratch);
            },
        );

        // Spawn one task per worker (roughly)
        for _ in 0..4 {
            ex.spawn_external(()).unwrap();
        }

        let _ = ex.join();

        let ids = worker_ids.lock().unwrap();
        // All worker IDs should be in 0..4
        for &id in ids.iter() {
            assert!(id < 4, "worker_id {} out of range", id);
        }
    }

    #[test]
    fn metrics_track_steals() {
        // Force stealing with high fanout on few workers
        let ex = Executor::<u32>::new(
            test_config(4),
            |_wid| (),
            |_t, _ctx| {
                // Small task body
                std::hint::black_box(42);
            },
        );

        for i in 0..1000u32 {
            ex.spawn_external(i).unwrap();
        }

        let metrics = ex.join();
        assert_perf_metric_u64(metrics.tasks_executed, 1000);
        // With 4 workers and 1000 tasks, there should be some stealing
        // (not guaranteed, but highly likely)
    }

    /// Stress test: concurrent spawn + join must not lose tasks.
    ///
    /// This test validates that the combined atomic state correctly prevents
    /// the TOCTOU race between external spawn and join.
    #[test]
    fn concurrent_spawn_and_join_no_task_loss() {
        use std::thread;

        for iteration in 0..100 {
            let counter = Arc::new(AtomicUsize::new(0));
            let c2 = Arc::clone(&counter);

            let ex = Executor::<u32>::new(
                test_config(4),
                |_wid| (),
                move |_task, _ctx| {
                    c2.fetch_add(1, Ordering::Relaxed);
                },
            );

            let handle = ex.handle();
            let spawned = Arc::new(AtomicUsize::new(0));
            let spawned2 = Arc::clone(&spawned);

            // Spawn tasks from another thread while we call join
            let spawn_thread = thread::spawn(move || {
                for i in 0..1000u32 {
                    match handle.spawn(i) {
                        Ok(()) => {
                            spawned2.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(_) => {
                            // Executor closed, stop spawning
                            break;
                        }
                    }
                }
            });

            // Give spawner a head start sometimes
            if iteration % 2 == 0 {
                thread::yield_now();
            }

            let _metrics = ex.join();
            spawn_thread.join().unwrap();

            // CRITICAL INVARIANT: every successfully spawned task must execute
            let total_spawned = spawned.load(Ordering::Relaxed);
            let total_executed = counter.load(Ordering::Relaxed);
            assert_eq!(
                total_executed, total_spawned,
                "iteration {}: spawned {} but executed {}",
                iteration, total_spawned, total_executed
            );
        }
    }

    /// Test that panic in task doesn't corrupt in_flight count.
    #[test]
    fn panic_in_task_decrements_count() {
        use std::panic;

        let counter = Arc::new(AtomicUsize::new(0));
        let c2 = Arc::clone(&counter);

        #[derive(Clone, Copy, Debug)]
        enum Task {
            Normal,
            Panic,
        }

        let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            let ex = Executor::<Task>::new(
                test_config(2),
                |_wid| (),
                move |task, _ctx| match task {
                    Task::Normal => {
                        c2.fetch_add(1, Ordering::Relaxed);
                    }
                    Task::Panic => {
                        panic!("intentional test panic");
                    }
                },
            );

            // Spawn some normal tasks, then a panic
            for _ in 0..10 {
                ex.spawn_external(Task::Normal).unwrap();
            }
            ex.spawn_external(Task::Panic).unwrap();
            for _ in 0..10 {
                ex.spawn_external(Task::Normal).unwrap();
            }

            ex.join()
        }));

        // Should have panicked
        assert!(result.is_err(), "executor should have propagated panic");

        // Some tasks should have executed (at least until panic)
        let executed = counter.load(Ordering::Relaxed);
        assert!(executed > 0, "some tasks should have executed before panic");
    }
}

//! Deterministic single-thread executor for simulation.
//!
//! The executor models a work-stealing scheduler in a single OS thread. Tasks
//! are identified by stable ids and queued in per-worker deques plus a global
//! injector queue.
//!
//! Scheduling invariants:
//! - Local workers pop from the back (LIFO) of their own queues.
//! - Steals pop from the front (FIFO) of victim queues.
//! - Global queue pops from the front (FIFO).
//! - When any task is runnable, every worker is eligible to run and may steal.

use std::collections::VecDeque;

use crate::sim::rng::SimRng;

/// Stable task identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SimTaskId(u32);

impl SimTaskId {
    #[inline(always)]
    pub fn from_u32(id: u32) -> Self {
        Self(id)
    }

    #[inline(always)]
    pub fn index(self) -> usize {
        self.0 as usize
    }
}

/// Stable worker identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WorkerId(u32);

impl WorkerId {
    #[inline(always)]
    pub fn from_u32(id: u32) -> Self {
        Self(id)
    }

    #[inline(always)]
    pub fn index(self) -> usize {
        self.0 as usize
    }
}

/// Minimal task metadata tracked by the executor.
#[derive(Clone, Debug)]
pub struct SimTask {
    /// Opaque task-type tag set by the simulation harness.
    ///
    /// The executor does not interpret this value — it exists so the runner
    /// callback can dispatch based on task type (e.g., `0 = Enumerate`,
    /// `1 = Fetch`, `2 = Scan`).
    pub kind: u16,
}

/// Task state for runner-level invariants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SimTaskState {
    Runnable,
    Blocked,
    Completed,
}

/// Result of a single scheduling step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StepResult {
    Ran {
        worker: WorkerId,
        task_id: SimTaskId,
        decision: StepDecision,
    },
    Idle,
}

/// Deterministic choice metadata for trace logging.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StepDecision {
    /// Total number of workers considered (always `== executor.worker_count()`).
    pub choices: u32,
    /// Index of the worker selected by the RNG (0-based).
    pub chosen: u32,
}

/// Deterministic single-thread executor with work-stealing queues.
///
/// Models a multi-worker work-stealing scheduler within a single OS thread
/// for property testing and simulation. Each [`step()`](Self::step) call
/// selects a worker uniformly at random (via seeded RNG), then that worker
/// pops from its local queue (LIFO), falls back to the global queue (FIFO),
/// or steals from a random victim (FIFO).
///
/// # What This Models
///
/// - Worker-local queue semantics (LIFO pop, FIFO steal)
/// - Global injection queue (FIFO)
/// - Random worker selection and victim selection
///
/// # What This Does NOT Model
///
/// - Real-time scheduling or timing
/// - Cache effects or memory locality
/// - Contention or CAS failures
/// - Thread wake/sleep transitions
///
/// Given the same seed and input sequence, execution is fully deterministic.
pub struct SimExecutor {
    workers: u32,
    next_task_id: u32,
    tasks: Vec<SimTask>,
    states: Vec<SimTaskState>,
    local_queues: Vec<VecDeque<SimTaskId>>,
    global_queue: VecDeque<SimTaskId>,
    rng: SimRng,
}

impl SimExecutor {
    /// Create a new executor with `workers` and a deterministic seed.
    pub fn new(workers: u32, seed: u64) -> Self {
        assert!(workers > 0);
        let mut local_queues = Vec::with_capacity(workers as usize);
        for _ in 0..workers {
            local_queues.push(VecDeque::new());
        }

        Self {
            workers,
            next_task_id: 0,
            tasks: Vec::new(),
            states: Vec::new(),
            local_queues,
            global_queue: VecDeque::new(),
            rng: SimRng::new(seed),
        }
    }

    /// Number of workers modeled by this executor.
    #[inline(always)]
    pub fn worker_count(&self) -> u32 {
        self.workers
    }

    /// Spawn a task from outside the executor (goes to the global queue).
    pub fn spawn_external(&mut self, task: SimTask) -> SimTaskId {
        let id = self.alloc_task(task, SimTaskState::Runnable);
        self.global_queue.push_back(id);
        id
    }

    /// Spawn a task from a worker (goes to that worker's local queue).
    pub fn spawn_local(&mut self, worker: WorkerId, task: SimTask) -> SimTaskId {
        let id = self.alloc_task(task, SimTaskState::Runnable);
        self.enqueue_local(worker, id);
        id
    }

    /// Enqueue an existing task on a worker's local queue.
    pub fn enqueue_local(&mut self, worker: WorkerId, task_id: SimTaskId) {
        self.ensure_worker(worker);
        debug_assert!(self.is_runnable(task_id));
        self.local_queues[worker.index()].push_back(task_id);
    }

    /// Enqueue an existing task onto the global queue.
    pub fn enqueue_global(&mut self, task_id: SimTaskId) {
        debug_assert!(self.is_runnable(task_id));
        self.global_queue.push_back(task_id);
    }

    /// Mark a task as blocked (runner must re-enqueue when ready).
    pub fn mark_blocked(&mut self, task_id: SimTaskId) {
        self.set_state(task_id, SimTaskState::Blocked);
    }

    /// Mark a task as completed.
    pub fn mark_completed(&mut self, task_id: SimTaskId) {
        self.set_state(task_id, SimTaskState::Completed);
    }

    /// Mark a task as runnable (does not enqueue).
    pub fn mark_runnable(&mut self, task_id: SimTaskId) {
        self.set_state(task_id, SimTaskState::Runnable);
    }

    /// Execute a single scheduling step and return the chosen task, if any.
    pub fn step(&mut self) -> StepResult {
        if !self.any_task_queued() {
            return StepResult::Idle;
        }

        let (worker, decision) = self.choose_worker();
        let task_id = self.pop_for_worker(worker);
        debug_assert!(self.is_runnable(task_id));

        StepResult::Ran {
            worker,
            task_id,
            decision,
        }
    }

    /// Immutable access to a task by id.
    pub fn task(&self, task_id: SimTaskId) -> &SimTask {
        &self.tasks[task_id.index()]
    }

    /// Whether any task is currently queued for execution.
    pub fn has_queued_tasks(&self) -> bool {
        self.any_task_queued()
    }

    /// Current state of a task.
    pub fn state(&self, task_id: SimTaskId) -> SimTaskState {
        self.states[task_id.index()]
    }

    /// Remove a task from all queues (local and global).
    pub fn remove_from_queues(&mut self, task_id: SimTaskId) {
        for queue in &mut self.local_queues {
            queue.retain(|t| *t != task_id);
        }
        self.global_queue.retain(|t| *t != task_id);
    }

    fn alloc_task(&mut self, task: SimTask, state: SimTaskState) -> SimTaskId {
        let id = SimTaskId(self.next_task_id);
        self.next_task_id = self.next_task_id.saturating_add(1);
        self.tasks.push(task);
        self.states.push(state);
        id
    }

    fn any_task_queued(&self) -> bool {
        if !self.global_queue.is_empty() {
            return true;
        }
        self.local_queues.iter().any(|q| !q.is_empty())
    }

    fn choose_worker(&mut self) -> (WorkerId, StepDecision) {
        let choices = self.workers;
        let chosen = if choices == 1 {
            0
        } else {
            self.rng.gen_range(0, choices)
        };

        (WorkerId(chosen), StepDecision { choices, chosen })
    }

    fn pop_for_worker(&mut self, worker: WorkerId) -> SimTaskId {
        self.ensure_worker(worker);

        if let Some(id) = self.local_queues[worker.index()].pop_back() {
            return id;
        }

        if let Some(id) = self.global_queue.pop_front() {
            return id;
        }

        let victim = self.choose_victim(worker).expect("runnable task exists");
        self.local_queues[victim.index()]
            .pop_front()
            .expect("victim queue non-empty")
    }

    fn choose_victim(&mut self, worker: WorkerId) -> Option<WorkerId> {
        let mut victims = Vec::new();
        for (idx, queue) in self.local_queues.iter().enumerate() {
            let wid = WorkerId(idx as u32);
            if wid != worker && !queue.is_empty() {
                victims.push(wid);
            }
        }

        if victims.is_empty() {
            return None;
        }

        let chosen = if victims.len() == 1 {
            0
        } else {
            self.rng.gen_range(0, victims.len() as u32) as usize
        };
        Some(victims[chosen])
    }

    fn is_runnable(&self, task_id: SimTaskId) -> bool {
        self.state(task_id) == SimTaskState::Runnable
    }

    fn set_state(&mut self, task_id: SimTaskId, state: SimTaskState) {
        self.states[task_id.index()] = state;
    }

    fn ensure_worker(&self, worker: WorkerId) {
        debug_assert!(worker.0 < self.workers);
    }
}

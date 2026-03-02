//! Deterministic scheduler simulation runner and oracles.
//!
//! The runner interprets task programs over a `SimExecutor` and `SimClock` and
//! checks safety/liveness/fairness invariants on each step.

use std::collections::{BTreeMap, VecDeque};

use serde::{Deserialize, Serialize};

use crate::sim::clock::SimClock;
use crate::sim::executor::{SimExecutor, SimTask, SimTaskId, SimTaskState, StepResult, WorkerId};

use super::program::{Instr, Program};

/// Configuration for the scheduler simulation runner.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SimSchedulerConfig {
    pub workers: u32,
    pub max_steps: u64,
    /// Maximum steps a runnable task may wait before being scheduled.
    pub fairness_bound: u64,
    /// Budget capacities keyed by budget id.
    pub budgets: BTreeMap<u16, u32>,
}

/// Result of a scheduler simulation run.
#[derive(Clone, Debug)]
pub enum RunOutcome {
    Ok,
    Failed(FailureReport),
}

/// Failure details for scheduler simulation runs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FailureReport {
    pub kind: FailureKind,
    pub message: String,
    pub step: u64,
}

/// Failure classification for scheduler simulation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum FailureKind {
    Hang,
    InvariantViolation { code: u32 },
    FairnessViolation,
    ProgramError,
}

#[derive(Clone, Debug)]
struct TaskInstance {
    program_idx: u32,
    pc: usize,
}

pub struct SimSchedulerRunner {
    cfg: SimSchedulerConfig,
    program: Program,
    executor: SimExecutor,
    clock: SimClock,
    tasks: Vec<TaskInstance>,
    runnable_since: BTreeMap<SimTaskId, u64>,
    budget_in_use: BTreeMap<u16, u32>,
    budget_waiters: BTreeMap<u16, VecDeque<SimTaskId>>,
    task_budgets: Vec<BTreeMap<u16, u32>>,
    event_waiters: BTreeMap<u16, VecDeque<SimTaskId>>,
    sleep_waiters: BTreeMap<u64, Vec<SimTaskId>>,
}

impl SimSchedulerRunner {
    pub fn new(program: Program, cfg: SimSchedulerConfig, seed: u64) -> Self {
        let executor = SimExecutor::new(cfg.workers, seed);
        Self {
            cfg,
            program,
            executor,
            clock: SimClock::new(),
            tasks: Vec::new(),
            runnable_since: BTreeMap::new(),
            budget_in_use: BTreeMap::new(),
            budget_waiters: BTreeMap::new(),
            task_budgets: Vec::new(),
            event_waiters: BTreeMap::new(),
            sleep_waiters: BTreeMap::new(),
        }
    }

    /// Execute the program until completion or failure.
    pub fn run(mut self) -> RunOutcome {
        if self.program.tasks.is_empty() {
            return RunOutcome::Ok;
        }

        for idx in 0..self.program.tasks.len() {
            self.spawn_task(idx as u32, None, 0);
        }

        for step in 0..self.cfg.max_steps {
            self.deliver_due_sleepers(step);

            if !self.executor.has_queued_tasks() {
                if let Some(next_tick) = self.next_sleep_tick() {
                    self.clock.advance_to(next_tick);
                    self.deliver_due_sleepers(step);
                } else if self.any_blocked() {
                    return self.fail(
                        FailureKind::Hang,
                        "no runnable tasks and no pending wakeups",
                        step,
                    );
                } else {
                    return RunOutcome::Ok;
                }
            }

            if self.fairness_violation(step) {
                return self.fail(FailureKind::FairnessViolation, "fairness bound", step);
            }

            match self.executor.step() {
                StepResult::Idle => {
                    return self.fail(FailureKind::Hang, "executor idle with runnable tasks", step);
                }
                StepResult::Ran {
                    worker, task_id, ..
                } => {
                    if self.executor.state(task_id) != SimTaskState::Runnable {
                        return self.fail(
                            FailureKind::InvariantViolation { code: 1 },
                            "ran non-runnable task",
                            step,
                        );
                    }
                    if let RunOutcome::Failed(fail) = self.execute_task(step, worker, task_id) {
                        return RunOutcome::Failed(fail);
                    }
                }
            }
        }

        self.fail(FailureKind::Hang, "max steps exceeded", self.cfg.max_steps)
    }

    fn execute_task(&mut self, step: u64, worker: WorkerId, task_id: SimTaskId) -> RunOutcome {
        let idx = task_id.index();
        let (program_idx, pc) = match self.tasks.get(idx) {
            Some(task) => (task.program_idx, task.pc),
            None => {
                return self.fail(
                    FailureKind::InvariantViolation { code: 2 },
                    "unknown task id",
                    step,
                );
            }
        };

        let program = match self.program.tasks.get(program_idx as usize) {
            Some(p) => p,
            None => return self.fail(FailureKind::ProgramError, "invalid program index", step),
        };

        if pc >= program.code.len() {
            return self.fail(FailureKind::ProgramError, "pc out of bounds", step);
        }

        let instr = program.code[pc].clone();
        if let Some(task) = self.tasks.get_mut(idx) {
            task.pc = task.pc.saturating_add(1);
        }

        match instr {
            Instr::Spawn { task_idx } => {
                if (task_idx as usize) >= self.program.tasks.len() {
                    return self.fail(FailureKind::ProgramError, "spawn index out of range", step);
                }
                self.spawn_task(task_idx, Some(worker), step);
                self.reschedule(worker, task_id, step);
            }
            Instr::Yield => {
                self.reschedule(worker, task_id, step);
            }
            Instr::Sleep { ticks } => {
                if ticks == 0 {
                    self.reschedule(worker, task_id, step);
                } else {
                    self.block_task(task_id);
                    let wake_at = self.clock.now_ticks().saturating_add(ticks);
                    self.sleep_waiters.entry(wake_at).or_default().push(task_id);
                }
            }
            Instr::Acquire { budget } => match self.acquire_budget(task_id, budget, step) {
                Ok(true) => self.reschedule(worker, task_id, step),
                Ok(false) => {
                    // Retry the acquire when the task is unblocked.
                    if let Some(task) = self.tasks.get_mut(idx) {
                        task.pc = task.pc.saturating_sub(1);
                    }
                }
                Err(outcome) => return outcome,
            },
            Instr::Release { budget } => {
                if let RunOutcome::Failed(fail) = self.release_budget(task_id, budget, step) {
                    return RunOutcome::Failed(fail);
                }
                self.reschedule(worker, task_id, step);
            }
            Instr::WaitEvent { event } => {
                self.block_task(task_id);
                self.event_waiters
                    .entry(event)
                    .or_default()
                    .push_back(task_id);
            }
            Instr::SignalEvent { event } => {
                if let Some(mut waiters) = self.event_waiters.remove(&event) {
                    while let Some(waiter) = waiters.pop_front() {
                        self.make_runnable(waiter, step, Some(worker));
                    }
                }
                self.reschedule(worker, task_id, step);
            }
            Instr::Cancel { task_idx } => {
                self.cancel_tasks(task_idx, step);
                self.reschedule(worker, task_id, step);
            }
            Instr::Complete => {
                if let Some(held) = self.task_budgets.get(idx) {
                    if !held.is_empty() {
                        return self.fail(
                            FailureKind::InvariantViolation { code: 3 },
                            "task completed with outstanding permits",
                            step,
                        );
                    }
                }
                self.executor.mark_completed(task_id);
                self.runnable_since.remove(&task_id);
            }
        }

        RunOutcome::Ok
    }

    fn spawn_task(&mut self, program_idx: u32, worker: Option<WorkerId>, step: u64) {
        debug_assert!(program_idx <= u16::MAX as u32);
        let id = match worker {
            Some(w) => self.executor.spawn_local(
                w,
                SimTask {
                    kind: program_idx as u16,
                },
            ),
            None => self.executor.spawn_external(SimTask {
                kind: program_idx as u16,
            }),
        };

        if id.index() == self.tasks.len() {
            self.tasks.push(TaskInstance { program_idx, pc: 0 });
            self.task_budgets.push(BTreeMap::new());
        } else if id.index() < self.tasks.len() {
            self.tasks[id.index()] = TaskInstance { program_idx, pc: 0 };
            self.task_budgets[id.index()].clear();
        }

        self.runnable_since.insert(id, step);
    }

    fn reschedule(&mut self, worker: WorkerId, task_id: SimTaskId, step: u64) {
        self.executor.mark_runnable(task_id);
        self.executor.enqueue_local(worker, task_id);
        self.runnable_since.insert(task_id, step);
    }

    fn block_task(&mut self, task_id: SimTaskId) {
        self.executor.mark_blocked(task_id);
        self.runnable_since.remove(&task_id);
    }

    fn make_runnable(&mut self, task_id: SimTaskId, step: u64, worker: Option<WorkerId>) {
        self.executor.mark_runnable(task_id);
        match worker {
            Some(w) => self.executor.enqueue_local(w, task_id),
            None => self.executor.enqueue_global(task_id),
        }
        self.runnable_since.insert(task_id, step);
    }

    fn acquire_budget(
        &mut self,
        task_id: SimTaskId,
        budget: u16,
        step: u64,
    ) -> Result<bool, RunOutcome> {
        let cap = match self.cfg.budgets.get(&budget) {
            Some(cap) => *cap,
            None => {
                return Err(self.fail(FailureKind::ProgramError, "unknown budget id", step));
            }
        };

        let in_use = self.budget_in_use.entry(budget).or_insert(0);
        if *in_use < cap {
            *in_use += 1;
            let entry = self.task_budgets[task_id.index()]
                .entry(budget)
                .or_insert(0);
            *entry += 1;
            Ok(true)
        } else {
            self.block_task(task_id);
            self.budget_waiters
                .entry(budget)
                .or_default()
                .push_back(task_id);
            Ok(false)
        }
    }

    fn release_budget(&mut self, task_id: SimTaskId, budget: u16, step: u64) -> RunOutcome {
        let held = match self.task_budgets.get_mut(task_id.index()) {
            Some(map) => map,
            None => {
                return self.fail(
                    FailureKind::InvariantViolation { code: 4 },
                    "missing task budget map",
                    step,
                );
            }
        };

        let count = match held.get_mut(&budget) {
            Some(c) if *c > 0 => c,
            _ => {
                return self.fail(
                    FailureKind::InvariantViolation { code: 5 },
                    "release without acquire",
                    step,
                );
            }
        };

        *count -= 1;
        if *count == 0 {
            held.remove(&budget);
        }

        let in_use = self.budget_in_use.entry(budget).or_insert(0);
        if *in_use == 0 {
            return self.fail(
                FailureKind::InvariantViolation { code: 6 },
                "budget underflow",
                step,
            );
        }
        *in_use -= 1;

        let (waiter, empty) = if let Some(waiters) = self.budget_waiters.get_mut(&budget) {
            let waiter = waiters.pop_front();
            let empty = waiters.is_empty();
            (waiter, empty)
        } else {
            (None, false)
        };

        if empty {
            self.budget_waiters.remove(&budget);
        }
        if let Some(waiter) = waiter {
            self.make_runnable(waiter, step, None);
        }

        RunOutcome::Ok
    }

    fn cancel_tasks(&mut self, program_idx: u32, step: u64) {
        let to_cancel: Vec<SimTaskId> = self
            .tasks
            .iter()
            .enumerate()
            .filter_map(|(id, task)| {
                if task.program_idx == program_idx {
                    Some(SimTaskId::from_u32(id as u32))
                } else {
                    None
                }
            })
            .collect();

        for task_id in to_cancel {
            self.executor.mark_completed(task_id);
            self.executor.remove_from_queues(task_id);
            self.runnable_since.remove(&task_id);
            self.remove_from_waitlists(task_id);
            self.release_all_budgets(task_id, step);
        }
    }

    fn release_all_budgets(&mut self, task_id: SimTaskId, step: u64) {
        if let Some(held) = self.task_budgets.get_mut(task_id.index()) {
            let held = std::mem::take(held);
            for (budget, count) in held {
                let in_use = self.budget_in_use.entry(budget).or_insert(0);
                if *in_use < count {
                    *in_use = 0;
                } else {
                    *in_use -= count;
                }

                let (waiter, empty) = if let Some(waiters) = self.budget_waiters.get_mut(&budget) {
                    let waiter = waiters.pop_front();
                    let empty = waiters.is_empty();
                    (waiter, empty)
                } else {
                    (None, false)
                };

                if empty {
                    self.budget_waiters.remove(&budget);
                }
                if let Some(waiter) = waiter {
                    self.make_runnable(waiter, step, None);
                }
            }
        }
    }

    fn remove_from_waitlists(&mut self, task_id: SimTaskId) {
        for waiters in self.event_waiters.values_mut() {
            waiters.retain(|t| *t != task_id);
        }
        for waiters in self.budget_waiters.values_mut() {
            waiters.retain(|t| *t != task_id);
        }
        for waiters in self.sleep_waiters.values_mut() {
            waiters.retain(|t| *t != task_id);
        }
    }

    fn deliver_due_sleepers(&mut self, step: u64) {
        let now = self.clock.now_ticks();
        let due: Vec<u64> = self.sleep_waiters.range(..=now).map(|(k, _)| *k).collect();

        for key in due {
            if let Some(mut tasks) = self.sleep_waiters.remove(&key) {
                tasks.sort_by_key(|t| t.index());
                for task_id in tasks {
                    self.make_runnable(task_id, step, None);
                }
            }
        }
    }

    fn next_sleep_tick(&self) -> Option<u64> {
        self.sleep_waiters.keys().next().copied()
    }

    fn any_blocked(&self) -> bool {
        self.tasks.iter().enumerate().any(|(id, _)| {
            self.executor.state(SimTaskId::from_u32(id as u32)) == SimTaskState::Blocked
        })
    }

    fn fairness_violation(&self, step: u64) -> bool {
        if self.cfg.fairness_bound == 0 {
            return false;
        }
        self.runnable_since
            .iter()
            .any(|(_, since)| step.saturating_sub(*since) > self.cfg.fairness_bound)
    }

    fn fail(&self, kind: FailureKind, message: &str, step: u64) -> RunOutcome {
        RunOutcome::Failed(FailureReport {
            kind,
            message: message.to_string(),
            step,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sim_scheduler::program::{Instr, Program, TaskProgram};

    #[test]
    fn scheduler_runner_completes_simple_program() {
        let program = Program {
            tasks: vec![TaskProgram {
                name: "main".to_string(),
                code: vec![Instr::Yield, Instr::Complete],
            }],
        };

        let cfg = SimSchedulerConfig {
            workers: 1,
            max_steps: 10,
            fairness_bound: 10,
            budgets: BTreeMap::new(),
        };

        let runner = SimSchedulerRunner::new(program, cfg, 1);
        match runner.run() {
            RunOutcome::Ok => {}
            RunOutcome::Failed(fail) => panic!("unexpected failure: {fail:?}"),
        }
    }
}

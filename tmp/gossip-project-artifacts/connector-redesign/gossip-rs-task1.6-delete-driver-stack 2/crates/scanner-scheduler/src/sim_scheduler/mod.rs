//! Scheduler-only simulation harness.
//!
//! This module provides deterministic task-program execution and safety/
//! liveness/fairness checks against a simulated work-stealing executor.

pub mod program;
pub mod runner;

pub use program::{Instr, Program, TaskProgram};
pub use runner::{FailureKind, FailureReport, RunOutcome, SimSchedulerConfig, SimSchedulerRunner};

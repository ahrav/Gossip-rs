//! Task program definitions for the scheduler simulation.
//!
//! Programs are deterministic instruction streams interpreted by the runner.

use serde::{Deserialize, Serialize};

/// A complete scheduler simulation program.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Program {
    pub tasks: Vec<TaskProgram>,
}

/// A single task program with a name and instruction stream.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaskProgram {
    pub name: String,
    pub code: Vec<Instr>,
}

/// Instruction set for the scheduler simulation interpreter.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Instr {
    Spawn { task_idx: u32 },
    Yield,
    Sleep { ticks: u64 },
    Acquire { budget: u16 },
    Release { budget: u16 },
    WaitEvent { event: u16 },
    SignalEvent { event: u16 },
    Cancel { task_idx: u32 },
    Complete,
}

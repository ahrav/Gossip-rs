//! Deterministic simulation primitives used by the sim harnesses.
//!
//! Purpose:
//! - Provide a stable RNG, simulated time source, and bounded trace buffer.
//! - Keep replay inputs small and deterministic by avoiding OS time/scheduling.
//!
//! Invariants:
//! - `SimClock` is monotonic and advances only through explicit calls.
//! - `TraceRing` never exceeds its capacity and evicts oldest events first.
//! - `SimRng` is deterministic and remaps a zero seed to a non-zero state.
//!
//! This module is only available with the `sim-harness` feature.

pub mod artifact;
pub mod clock;
pub mod executor;
pub mod fault;
pub mod fs;
pub mod minimize;
pub mod mutation;
pub mod rng;
pub mod trace;

pub use artifact::{ReproArtifact, TraceDump};
pub use clock::SimClock;
pub use executor::{
    SimExecutor, SimTask, SimTaskId, SimTaskState, StepDecision, StepResult, WorkerId,
};
pub use fault::{Corruption, FaultInjector, FaultPlan, FileFaultPlan, IoFault, ReadFault};
pub use fs::{SimFileHandle, SimFs, SimFsSpec, SimNodeSpec, SimPath, SimTypeHint};
pub use minimize::{minimize_scanner_case, MinimizerCfg};
pub use rng::SimRng;
pub use trace::{TraceEvent, TraceRing};

//! Coordination simulation harness for deterministic testing.
//!
//! Provides a simulated coordination environment with multiple workers
//! operating on shards through a simplified in-memory backend. The harness
//! drives operations via a discrete-event scheduler (following sled's
//! priority-queue pattern) and verifies invariants after every step.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
//! │  SimWorker 0 │     │  SimWorker 1 │     │  SimWorker N │
//! └──────┬──────┘     └──────┬──────┘     └──────┬──────┘
//!        │                   │                   │
//!        └──────────┬────────┴───────────────────┘
//!                   │
//!            ┌──────┴──────┐
//!            │ SimBackend  │  ← simplified in-memory coordination
//!            └──────┬──────┘
//!                   │
//!            ┌──────┴──────┐
//!            │ SimScheduler│  ← discrete-event priority queue
//!            └─────────────┘
//! ```
//!
//! # Evidence
//!
//! - sled: discrete-event simulation with priority queue scheduler
//! - TigerBeetle VOPR: progressive difficulty (3 levels), time compression
//! - FoundationDB SIGMOD 2021: seeded PRNG, simulated clock, scheduler
//! - Yuan et al. OSDI 2014: error handling paths are highest-value targets
//!
//! # Feature gate
//!
//! This module is only available when the `test-support` feature is enabled.

mod backend;
mod harness;
mod invariants;
mod worker;

pub use backend::SimBackend;
pub use harness::CoordinationSim;
pub use invariants::InvariantChecker;
pub use worker::SimWorker;

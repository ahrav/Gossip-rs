//! Simulation harness tests for scheduler and scanner.
//!
//! Feature gates:
//! - `scheduler-sim` compiles scheduler-only simulations.
//! - `sim-harness` compiles scanner and Git scan simulations.
//! - `real-rules-harness` compiles real-ruleset baseline snapshot tests.
//!
//! Run with:
//!   cargo test --features scheduler-sim --test simulation  # scheduler only
//!   cargo test -p scanner-engine-integration-tests --features sim-harness,rocksdb --test simulation
//!                                                     # scanner + git
//!   cargo test --features real-rules-harness --test simulation  # real rules
//!   cargo test -p scanner-engine-integration-tests --features scheduler-sim,sim-harness,rocksdb --test simulation
//!                                                     # both

#[allow(unused_imports)]
mod scanner_rs {
    pub use scanner_engine::*;
    pub use scanner_git as git_scan;
    pub use scanner_scheduler::archive;
    pub use scanner_scheduler::scheduler;
    pub mod unified {
        #[allow(unused_imports)]
        pub mod events {
            pub use scanner_git::{EventSink, NullEventSink, ScanEvent, VecEventSink};
        }
    }
    #[cfg(feature = "sim-harness")]
    pub use scanner_git::sim_git_scan;
    #[cfg(feature = "sim-harness")]
    pub use scanner_scheduler::sim;
    #[cfg(feature = "sim-harness")]
    pub use scanner_scheduler::sim_archive;
    #[cfg(feature = "sim-harness")]
    pub use scanner_scheduler::sim_scanner;
    #[cfg(feature = "scheduler-sim")]
    pub use scanner_scheduler::sim_scheduler;
}

#[cfg(feature = "scheduler-sim")]
mod scheduler_sim;

#[cfg(feature = "sim-harness")]
mod scanner_random;

#[cfg(feature = "sim-harness")]
mod scanner_corpus;

#[cfg(feature = "sim-harness")]
mod scanner_archive_corpus;

#[cfg(feature = "sim-harness")]
mod scanner_archive_random;

#[cfg(feature = "sim-harness")]
mod scanner_discovery;

#[cfg(feature = "sim-harness")]
mod scanner_max_file_size;

#[cfg(feature = "sim-harness")]
mod scanner_budget_invariance;

#[cfg(feature = "sim-harness")]
mod git_scan_corpus;

#[cfg(feature = "sim-harness")]
mod git_scan_random;

#[cfg(feature = "sim-harness")]
mod git_scan_shallow_limits;

#[cfg(feature = "sim-harness")]
mod scanner_mutation_random;

#[cfg(feature = "sim-harness")]
mod scanner_mutation_corpus;

#[cfg(feature = "real-rules-harness")]
mod scanner_real_rules;

//! Distributed worker runtime for receipt-driven shard execution.
//!
//! This module is the entry point for distributed scanning. Two worker loops
//! share the claim-execute-advance structure but target different source
//! families:
//!
//! - **Filesystem** ([`run_worker`]): ordered-content shards scanned via
//!   `parallel_scan_dir` and committed through a bounded receipt pipeline.
//! - **Git repo-frontier** ([`run_git_repo_worker`]): singleton repo-frontier
//!   shards scanned via `GitRepoRuntime::execute_repo` with durable finalize
//!   receipts producing the shard-advance checkpoint.
//!
//! Both loops claim leases from a [`CoordinationFacade`], execute the
//! appropriate scan path, and advance (or fail-fast) based on the committed
//! result.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────┐    claim        ┌────────────────────┐
//! │ Coordinator  │ ─────────────>  │  run_worker loop   │ (filesystem)
//! │ (CoordFacade)│ <───────────── │ (claim/scan/advance)│
//! └──────┬───────┘ checkpoint/complete └──────┬────────┘
//!        │                               │
//!        │                     ┌─────────▼──────────┐
//!        │                     │ run_filesystem_lease│
//!        │                     │  (per shard)        │
//!        │                     └─────────┬──────────┘
//!        │            ┌──────────────────┼──────────────────┐
//!        │            ▼                  ▼                  ▼
//!        │ ┌────────────────┐  ┌──────────────────┐ ┌─────────────┐
//!        │ │ scan engine    │  │ ReceiptCommitSink │ │ commit      │
//!        │ │ (scheduler)    │──│ (CommitSink impl) │─│ pipeline    │
//!        │ └────────────────┘  └──────────────────┘ │ + drainer   │
//!        │                                          └──────┬──────┘
//!        │                                                 ▼
//!        │                                        ┌────────────────┐
//!        │                                        │ Checkpoint     │
//!        │                                        │ Aggregator     │
//!        │                                        └────────────────┘
//!        │
//!        │   claim     ┌──────────────────────────┐
//!        └────────────>│ run_git_repo_worker loop  │ (repo-frontier)
//!         <────────────│ (claim/mirror/scan/advance)│
//!     complete/fail    └──────────┬───────────────┘
//!                                 │
//!                       ┌─────────▼──────────┐
//!                       │ run_git_repo_lease  │
//!                       │  (per shard)        │
//!                       └─────────┬──────────┘
//!                    ┌────────────┼────────────┐
//!                    ▼            ▼            ▼
//!          ┌──────────────┐ ┌──────────┐ ┌──────────────┐
//!          │ mirror sync  │ │ execute  │ │ persistence  │
//!          │ (locator)    │ │ _repo    │ │ (finalize    │
//!          └──────────────┘ │ (scan)   │ │  receipt)    │
//!                           └──────────┘ └──────────────┘
//! ```
//!
//! # Key types
//!
//! | Type                        | Role                                             |
//! |-----------------------------|--------------------------------------------------|
//! | [`WorkerIdentity`]          | Immutable filesystem worker identity bundle       |
//! | [`GitWorkerIdentity`]       | Immutable Git repo-frontier worker identity bundle|
//! | [`ShardLease`]              | Per-shard lease payload with scan config + fencing|
//! | [`GitShardLease`]           | Per-shard lease payload for repo-frontier shards  |
//! | [`DistributedPersistence`]  | Cloneable persistence backend handles             |
//! | [`DistributedRuntimeConfig`]| Budget and queue-sizing knobs                     |
//! | [`DistributedRunReport`]    | Summary counters from one worker invocation       |
//! | [`DistributedRuntimeError`] | Layered error: coordinator / lease-uncertainty / runtime / durability |
//!
//! # Invariants
//!
//! 1. **Receipt-only checkpoint advancement.** Checkpoint progress is derived
//!    exclusively from durable commit receipts, never from raw scan completion.
//! 2. **Single-threaded scan execution.** Each shard runs with `workers = 1` so
//!    the `ReceiptCommitSink` sequence counter remains monotonic without
//!    cross-thread synchronization.
//! 3. **At-least-once delivery.** The commit pipeline tolerates duplicate writes
//!    for the same `(write_context, item_key)` pair. Persistence backends must
//!    be idempotent.
//! 4. **Fail-fast after claim.** Once a shard is claimed, any scan, commit,
//!    shard-advance, or explicit lease-uncertainty stop terminates the worker
//!    loop. Uncompleted leases expire via coordination-layer deadlines.
//!
//! # Internal adapter: `ReceiptCommitSink`
//!
//! The scan scheduler emits compact `CommitSink` callbacks (`begin_item`,
//! `upsert_findings`, `finish_item`). `ReceiptCommitSink` bridges these into
//! the richer [`CommitPipeline`] by reconstructing deterministic
//! [`crate::result_translation::translate_item_result`]
//! inputs and submitting owned [`QueuedCommit`] work items.
//!
//! [`CoordinationFacade`]: gossip_coordination::CoordinationFacade
//! [`CommitPipeline`]: crate::commit_pipeline::CommitPipeline
//! [`QueuedCommit`]: crate::commit_pipeline::QueuedCommit

// -- Submodules (production) ------------------------------------------------

mod commit_bridge;
mod execution;
mod lease_ops;
mod types;

// -- Public API re-exports --------------------------------------------------

pub use types::{
    DistributedPersistence, DistributedRunReport, DistributedRuntimeConfig,
    DistributedRuntimeError, GitShardLease, GitWorkerIdentity, LeaseUncertainty, ShardLease,
    WorkerIdentity,
};

pub use execution::{run_git_repo_worker, run_worker};

#[cfg(any(test, feature = "test-support"))]
pub use execution::secret_fixture;

// -- Test-only modules ------------------------------------------------------

#[cfg(test)]
mod test_support;

#[cfg(test)]
mod unit_tests;

#[cfg(test)]
mod integration_tests;

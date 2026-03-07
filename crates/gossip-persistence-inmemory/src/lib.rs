//! In-memory persistence backends for tests and deterministic simulation.
//!
//! These are **reference implementations**, not toy mocks:
//! - Done-ledger writes use the same monotonic lattice merge semantics
//!   required of real backends (see [`DoneLedgerStatus::merge`]).
//! - Findings writes are idempotent and enforce referential integrity between
//!   findings, occurrences, and observations: every occurrence must reference
//!   a finding that is either already durable *or* present in the same batch,
//!   and likewise for observations referencing occurrences.
//! - Durability acknowledgements remain explicit via [`CommitHandle::wait()`]:
//!   a returned handle only proves the backend *accepted* the write — callers
//!   must wait to establish durability.
//!
//! # Architecture
//!
//! Both [`InMemoryDoneLedger`] and [`InMemoryFindingsSink`] share the same
//! internal pattern: `Arc<Inner>` wrapping a `Mutex<State>` + `Condvar`.
//! Commit handles hold an `Arc` clone and block on the condvar until the
//! operation transitions from `Pending` to `Finished`. This mirrors the
//! real-backend contract where `wait()` blocks on I/O (fsync, replication).
//!
//! # Completion modes
//!
//! Each store has two completion modes controlled by `auto_complete`:
//!
//! - **Auto-complete (default):** writes apply immediately during
//!   `batch_upsert` / `upsert_batch`, so `handle.wait()` returns at once.
//!   This is the normal test path.
//! - **Delayed:** writes are enqueued as pending operations and only applied
//!   when explicitly released via [`release_next`], [`release_specific`], or
//!   [`release_all`]. This mode is used in deterministic simulation to
//!   exercise concurrent-durability scenarios and out-of-order completion.
//!
//! [`delay_next_writes`] overrides `auto_complete` for a specific count of
//! submissions, allowing mixed-mode operation within a single test.
//!
//! # Fault injection
//!
//! The fault-injection controls are intentionally simple and deterministic.
//! Three independent counters control failure behavior, checked in this order
//! during each submission:
//!
//! 1. **`fail_submit_remaining`** — rejects the request before any state
//!    mutation or handle creation. The caller sees an immediate error from
//!    `batch_upsert` / `upsert_batch`.
//! 2. **`delay_next`** / **`auto_complete`** — determines whether the
//!    accepted write is applied immediately or enqueued as pending.
//! 3. **`fail_commit_remaining`** — injects a failure at apply time (either
//!    immediately for auto-completed writes, or when the pending op is
//!    released). The caller sees the error from `handle.wait()`.
//!
//! [`DoneLedgerStatus::merge`]: gossip_contracts::persistence::DoneLedgerStatus::merge
//! [`CommitHandle::wait()`]: gossip_contracts::persistence::CommitHandle::wait
//! [`release_next`]: InMemoryDoneLedger::release_next
//! [`release_specific`]: InMemoryDoneLedger::release_specific
//! [`release_all`]: InMemoryDoneLedger::release_all
//! [`delay_next_writes`]: InMemoryDoneLedger::delay_next_writes

#![forbid(unsafe_code)]

mod done_ledger;
pub mod error;
mod findings;
pub(crate) mod pending;

pub use done_ledger::{InMemoryDoneLedger, InMemoryDoneLedgerHandle};
pub use error::{CompletionOrder, InMemoryPersistenceError, InMemoryStoreKind, PendingWriteId};
pub use findings::{InMemoryFindingsHandle, InMemoryFindingsSink};

#[cfg(test)]
mod tests;

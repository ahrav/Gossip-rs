//! Persistence-boundary core contracts: done-ledger identity, findings record
//! shapes, durable acknowledgement semantics, and backend-neutral traits.
//!
//! This module publishes the storage-agnostic durable data model that
//! persistence backends compile against without committing to any
//! backend-specific transaction, batching, or retry mechanism. The re-exports
//! below keep the contract surface centralized for production use and for the
//! reference harness.
//!
//! ## Surface split
//!
//! - `commit.rs` declares the durable acknowledgement handles (`CommitHandle`,
//!   `ReadyCommitHandle`) and receipt types that flow through `CommitScope`.
//! - `ovid.rs` defines the `OvidHash` identity, `OvidHashInputs`, and helper
//!   utilities that the done-ledger uses to anchor observation snapshots.
//! - `done_ledger.rs` defines `DoneLedger` keys, records, provenance helpers,
//!   safe error codes, status markers, and the backend-neutral `DoneLedger`
//!   trait.
//! - `findings.rs` exposes the `PersistenceFinding` normalization boundary,
//!   observation/occurrence/record shapes, and the backend-neutral
//!   `FindingsSink` trait along with `FindingsUpsertBatch`.
//! - `page_commit.rs` captures checkpoint boundary types and the typestate
//!   `PageCommit<S>` that enforces the required findings → done-ledger →
//!   checkpoint ordering.
//! - `write_context.rs` defines the routing, fencing, and batching metadata that
//!   accompany runtime write paths before they issue durable acknowledgements.
//! - `error.rs` surfaces `PersistenceInputError` and related validation helpers
//!   shared across persistence-only value wrappers.
//! - `conformance.rs` drives the backend-agnostic persistence conformance
//!   harness that reference backends and production implementations can reuse.
//!
//! ## Conformance harness
//!
//! The reusable persistence conformance harness lets backend implementors verify
//! correctness against the contract surface without hard-wiring a specific
//! storage driver:
//! - `run_conformance` executes the done-ledger, findings, and redaction checks.
//! - `run_done_ledger_conformance` runs only the done-ledger checks for backends
//!   that do not implement findings persistence.
//! - `run_findings_conformance` runs only the findings-layer checks for backends
//!   that implement findings but not done-ledger persistence.
//! - `run_redaction_conformance` executes only the `Debug`-redaction checks and
//!   requires no backend instance (pure in-memory assertions).
//! - `FindingsConformanceProbe` keeps findings replay/idempotency verification
//!   out of the production `FindingsSink` trait surface.
//! - External backend crates can depend on this public module in integration
//!   tests without enabling a contracts-only `cfg` gate.
//!
//! ## Submission vs durability
//!
//! Persistence sinks separate request acceptance from durable acknowledgement:
//! `Ok(handle)` means the backend accepted responsibility for the write, while
//! `handle.wait()` establishes durability and returns a receipt proving what
//! committed.
//!
//! ## Cross-trait ordering contract
//!
//! When a scan produces findings, callers must durably persist them via
//! `FindingsSink::upsert_batch` **before** durably recording completion in
//! `DoneLedger::batch_upsert`, and only checkpoint the family-specific
//! frontier boundary after both layers cover their writes. The `PageCommit<S>`
//! typestate machine enforces that ordering at compile time.
//!
//! ## Observation-identity scope
//!
//! Durable policy-scoped observations are rooted in a canonical
//! [`ObservationId`](crate::identity::ObservationId) derived from
//! `(tenant_id, policy_hash, occurrence_id)`. Persistence constructors
//! ([`ObservationRecord::from_persisted`](crate::persistence::ObservationRecord::from_persisted))
//! and batch validation
//! ([`FindingsUpsertBatch::validate_observation_identity`](crate::persistence::FindingsUpsertBatch::validate_observation_identity))
//! reject mismatched observation IDs rather than trusting caller-provided
//! values.
//!
//! ## Batch size guidance
//!
//! Both `DoneLedger` and `FindingsSink` accept slice-based batches. Callers
//! SHOULD keep batches at or below `RECOMMENDED_MAX_BATCH_SIZE` records to keep
//! acknowledgement latency and retry work bounded. Implementations SHOULD
//! reject batches exceeding this limit via their associated error type.
//!
//! ## Invariants
//!
//! - No raw secret bytes appear in any public record shape.
//! - Secret-derived fields use fixed-width hash newtypes whose `Debug` output is
//!   already redacted or bounded.
//! - Free-form strings are limited to explicitly safe, size-bounded wrappers or
//!   reused safe boundary types such as [`Location`](crate::connector::Location).

mod commit;
pub mod conformance;
mod done_ledger;
mod error;
mod findings;
mod ovid;
mod page_commit;
mod write_context;

/// Recommended maximum batch size for persistence operations.
///
/// Both [`DoneLedger`] and [`FindingsSink`] accept slice-based batches. Callers
/// SHOULD keep batches under this limit to bound acknowledgement latency and
/// retry work, and implementations SHOULD reject larger batches via their
/// associated error type.
pub const RECOMMENDED_MAX_BATCH_SIZE: usize = 10_000;

/// Durable acknowledgement handles and receipts exposed by the persistence layer.
pub use commit::{
    CheckpointCommitReceipt, CommitHandle, CommitReceipt, DoneLedgerCommitReceipt,
    FindingsCommitReceipt, ItemCommitReceipt, PageCommitReceipt, ReadyCommitHandle,
};
/// Conformance harness entry points and reports.
pub use conformance::{
    DurableFindingsCounts, FindingsConformanceProbe, PersistenceConformanceError,
    PersistenceConformanceReport, run_conformance, run_done_ledger_conformance,
    run_findings_conformance, run_redaction_conformance,
};
/// Done-ledger keys, records, and traits.
pub use done_ledger::{
    DoneLedger, DoneLedgerErrorCode, DoneLedgerKey, DoneLedgerProvenance, DoneLedgerRecord,
    DoneLedgerStatus, MAX_DONE_LEDGER_ERROR_CODE_SIZE,
};
/// Input-validation errors shared across persistence-only wrappers.
pub use error::PersistenceInputError;
/// Findings and observation record shapes plus the sink/normalization contracts.
pub use findings::{
    FindingRecord, FindingsSink, FindingsUpsertBatch, ObservationRecord, OccurrenceRecord,
    PersistenceFinding,
};
/// Object-version identity utilities used by the done-ledger.
pub use ovid::{OvidHash, OvidHashInputs, derive_ovid_hash};
/// Typestate machine and checkpoint boundary helpers.
pub use page_commit::{
    AwaitingFindings, CheckpointBoundary, CheckpointBoundaryKind, CheckpointDurable,
    CommitAdvanceError, CommitScope, FindingsDurable, ItemDurable, PageCommit,
    PageCommitValidationError,
};
/// Metadata routable through runtime writes before acknowledgements.
pub use write_context::WriteContext;

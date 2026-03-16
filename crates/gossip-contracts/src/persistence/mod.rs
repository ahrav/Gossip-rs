//! Persistence-boundary core contracts: done-ledger identity, findings record
//! shapes, durable acknowledgement semantics, and backend-neutral traits.
//!
//! This module is intentionally storage-agnostic. It defines the durable data
//! model that persistence backends compile against without committing to any
//! backend-specific transaction, batching, or retry mechanism.
//!
//! ## Surface split
//!
//! - `commit.rs` defines backend-neutral durable acknowledgement handles and
//!   receipt types.
//! - `ovid.rs` defines object-version identity hashing used by the done-ledger.
//! - `done_ledger.rs` defines done-ledger keys, records, safe error codes, and
//!   the backend-neutral `DoneLedger` trait.
//! - `findings.rs` defines stable finding, occurrence, and observation record
//!   shapes plus the backend-neutral `FindingsSink` trait.
//! - `page_commit.rs` defines the family-neutral checkpoint boundary types and
//!   the `PageCommit<S>` typestate machine that enforces findings →
//!   done-ledger → checkpoint ordering.
//! - `write_context.rs` defines the shared routing and fencing metadata carried
//!   by runtime write paths.
//! - `error.rs` defines shared input-validation errors used by persistence-only
//!   value wrappers.
//! - `conformance.rs` defines the backend-agnostic persistence conformance
//!   harness used by reference backends and future production implementations.
//!
//! ## Conformance harness
//!
//! The reusable persistence conformance harness enables backend
//! implementors to verify correctness against the contract surface:
//!
//! - `run_conformance` executes done-ledger, findings, and redaction checks.
//! - `run_done_ledger_conformance` executes only the done-ledger checks (4)
//!   for backends that have not implemented findings persistence yet.
//! - `run_findings_conformance` executes only the findings-layer checks (4)
//!   for backends that have findings but not done-ledger persistence.
//! - `run_redaction_conformance` executes only the `Debug`-redaction checks
//!   (3) and requires no backend instance (pure in-memory assertions).
//! - `FindingsConformanceProbe` keeps findings replay/idempotency verification
//!   out of the production `FindingsSink` trait surface.
//! - External backend crates can depend on this public module in integration
//!   tests without enabling a contracts-only cfg gate.
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
//! frontier boundary after both layers are durable. The `PageCommit<S>`
//! typestate machine enforces that ordering.
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
//! Both `DoneLedger` and `FindingsSink` accept slice-based batches.
//! Callers SHOULD keep batches at or below `RECOMMENDED_MAX_BATCH_SIZE`
//! records. Implementations SHOULD reject batches exceeding this limit via
//! their associated error type.
//!
//! ## Invariants
//!
//! - No raw secret bytes appear in any public record shape.
//! - Secret-derived fields use fixed-width hash newtypes whose `Debug` output
//!   is already redacted or bounded.
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
/// Both [`DoneLedger`] and [`FindingsSink`] accept slice-based batches.
/// Implementations SHOULD reject batches exceeding this limit via their
/// associated error type.
pub const RECOMMENDED_MAX_BATCH_SIZE: usize = 10_000;

pub use commit::{
    CheckpointCommitReceipt, CommitHandle, CommitReceipt, DoneLedgerCommitReceipt,
    FindingsCommitReceipt, ItemCommitReceipt, PageCommitReceipt, ReadyCommitHandle,
};
pub use conformance::{
    DurableFindingsCounts, FindingsConformanceProbe, PersistenceConformanceError,
    PersistenceConformanceReport, run_conformance, run_done_ledger_conformance,
    run_findings_conformance, run_redaction_conformance,
};
pub use done_ledger::{
    DoneLedger, DoneLedgerErrorCode, DoneLedgerKey, DoneLedgerProvenance, DoneLedgerRecord,
    DoneLedgerStatus, MAX_DONE_LEDGER_ERROR_CODE_SIZE,
};
pub use error::PersistenceInputError;
pub use findings::{
    FindingRecord, FindingsSink, FindingsUpsertBatch, ObservationRecord, OccurrenceRecord,
};
pub use ovid::{OvidHash, OvidHashInputs, derive_ovid_hash};
pub use page_commit::{
    AwaitingFindings, CheckpointBoundary, CheckpointBoundaryKind, CheckpointDurable,
    CommitAdvanceError, CommitScope, FindingsDurable, ItemDurable, PageCommit,
    PageCommitValidationError,
};
pub use write_context::WriteContext;

//! Persistence-boundary core contracts: done-ledger identity, findings record
//! shapes, validation errors, and backend-neutral traits.
//!
//! This module is intentionally storage-agnostic. It defines the durable data
//! model that persistence backends compile against without committing to any
//! backend-specific transaction, batching, or retry mechanism.
//!
//! ## Surface split
//!
//! - `ovid.rs` defines object-version identity hashing used by the done-ledger.
//! - `done_ledger.rs` defines done-ledger keys, records, safe error codes, and
//!   the backend-neutral `DoneLedger` trait.
//! - `findings.rs` defines stable finding, occurrence, and observation record
//!   shapes plus the backend-neutral `FindingsSink` trait.
//! - `error.rs` defines shared input-validation errors used by persistence-only
//!   value wrappers.
//!
//! ## Cross-trait ordering contract
//!
//! When a scan produces findings, callers must persist them via
//! `FindingsSink::upsert_batch` **before** recording completion in
//! `DoneLedger::batch_upsert`. This ordering ensures that a done-ledger
//! entry with `ScannedWithFindings` always has its findings already durable.
//! Mechanical enforcement of this ordering is deferred to the commit protocol
//! layer (`PageCommit`), which is not yet defined in this crate.
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

mod done_ledger;
mod error;
mod findings;
mod ovid;

/// Recommended maximum batch size for persistence operations.
///
/// Both [`DoneLedger`] and [`FindingsSink`] accept slice-based batches.
/// Implementations SHOULD reject batches exceeding this limit via their
/// associated error type.
pub const RECOMMENDED_MAX_BATCH_SIZE: usize = 10_000;

pub use done_ledger::{
    DoneLedger, DoneLedgerErrorCode, DoneLedgerKey, DoneLedgerProvenance, DoneLedgerRecord,
    DoneLedgerStatus, MAX_DONE_LEDGER_ERROR_CODE_SIZE,
};
pub use error::PersistenceInputError;
pub use findings::{
    FindingRecord, FindingsSink, FindingsUpsertBatch, ObservationRecord, OccurrenceRecord,
};
pub use ovid::{OvidHash, OvidHashInputs, derive_ovid_hash};

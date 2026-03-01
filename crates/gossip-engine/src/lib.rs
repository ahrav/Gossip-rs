//! Runtime-agnostic scanner core for deterministic page and stream evaluation.
//!
//! This crate defines the stable API boundary that both the standalone CLI and
//! distributed worker runtimes compile against. It replaces the former
//! detection-engine crate (regex / vectorscan / custom detectors) with a
//! deterministic scaffold suitable for parity validation during migration.
//!
//! # How scanning works
//!
//! A **scan** evaluates connector-provided [`ScanItem`](gossip_contracts::connector::ScanItem)s
//! against a page or stream context:
//!
//! 1. Each item is fingerprinted with FNV-1a over `(stable_item_id, version, payload)`.
//! 2. A per-page **signature** (also FNV-1a) aggregates key range, cursor, and
//!    item boundary data so upstream can detect page-level changes cheaply.
//! 3. Fingerprints are deduplicated through caller-owned [`ScanDedupState`];
//!    duplicates within or across pages are suppressed.
//! 4. Findings exceeding [`ScannerCoreConfig::max_findings_per_page`] are
//!    truncated with a [`ScanDiagnostic::FindingsTruncated`] diagnostic.
//!
//! # Phase 1A scope
//!
//! The current surface intentionally ships a small typed contract used for
//! parity scaffolding — no actual detection rules execute yet.
//!
//! | Concern         | Types |
//! |-----------------|-------|
//! | Construction    | [`ScannerCore`], [`ScannerCoreBuilder`], [`ScannerCoreConfig`] |
//! | Entrypoints     | [`ScannerCore::scan_page`], [`ScannerCore::scan_stream`] |
//! | Inputs          | [`PageScanContext`], [`PageScanRequest`] |
//! | Outputs         | [`PageScanOutput`], [`StreamScanOutput`], [`ScanFinding`], [`ScanStats`], [`ScanDedupeCounters`], [`ScanDiagnostic`] |
//! | Errors          | [`ScannerCoreBuildError`], [`ScannerCoreError`] |
//!
//! # Design constraints
//!
//! - **Runtime agnostic**: no CLI output formatting, no process exits, no I/O.
//! - **Deterministic**: identical inputs always produce identical outputs;
//!   the core is `Copy + Send + Sync`.
//! - **Boundary consistency**: request types align with
//!   [`gossip_contracts::connector::{ScanItem, Cursor}`].
//! - **Hot-path awareness**: borrowed inputs and caller-owned dedupe state
//!   avoid forcing per-page heap allocation. See also
//!   [`ScannerCore::scan_page_into`] for zero-reallocation page scanning.

mod core;
mod error;
mod types;

pub use core::{ScannerCore, ScannerCoreBuilder, ScannerCoreConfig};
pub use error::{ScannerCoreBuildError, ScannerCoreError};
pub use types::{
    PageScanContext, PageScanOutput, PageScanRequest, PageScanSummary, ScanDedupState,
    ScanDedupeCounters, ScanDiagnostic, ScanFinding, ScanStats, StreamScanOutput,
};

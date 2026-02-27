//! Conformance harness configuration and digest-only diagnostic vocabulary.
//!
//! This module is a contracts-only surface for connector conformance checks.
//! It provides:
//!
//! - strict-by-default harness configuration knobs ([`ConformanceConfig`]),
//! - observation types for cross-run comparisons
//!   ([`Digest32`], [`ItemObservation`], [`EnumerationTrace`]),
//! - and an invariant-failure taxonomy ([`ConformanceError`]).
//!
//! ## Invariants
//!
//! - Conformance diagnostic payloads represented by [`Digest32`] avoid raw
//!   connector byte exposure.
//! - [`Digest32`] and [`ItemObservation`] format as redacted, stable tokens for
//!   log correlation.
//!
//! ## Trade-off
//!
//! [`Digest32`] keeps full 32-byte hashes for equality and map/set keys, while
//! its `Display` output prints only an 8-byte hex prefix. This preserves
//! compact log lines while retaining precise in-memory comparisons.

use std::fmt;

use super::api::{ConnectorCapabilities, ErrorClass};
use super::page_validator::PageValidationError;
use super::types::{Budgets, Cursor};

/// Default best-effort secret patterns that should not appear in `ItemRef`.
///
/// These are heuristics used by conformance checks to catch accidental
/// credential leakage in connector handles. The harness reports digest-only
/// diagnostics for matches.
pub const DEFAULT_FORBIDDEN_ITEMREF_PATTERNS: &[&[u8]] = &[
    b"Authorization:",
    b"Bearer ",
    b"AKIA",
    b"ASIA",
    b"x-amz-security-token",
    b"X-Amz-Signature=",
    b"X-Amz-Credential=",
    b"GoogleAccessId=",
    b"-----BEGIN ",
];

/// Whether a connector run is expected to be fully deterministic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeterminismExpectation {
    /// Repeated full scans are expected to produce identical observations.
    Deterministic,
    /// Determinism is not strictly required by caller policy.
    ///
    /// This type records the expectation only; enforcement behavior is defined
    /// by the harness that consumes this configuration.
    BestEffort,
}

/// Resume-by-key checks toggled by the conformance harness.
///
/// Each flag independently enables a token perturbation scenario. Keeping the
/// controls separate allows callers to narrow failures to one recovery path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResumeChecks {
    /// Require forward progress when pagination token state is removed.
    pub drop_token: bool,
    /// Require forward progress when pagination token state is corrupted.
    pub corrupt_token: bool,
}

impl Default for ResumeChecks {
    fn default() -> Self {
        Self {
            drop_token: true,
            corrupt_token: true,
        }
    }
}

/// Best-effort secret scan configuration for `ItemRef` bytes.
///
/// This is a heuristic leak-detection surface. It is intentionally configurable
/// so tests can tune false-positive/false-negative trade-offs per connector.
#[derive(Clone, Debug)]
pub struct SecretScanConfig {
    /// Global on/off switch for secret scanning.
    pub enabled: bool,
    /// Byte substrings that should not appear in connector item references.
    pub forbidden_substrings: Vec<&'static [u8]>,
    /// Full-byte canaries injected by tests for connector-specific leak checks.
    pub secret_canaries: Vec<Vec<u8>>,
}

impl Default for SecretScanConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            forbidden_substrings: DEFAULT_FORBIDDEN_ITEMREF_PATTERNS.to_vec(),
            secret_canaries: Vec::new(),
        }
    }
}

/// Restart-point selection strategy for resume checks.
///
/// Restart points refer to cursor checkpoint indices from a baseline run.
/// Index validation and out-of-range handling are owned by the harness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestartPoints {
    /// Choose up to `N` points spread across a baseline run.
    Auto(usize),
    /// Restart from explicit cursor checkpoint indices.
    Explicit(&'static [usize]),
}

/// Conformance harness knobs.
///
/// Defaults are intentionally strict so connectors explicitly opt out of weaker
/// checks.
#[derive(Clone, Debug)]
pub struct ConformanceConfig {
    /// Hard cap on number of page requests in a single run.
    pub max_pages: usize,
    /// Hard cap on number of collected items in a single run.
    pub max_total_items: usize,
    /// Budgets forwarded to each `enumerate_page` call.
    pub page_budgets: Budgets,
    /// Enforce strictly increasing keys within each page.
    pub require_strict_key_order: bool,
    /// Enforce `next_cursor.last_key == last_item.key` when pages are non-empty.
    pub require_cursor_eq_last_item: bool,
    /// Cross-run determinism policy.
    pub determinism: DeterminismExpectation,
    /// Resume-path perturbation checks.
    pub resume_checks: ResumeChecks,
    /// Secret-scan policy for connector `ItemRef` values.
    pub secret_scan: SecretScanConfig,
    /// Baseline cursor checkpoint selection for resume comparisons.
    pub restart_points: RestartPoints,
}

impl Default for ConformanceConfig {
    fn default() -> Self {
        Self {
            max_pages: 10_000,
            max_total_items: 1_000_000,
            page_budgets: Budgets::try_new(32, u64::MAX, None)
                .expect("conformance default page budgets must be non-zero"),
            require_strict_key_order: true,
            require_cursor_eq_last_item: true,
            determinism: DeterminismExpectation::Deterministic,
            resume_checks: ResumeChecks::default(),
            secret_scan: SecretScanConfig::default(),
            restart_points: RestartPoints::Auto(4),
        }
    }
}

/// Formats the first 8 bytes of a 32-byte hash as lowercase hex.
///
/// Used in human-facing diagnostics to keep output compact while preserving
/// enough entropy for log-line correlation.
#[inline]
fn hash_prefix8_hex(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(16);
    for byte in bytes.iter().take(8) {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Hash-only digest used in conformance diagnostics and set/map keys.
///
/// The original payload is never stored directly. This keeps diagnostics
/// log-safe while allowing deterministic equality/hash behavior.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Digest32 {
    /// Original payload length, saturating at `u32::MAX` for oversized inputs.
    len: u32,
    /// Full 32-byte BLAKE3 digest of the original payload.
    hash: [u8; 32],
}

impl Digest32 {
    /// Builds a digest from raw bytes.
    ///
    /// # Edge case
    ///
    /// `len` is stored as `u32`. Inputs larger than `u32::MAX` bytes retain
    /// their full hash but report `len == u32::MAX`.
    #[must_use]
    pub fn of_bytes(bytes: &[u8]) -> Self {
        let hash = blake3::hash(bytes);
        Self {
            len: u32::try_from(bytes.len()).unwrap_or(u32::MAX),
            hash: *hash.as_bytes(),
        }
    }

    /// Returns the lowercase hex prefix (16 chars) used in diagnostics.
    #[must_use]
    pub fn prefix8_hex(&self) -> String {
        hash_prefix8_hex(&self.hash)
    }
}

impl fmt::Debug for Digest32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Digest32 {{ len: {}, hash_prefix8: {} }}",
            self.len,
            self.prefix8_hex()
        )
    }
}

impl fmt::Display for Digest32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "len={} hash_prefix8={}", self.len, self.prefix8_hex())
    }
}

/// Per-item observation used for cross-run comparisons.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ItemObservation {
    /// Digest of the item key.
    pub key: Digest32,
    /// Full 32-byte fingerprint used for cross-run item identity checks.
    pub fingerprint: [u8; 32],
}

impl ItemObservation {
    #[must_use]
    fn fingerprint_prefix8_hex(&self) -> String {
        hash_prefix8_hex(&self.fingerprint)
    }
}

impl fmt::Display for ItemObservation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "key=({}) item_fp_prefix8={}",
            self.key,
            self.fingerprint_prefix8_hex()
        )
    }
}

/// Trace captured from one full enumeration run.
///
/// This is a passive record type: it does not enforce internal consistency
/// between `items`, `cursors`, and `pages`.
#[derive(Clone, Debug)]
pub struct EnumerationTrace {
    /// Item observations in encounter order.
    pub items: Vec<ItemObservation>,
    /// Cursor checkpoints captured during the run.
    pub cursors: Vec<Cursor>,
    /// Number of page responses observed in the run.
    pub pages: usize,
}

/// Resume check mode used in mismatch diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResumeMode {
    /// Resume comparison where token state was removed.
    DropToken,
    /// Resume comparison where token state was mutated.
    CorruptToken,
}

/// Conformance failure taxonomy.
///
/// Variants are grouped by failure stage:
/// - capability gate (`CapabilityMissingSeekByKey`)
/// - per-page collection/validation failures
/// - run-level caps and determinism checks
/// - resume-path mismatch checks
/// - secret-scan findings
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConformanceError {
    /// Connector does not advertise required `seek_by_key` capability.
    CapabilityMissingSeekByKey {
        /// Connector capability snapshot seen by the harness.
        caps: ConnectorCapabilities,
    },
    /// `enumerate_page` returned an operational error.
    EnumerateFailed {
        /// Zero-based page index where failure occurred.
        at_page: usize,
        /// Retryability class reported by the connector.
        class: ErrorClass,
    },
    /// Connector returned more items than the configured page bound.
    ReturnedTooManyItems {
        /// Zero-based page index where violation occurred.
        at_page: usize,
        /// Item count returned by the connector.
        got: usize,
        /// Maximum allowed item count for this page.
        max: usize,
    },
    /// Generic page invariant failure from `validate_page`.
    PageValidationFailed {
        /// Zero-based page index where violation occurred.
        at_page: usize,
        /// Specific page-validation diagnostic.
        err: PageValidationError,
    },
    /// Page keys are not strictly increasing where strict order is required.
    NotStrictlyIncreasingWithinPage {
        /// Zero-based page index where violation occurred.
        at_page: usize,
        /// Index of the second key in the violating pair.
        at_index: usize,
        /// Previous key digest.
        prev_key: Digest32,
        /// Next key digest.
        next_key: Digest32,
    },
    /// Non-empty page returned a cursor key that differs from the last item key.
    CursorDoesNotMatchLastItem {
        /// Zero-based page index where violation occurred.
        at_page: usize,
        /// Returned cursor key digest (or `None`).
        cursor_key: Option<Digest32>,
        /// Last item key digest from the same page.
        last_item_key: Digest32,
    },
    /// Key digest appeared more than once in a single run.
    DuplicateKeyInRun {
        /// Duplicate key digest.
        key: Digest32,
    },
    /// Run exceeded configured `max_pages`.
    TooManyPages {
        /// Configured maximum number of pages.
        max_pages: usize,
    },
    /// Run exceeded configured `max_total_items`.
    TooManyItems {
        /// Configured maximum number of collected items.
        max_total_items: usize,
    },
    /// Cross-run item mismatch under deterministic expectation.
    DeterminismMismatch {
        /// Index into compared item sequences.
        at_index: usize,
        /// Observation from baseline run.
        run1: ItemObservation,
        /// Observation from comparison run.
        run2: ItemObservation,
    },
    /// Resume run diverged from baseline suffix content.
    ResumeMismatch {
        /// Baseline cursor checkpoint index used for restart.
        restart_cursor_index: usize,
        /// Token perturbation mode used for this restart.
        mode: ResumeMode,
        /// Index within the compared suffix.
        at_index: usize,
        /// Expected observation from baseline suffix.
        expected: ItemObservation,
        /// Observed item from resume run.
        got: ItemObservation,
    },
    /// Resume run produced a suffix length different from baseline expectation.
    ResumeLengthMismatch {
        /// Baseline cursor checkpoint index used for restart.
        restart_cursor_index: usize,
        /// Token perturbation mode used for this restart.
        mode: ResumeMode,
        /// Expected suffix length from baseline run.
        expected_len: usize,
        /// Actual suffix length from resume run.
        got_len: usize,
    },
    /// Secret-scan heuristic found a forbidden pattern inside an `ItemRef`.
    ItemRefAppearsToContainSecret {
        /// Digest of the matched pattern/canary bytes.
        pattern: Digest32,
        /// Digest of the offending `ItemRef` bytes.
        item_ref: Digest32,
    },
}

impl fmt::Display for ConformanceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CapabilityMissingSeekByKey { caps } => {
                write!(f, "connector caps missing seek_by_key: {caps:?}")
            }
            Self::EnumerateFailed { at_page, class } => {
                write!(f, "enumerate_page failed at page {at_page} with {class}")
            }
            Self::ReturnedTooManyItems { at_page, got, max } => {
                write!(
                    f,
                    "enumerate_page returned too many items at page {at_page} (got {got}, max {max})"
                )
            }
            Self::PageValidationFailed { at_page, err } => {
                write!(f, "page validation failed at page {at_page}: {err}")
            }
            Self::NotStrictlyIncreasingWithinPage {
                at_page,
                at_index,
                prev_key,
                next_key,
            } => {
                write!(
                    f,
                    "keys not strictly increasing within page {at_page} at index {at_index}: prev=({prev_key}) next=({next_key})"
                )
            }
            Self::CursorDoesNotMatchLastItem {
                at_page,
                cursor_key,
                last_item_key,
            } => {
                write!(f, "next_cursor.last_key mismatch at page {at_page}: ")?;
                match cursor_key {
                    Some(cursor_key) => {
                        write!(
                            f,
                            "cursor_key=({cursor_key}) last_item_key=({last_item_key})"
                        )
                    }
                    None => write!(f, "cursor_key=<none> last_item_key=({last_item_key})"),
                }
            }
            Self::DuplicateKeyInRun { key } => {
                write!(f, "duplicate key observed in run: ({key})")
            }
            Self::TooManyPages { max_pages } => {
                write!(f, "too many pages (max {max_pages})")
            }
            Self::TooManyItems { max_total_items } => {
                write!(f, "too many items collected (max {max_total_items})")
            }
            Self::DeterminismMismatch {
                at_index,
                run1,
                run2,
            } => {
                write!(
                    f,
                    "determinism mismatch at item index {at_index}: run1={run1} run2={run2}"
                )
            }
            Self::ResumeMismatch {
                restart_cursor_index,
                mode,
                at_index,
                expected,
                got,
            } => {
                write!(
                    f,
                    "resume mismatch (restart_cursor_index={restart_cursor_index}, mode={mode:?}) at suffix index {at_index}: expected={expected} got={got}"
                )
            }
            Self::ResumeLengthMismatch {
                restart_cursor_index,
                mode,
                expected_len,
                got_len,
            } => {
                write!(
                    f,
                    "resume length mismatch (restart_cursor_index={restart_cursor_index}, mode={mode:?}): expected_len={expected_len} got_len={got_len}"
                )
            }
            Self::ItemRefAppearsToContainSecret { pattern, item_ref } => {
                write!(
                    f,
                    "item_ref appears to contain secret substring: pattern=({pattern}) item_ref=({item_ref})"
                )
            }
        }
    }
}

impl std::error::Error for ConformanceError {}

#[cfg(test)]
#[path = "conformance_tests.rs"]
mod tests;

#![allow(dead_code)]

//! Conformance harness configuration and digest-only diagnostic vocabulary.
//!
//! The conformance harness validates that a connector implementation
//! satisfies the enumeration contract defined in the connector API module. A typical
//! conformance session:
//!
//! 1. Performs a **baseline** full enumeration, collecting
//!    [`ItemObservation`]s and cursor checkpoints into an
//!    [`EnumerationTrace`].
//! 2. Optionally performs a **comparison** run and checks determinism
//!    (item-by-item digest equality).
//! 3. Selects restart points from the baseline trace and performs
//!    **resume** runs under token perturbation ([`ResumeChecks`]),
//!    verifying that the suffix of items matches the baseline.
//! 4. Scans every `ItemRef` for forbidden byte patterns
//!    ([`SecretScanConfig`]) to catch accidental credential leakage.
//!
//! This module provides the types that parameterize and report on those
//! steps:
//!
//! - **Configuration**: strict-by-default harness knobs
//!   ([`ConformanceConfig`]) that control page limits, ordering policy,
//!   determinism expectations, resume-path perturbation, and secret scanning.
//! - **Observation types**: digest-only records for cross-run comparison
//!   ([`ItemObservation`], [`EnumerationTrace`]).
//! - **Error taxonomy**: a flat enum ([`ConformanceError`]) covering every
//!   failure mode from capability gates through secret-scan findings.
//!
//! ## Relationship to page validation
//!
//! Per-page structural checks (ordering, cursor membership, range bounds)
//! are delegated to [`super::page_validator::validate_page`]. This module
//! layers additional cross-page and cross-run checks on top: duplicate
//! detection, strict-increase enforcement, determinism comparison, and
//! resume-path suffix matching.
//!
//! ## Invariants
//!
//! - All diagnostic payloads use [`ToxicDigest`] -- no raw connector bytes
//!   appear in error messages or trace records.
//! - [`ToxicDigest`] and [`ItemObservation`] format as redacted, stable
//!   tokens suitable for log correlation.
//! - [`ConformanceConfig::default()`] is intentionally strict: connectors
//!   must explicitly opt out of checks they cannot satisfy.
//!
//! ## Trade-off
//!
//! [`ToxicDigest`] keeps full 32-byte hashes for equality and map/set keys,
//! while its `Display` output prints only the first 8 bytes as hex (16
//! characters). This preserves compact log lines while retaining precise
//! in-memory comparisons.

use std::fmt;
use std::num::NonZeroUsize;

use super::api::{ConnectorCapabilities, ErrorClass};
use super::page_validator::{PageValidationError, ToxicDigest};
use super::types::{Budgets, Cursor};

/// Default best-effort secret patterns that should not appear in `ItemRef`.
///
/// These are heuristics used by conformance checks to catch accidental
/// credential leakage in connector handles. The harness reports digest-only
/// diagnostics for matches.
///
/// Coverage includes: HTTP auth headers, AWS access keys, AWS signed
/// request parameters, GCP service-account identifiers, PEM/OpenSSH
/// private key markers, GitHub token prefixes (`ghp_`, `gho_`, `ghs_`,
/// `ghr_`), JWT Base64-encoded header prefix (`eyJ`), and common
/// database connection-string schemes.
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
    // GitHub token prefixes.
    b"ghp_",
    b"gho_",
    b"ghs_",
    b"ghr_",
    // JWT Base64-encoded header prefix.
    b"eyJ",
    // Narrower PEM key markers (supplement the generic `-----BEGIN `).
    b"-----BEGIN RSA PRIVATE",
    b"-----BEGIN OPENSSH",
    // Database connection-string schemes.
    b"postgres://",
    b"mongodb+srv://",
];

/// Whether repeated full enumeration runs are expected to produce identical
/// item sequences.
///
/// The harness uses this to decide whether to compare a second full run
/// against the baseline. Connectors backed by mutable or eventually-consistent
/// data sources should use [`BestEffort`](Self::BestEffort) to avoid spurious
/// failures from concurrent writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeterminismExpectation {
    /// Repeated full scans must produce identical [`ItemObservation`]
    /// sequences. The harness compares a second run element-by-element and
    /// reports [`ConformanceError::DeterminismMismatch`] on the first
    /// divergence.
    Deterministic,
    /// Determinism is not strictly required by caller policy.
    ///
    /// The harness records but does not fail on cross-run differences. This
    /// is appropriate for connectors over live, mutable data sources where
    /// concurrent modifications may change enumeration results between runs.
    BestEffort,
}

/// Resume-by-key checks toggled by the conformance harness.
///
/// The conformance harness tests a connector's ability to resume enumeration
/// using only the cursor `last_key` (without a valid pagination token). Each
/// flag independently enables a token perturbation scenario:
///
/// - **`drop_token`**: the harness removes the cursor's `token` field
///   entirely, leaving only `last_key`. The connector must resume from the
///   key position without the token.
/// - **`corrupt_token`**: the harness replaces the cursor's `token` with
///   random bytes. The connector must either fall back to key-based resume
///   or reject the corrupted token gracefully.
///
/// Keeping the controls separate allows callers to narrow failures to one
/// recovery path at a time.
///
/// Both flags default to `true` so connectors must explicitly opt out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResumeChecks {
    /// When `true`, test resume with the pagination token removed entirely.
    pub drop_token: bool,
    /// When `true`, test resume with the pagination token replaced by random bytes.
    pub corrupt_token: bool,
}

impl ResumeChecks {
    /// Iterates over the [`ResumeMode`] variants enabled by this configuration.
    ///
    /// Returns zero, one, or two items depending on which flags are set.
    /// Emission order is always `DropToken` before `CorruptToken`.
    pub fn modes(&self) -> impl Iterator<Item = ResumeMode> {
        self.drop_token
            .then_some(ResumeMode::DropToken)
            .into_iter()
            .chain(self.corrupt_token.then_some(ResumeMode::CorruptToken))
    }
}

impl Default for ResumeChecks {
    fn default() -> Self {
        Self {
            drop_token: true,
            corrupt_token: true,
        }
    }
}

/// Best-effort secret scan configuration for [`ItemRef`](super::ItemRef) bytes.
///
/// The harness performs a byte-substring search over every `ItemRef` emitted
/// during an enumeration run. A match triggers
/// [`ConformanceError::ItemRefAppearsToContainSecret`] with digest-only
/// diagnostics (no raw bytes are exposed).
///
/// This is a heuristic leak-detection surface. It is intentionally configurable
/// so tests can tune false-positive/false-negative trade-offs per connector.
/// Defaults enable scanning with [`DEFAULT_FORBIDDEN_ITEMREF_PATTERNS`] and
/// no additional canaries.
#[derive(Clone, Debug)]
pub struct SecretScanConfig {
    /// Global on/off switch for secret scanning. When `false`, the harness
    /// skips all substring and canary checks.
    pub enabled: bool,
    /// Byte substrings that should not appear in connector item references.
    /// Defaults to [`DEFAULT_FORBIDDEN_ITEMREF_PATTERNS`]. Callers can
    /// narrow or extend this list per connector to manage false positives.
    pub forbidden_substrings: Vec<&'static [u8]>,
    /// Full-byte canaries injected by tests for connector-specific leak
    /// checks. Unlike `forbidden_substrings` (which match common credential
    /// prefixes), canaries are exact secret values that a test plants in the
    /// connector's credential store and then verifies do not appear in
    /// enumerated handles.
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
/// During a baseline enumeration run the harness records a cursor checkpoint
/// after each page (stored in [`EnumerationTrace::cursors`]). Resume checks
/// then pick a subset of those checkpoints, perturb the token, and re-run
/// enumeration from each selected cursor. This enum controls how the subset
/// is chosen.
///
/// Index validation and out-of-range handling are owned by the harness;
/// invalid indices are silently clamped or skipped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestartPoints {
    /// Have the harness automatically choose up to `N` points spread
    /// evenly across the baseline run's cursor checkpoints. A value of
    /// `0` disables resume checks even when [`ResumeChecks`] flags are set.
    Auto(usize),
    /// Restart from specific cursor checkpoint indices (zero-based
    /// positions into [`EnumerationTrace::cursors`]).
    Explicit(&'static [usize]),
}

/// Conformance harness knobs.
///
/// Defaults are intentionally strict so connectors explicitly opt out of weaker
/// checks.
#[derive(Clone, Debug)]
pub struct ConformanceConfig {
    /// Hard cap on page requests per run. The harness stops and reports
    /// [`ConformanceError::TooManyPages`] when exceeded.
    pub max_pages: NonZeroUsize,
    /// Hard cap on collected items per run. The harness stops and reports
    /// [`ConformanceError::TooManyItems`] when exceeded.
    pub max_total_items: NonZeroUsize,
    /// [`Budgets`] forwarded to each `enumerate_page` call. Controls
    /// per-page item count, byte limit, and optional deadline.
    pub page_budgets: Budgets,
    /// When `true`, the harness requires strictly increasing keys within
    /// each page (no duplicate keys allowed). When `false`, non-decreasing
    /// order (as enforced by [`super::page_validator::validate_page`]) is
    /// sufficient.
    pub require_strict_key_order: bool,
    /// When `true`, non-empty pages must have
    /// `next_cursor.last_key == last_item.item_key`. This catches
    /// connectors that advance the cursor past the data they returned.
    pub require_cursor_eq_last_item: bool,
    /// Cross-run determinism policy. See [`DeterminismExpectation`].
    pub determinism: DeterminismExpectation,
    /// Which token-perturbation scenarios to exercise during resume checks.
    pub resume_checks: ResumeChecks,
    /// Secret-scan policy for connector `ItemRef` values.
    pub secret_scan: SecretScanConfig,
    /// How to select baseline cursor checkpoints for resume comparisons.
    pub restart_points: RestartPoints,
}

impl Default for ConformanceConfig {
    fn default() -> Self {
        Self {
            max_pages: NonZeroUsize::new(10_000)
                .expect("conformance default max_pages must be non-zero"),
            max_total_items: NonZeroUsize::new(1_000_000)
                .expect("conformance default max_total_items must be non-zero"),
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

/// Digest-only snapshot of one item observed during an enumeration run.
///
/// Two observations are compared element-by-element during determinism and
/// resume checks. The `key` digest identifies position (which item), while
/// `fingerprint` identifies content (what the item contained). A mismatch
/// in either field between runs constitutes a conformance failure.
///
/// `ItemObservation` is `Copy` (80 bytes: two [`ToxicDigest`] values at
/// 40 bytes each) and safe to store in bulk inside [`EnumerationTrace`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ItemObservation {
    /// BLAKE3 digest of the item's [`ItemKey`](super::ItemKey) bytes.
    pub key: ToxicDigest,
    /// BLAKE3 digest derived from item content (e.g., `item_ref` or a
    /// connector-specific content hash), used to detect content changes
    /// across runs even when the key remains stable.
    pub fingerprint: ToxicDigest,
}

impl fmt::Display for ItemObservation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "key=({}) fingerprint=({})", self.key, self.fingerprint)
    }
}

/// Trace captured from one full enumeration run.
///
/// The harness populates this incrementally: after each `enumerate_page` call
/// it appends one [`ItemObservation`] per returned item to `items`, pushes
/// the page's `next_cursor` onto `cursors`, and increments `pages`.
///
/// This is a passive record type: it does not enforce internal consistency
/// between `items`, `cursors`, and `pages`. In particular, `items.len()`
/// may be less than `pages * page_size` when pages return variable-length
/// results.
///
/// ## Field relationships
///
/// - `cursors.len() == pages` (one cursor checkpoint per page response).
/// - `items` contains every observed item across all pages, in encounter
///   order. Resume checks slice into this vector using cursor checkpoint
///   boundaries.
///
/// ## Memory
///
/// `ItemObservation` is 80 bytes (two `ToxicDigest` fields). At default
/// config limits (`max_total_items = 1_000_000`), the `items` vector alone
/// can reach ~76 MiB. `cursors` grows with `max_pages` but is typically
/// modest.
/// Callers should tune [`ConformanceConfig::max_pages`] and
/// [`ConformanceConfig::max_total_items`] when targeting connectors with
/// large datasets.
#[derive(Clone, Debug)]
pub struct EnumerationTrace {
    /// Item observations in encounter order across all pages.
    pub items: Vec<ItemObservation>,
    /// Cursor checkpoint after each page, in page order. `cursors[i]` is
    /// the `next_cursor` returned by the `i`-th `enumerate_page` call.
    /// Resume checks select restart points from this vector.
    pub cursors: Vec<Cursor>,
    /// Total number of page responses observed in the run. Always equals
    /// `cursors.len()` when the harness populates the trace.
    pub pages: usize,
}

/// Token perturbation mode applied during a resume check.
///
/// Appears in [`ConformanceError::ResumeMismatch`] and
/// [`ConformanceError::ResumeLengthMismatch`] to indicate which
/// perturbation scenario triggered the failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResumeMode {
    /// The cursor's pagination token was removed before restarting.
    /// The connector should fall back to key-based positioning.
    DropToken,
    /// The cursor's pagination token was replaced with random bytes.
    /// The connector should detect the invalid token and either reject
    /// it or fall back to key-based positioning.
    CorruptToken,
}

/// Conformance failure taxonomy.
///
/// Each variant represents a single, actionable failure. Variants are
/// ordered by the harness execution stage where they can occur:
///
/// 1. **Capability gate** -- connector does not advertise required features.
/// 2. **Per-page collection** -- `enumerate_page` errors, budget overruns,
///    and structural violations detected by
///    [`validate_page`](super::page_validator::validate_page).
/// 3. **Cross-page checks** -- strict ordering, cursor-last-item matching,
///    and duplicate key detection within a single run.
/// 4. **Run-level caps** -- page or item count exceeded.
/// 5. **Cross-run comparisons** -- determinism mismatch between two full runs.
/// 6. **Resume checks** -- suffix divergence after token perturbation.
/// 7. **Secret scan** -- forbidden pattern found in `ItemRef` bytes.
///
/// Implements [`std::error::Error`] as a leaf error (no `source()` chain).
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
    /// Page-level structural violation detected by
    /// [`validate_page`](super::page_validator::validate_page). The wrapped
    /// [`PageValidationError`] carries the specific rule violation and
    /// redacted diagnostic context.
    PageValidationFailed {
        /// Zero-based page index where violation occurred.
        at_page: usize,
        /// Specific page-validation diagnostic.
        err: PageValidationError,
    },
    /// Adjacent keys within a page are equal (non-decreasing but not
    /// strictly increasing). Only raised when
    /// [`ConformanceConfig::require_strict_key_order`] is `true`.
    NotStrictlyIncreasingWithinPage {
        /// Zero-based page index where violation occurred.
        at_page: usize,
        /// Index of the second key in the violating pair.
        at_index: usize,
        /// Previous key digest.
        prev_key: ToxicDigest,
        /// Next key digest.
        next_key: ToxicDigest,
    },
    /// Non-empty page returned a cursor key that differs from the last
    /// item key. Only raised when
    /// [`ConformanceConfig::require_cursor_eq_last_item`] is `true`.
    CursorDoesNotMatchLastItem {
        /// Zero-based page index where violation occurred.
        at_page: usize,
        /// Returned cursor key digest (or `None`).
        cursor_key: Option<ToxicDigest>,
        /// Last item key digest from the same page.
        last_item_key: ToxicDigest,
    },
    /// Key digest appeared more than once in a single run.
    DuplicateKeyInRun {
        /// Duplicate key digest.
        key: ToxicDigest,
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
    /// Two full enumeration runs produced different [`ItemObservation`]s at
    /// the same index. Only raised when
    /// [`ConformanceConfig::determinism`] is
    /// [`Deterministic`](DeterminismExpectation::Deterministic).
    DeterminismMismatch {
        /// Index into the compared item sequences where divergence was first detected.
        at_index: usize,
        /// Observation from baseline run.
        run1: ItemObservation,
        /// Observation from comparison run.
        run2: ItemObservation,
    },
    /// A resume run from a baseline cursor checkpoint produced a different
    /// item at the same suffix position. The baseline suffix (items after
    /// the restart cursor) and the resume run's output should match
    /// element-by-element when the connector correctly resumes from key.
    ResumeMismatch {
        /// Index into [`EnumerationTrace::cursors`] identifying the restart point.
        restart_cursor_index: usize,
        /// Token perturbation mode that triggered this mismatch.
        mode: ResumeMode,
        /// Zero-based index within the compared suffix where divergence occurred.
        at_index: usize,
        /// Expected observation from the baseline suffix.
        expected: ItemObservation,
        /// Actual observation from the resume run.
        got: ItemObservation,
    },
    /// A resume run produced a different total number of items than the
    /// baseline suffix. This is checked before element-by-element
    /// comparison.
    ResumeLengthMismatch {
        /// Index into [`EnumerationTrace::cursors`] identifying the restart point.
        restart_cursor_index: usize,
        /// Token perturbation mode that triggered this mismatch.
        mode: ResumeMode,
        /// Number of items in the baseline suffix (items after the restart cursor).
        expected_len: usize,
        /// Number of items the resume run actually produced.
        got_len: usize,
    },
    /// Secret-scan heuristic found a forbidden pattern inside an `ItemRef`.
    ItemRefAppearsToContainSecret {
        /// Digest of the matched pattern/canary bytes.
        pattern: ToxicDigest,
        /// Digest of the offending `ItemRef` bytes.
        item_ref: ToxicDigest,
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

/// Leaf error: conformance failures do not wrap an underlying cause.
/// The `Display` output is log-safe (all byte content is redacted through
/// [`ToxicDigest`]).
impl std::error::Error for ConformanceError {}

#[cfg(test)]
#[path = "conformance_tests.rs"]
mod tests;

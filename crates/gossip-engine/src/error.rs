//! Error types for the scanner-core boundary.
//!
//! Errors are split into two enums that map to distinct lifecycle phases:
//!
//! - [`ScannerCoreBuildError`] — configuration validation at construction time.
//!   Catching invalid config here means every subsequent [`ScannerCore`] method
//!   can assume its config invariants hold without re-checking.
//!
//! - [`ScannerCoreError`] — runtime contract violations detected when
//!   processing page or stream scan requests. These guard structural
//!   preconditions (slice length agreement, page ordering) that callers must
//!   satisfy but that cannot be enforced at the type level.
//!
//! Both enums are `Copy + Eq` and carry enough context (page number, index,
//! lengths) for callers to produce actionable diagnostics without needing the
//! original request.
//!
//! [`ScannerCore`]: crate::ScannerCore

use std::fmt;

/// Configuration validation failure raised by [`ScannerCoreBuilder::build`] or
/// [`ScannerCore::new`].
///
/// Catching invalid config at construction ensures that scan entrypoints
/// never need to re-validate builder parameters on every call.
///
/// [`ScannerCoreBuilder::build`]: crate::ScannerCoreBuilder::build
/// [`ScannerCore::new`]: crate::ScannerCore::new
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScannerCoreBuildError {
    /// The per-page findings cap must be at least 1; a zero cap would silently
    /// suppress all findings with no truncation diagnostic.
    ZeroMaxFindingsPerPage,
}

impl fmt::Display for ScannerCoreBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroMaxFindingsPerPage => {
                f.write_str("max_findings_per_page must be greater than zero")
            }
        }
    }
}

impl std::error::Error for ScannerCoreBuildError {}

/// Runtime contract violations from [`ScannerCore`] scan entrypoints.
///
/// Each variant represents a precondition that callers must uphold but that
/// cannot be enforced through Rust's type system alone. All variants carry
/// enough positional context (page number, item index, lengths) for callers to
/// map the error back to the offending input without retaining the full request.
///
/// [`ScannerCore`]: crate::ScannerCore
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScannerCoreError {
    /// The optional `item_bytes` slice was `Some` but its length did not equal
    /// the `items` slice length. Because the scanner zips these two slices
    /// positionally, a length mismatch would cause silent data misalignment.
    ItemBytesLenMismatch {
        page_num: u64,
        items: usize,
        item_bytes: usize,
    },
    /// A single payload slice was too large to track as `u64` byte count.
    /// In practice this is unreachable on 64-bit targets, but the check
    /// prevents silent truncation on hypothetical platforms where
    /// `usize > u64`.
    PayloadLengthOverflow {
        page_num: u64,
        item_index: usize,
        payload_len: usize,
    },
    /// Stream pages arrived out of order. The scanner requires strictly
    /// increasing page numbers so that cross-page dedupe state and
    /// stream-level summaries remain well-defined.
    NonMonotonicPageNum {
        previous_page_num: u64,
        page_num: u64,
    },
}

impl fmt::Display for ScannerCoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ItemBytesLenMismatch {
                page_num,
                items,
                item_bytes,
            } => write!(
                f,
                "page {page_num}: item_bytes length mismatch (items={items}, item_bytes={item_bytes})"
            ),
            Self::PayloadLengthOverflow {
                page_num,
                item_index,
                payload_len,
            } => write!(
                f,
                "page {page_num} item {item_index}: payload length {payload_len} overflows u64"
            ),
            Self::NonMonotonicPageNum {
                previous_page_num,
                page_num,
            } => write!(
                f,
                "non-monotonic stream page order: previous={previous_page_num}, current={page_num}"
            ),
        }
    }
}

impl std::error::Error for ScannerCoreError {}

#[cfg(test)]
#[path = "error_tests.rs"]
mod tests;

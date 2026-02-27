//! Page-level connector contract diagnostic types.
//!
//! This module is intentionally limited to diagnostic infrastructure intended
//! for page validators. It does not implement validation itself.
//!
//! ## Invariant surface
//!
//! The diagnostics here encode failures for page-level connector invariants:
//!
//! - range contract validity for page specs,
//! - cursor and item membership within spec bounds,
//! - item ordering and cursor-relative progression,
//! - continuation-cursor monotonicity and presence rules,
//! - empty-page cursor stability.
//!
//! ## Toxic-data policy
//!
//! Connector keys, refs, and tokens are toxic bytes. Diagnostics from this
//! module are hash-only and length-based; they never include raw byte payloads.
//! `Debug`/`Display` output is safe for logs and metrics.

use std::fmt;

use super::{ItemKey, ScanItem};

/// A view of a page item that exposes its ordered key.
///
/// This keeps validation logic generic over both production connector items
/// and lightweight test fixtures, without coupling validation internals to a
/// specific item carrier type.
pub trait PageItem<K> {
    fn item_key(&self) -> &K;
}

impl PageItem<ItemKey> for ScanItem {
    fn item_key(&self) -> &ItemKey {
        self.item_key()
    }
}

/// A hash-only representation of toxic bytes.
///
/// Safe for errors/logs/metrics; never contains raw input bytes.
///
/// `ToxicDigest` stores payload length plus a BLAKE3 digest for stable
/// equality and diagnostics. Formatted output intentionally emits only a short
/// digest prefix to keep logs compact while preserving correlation value.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ToxicDigest {
    len: usize,
    hash: [u8; 32],
}

impl ToxicDigest {
    /// Digest toxic bytes into a redacted, fixed-size representation.
    #[must_use]
    pub fn of_bytes(bytes: &[u8]) -> Self {
        let hash = blake3::hash(bytes);
        Self {
            len: bytes.len(),
            hash: *hash.as_bytes(),
        }
    }

    /// Digest any key-like value that can be viewed as bytes.
    #[must_use]
    pub fn of<K: AsRef<[u8]> + ?Sized>(k: &K) -> Self {
        Self::of_bytes(k.as_ref())
    }
}

impl fmt::Display for ToxicDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "len={}, hash=", self.len)?;
        for b in &self.hash[..8] {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for ToxicDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// Identifies which cursor a violation refers to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CursorWhich {
    /// The caller-provided input cursor for this page request.
    Input,
    /// The connector-returned continuation cursor for the next request.
    Next,
}

/// The page-validation rule that was violated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageValidationViolation {
    /// The declared page spec bounds are internally inconsistent.
    SpecRangeInvalid,
    /// The input cursor key is outside the allowed cursor range.
    InputCursorOutOfRange,
    /// The next cursor key is outside the allowed cursor range.
    NextCursorOutOfRange,
    /// An emitted item key is outside the allowed item range.
    ItemKeyOutOfRange,
    /// Returned items are not strictly ordered by key.
    ItemsNotOrdered,
    /// The first returned item does not advance strictly past the input cursor.
    ItemsNotAfterCursor,
    /// Items were returned but `next_cursor.last_key` was missing.
    NextCursorMissing,
    /// `next_cursor.last_key` is behind the final returned item key.
    NextCursorBehindLastItem,
    /// The continuation cursor moved backwards relative to the input cursor.
    CursorRegressed,
    /// An empty page changed cursor state when it should have remained stable.
    EmptyPageCursorAdvanced,
}

/// Hash-only details for page-validation violations.
///
/// Each variant carries only redacted digests and indices. No raw connector
/// bytes are preserved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PageValidationDetails {
    /// Details for [`PageValidationViolation::SpecRangeInvalid`].
    Spec {
        /// Inclusive lower bound from the page spec.
        start: ToxicDigest,
        /// Upper bound from the page spec.
        end: ToxicDigest,
    },
    /// Details for cursor-bound checks.
    CursorOutOfRange {
        /// Which cursor violated the bound.
        which: CursorWhich,
        /// Offending cursor key digest.
        key: ToxicDigest,
        /// Inclusive lower bound for cursor keys.
        start: ToxicDigest,
        /// Inclusive upper bound for cursor keys.
        end: ToxicDigest,
    },
    /// Details for item-bound checks.
    ItemOutOfRange {
        /// Index of the first offending item in the page payload.
        index: usize,
        /// Offending item key digest.
        key: ToxicDigest,
        /// Inclusive lower bound for item keys.
        start: ToxicDigest,
        /// Exclusive upper bound for item keys.
        end: ToxicDigest,
    },
    /// Details for local ordering failures between adjacent items.
    NotOrdered {
        /// Index of the later item in the offending pair.
        index: usize,
        /// Digest of the previous item key.
        prev: ToxicDigest,
        /// Digest of the current item key.
        next: ToxicDigest,
    },
    /// Details for the "items must advance past input cursor" rule.
    NotAfterCursor {
        /// Input cursor digest.
        cursor: ToxicDigest,
        /// Digest of the first returned item key.
        first_item: ToxicDigest,
    },
    /// Details for `next_cursor.last_key` lagging behind returned data.
    NextCursorBehindLastItem {
        /// Digest of the returned continuation cursor key.
        next_cursor: ToxicDigest,
        /// Digest of the last item key in the page.
        last_item: ToxicDigest,
    },
    /// Details for cursor monotonicity failures.
    CursorRegressed {
        /// Input cursor digest.
        input: ToxicDigest,
        /// Next cursor digest.
        next: ToxicDigest,
    },
    /// Details for cursor movement on empty pages.
    EmptyCursorAdvanced {
        /// Input cursor digest (if present).
        input: Option<ToxicDigest>,
        /// Next cursor digest (if present).
        next: Option<ToxicDigest>,
    },
    /// Details for missing continuation cursor on non-empty pages.
    NextCursorMissing,
}

/// Structured page-validation error.
///
/// `violation` is the stable machine-facing classifier. `details` carries
/// redacted context for debugging and metrics.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PageValidationError {
    /// High-level violated rule identifier.
    pub violation: PageValidationViolation,
    /// Redacted violation context payload.
    pub details: PageValidationDetails,
}

impl fmt::Display for PageValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use PageValidationDetails as D;
        use PageValidationViolation as V;

        match (&self.violation, &self.details) {
            (V::SpecRangeInvalid, D::Spec { start, end }) => {
                write!(f, "invalid spec range: start={start}, end={end}")
            }
            (V::InputCursorOutOfRange, D::CursorOutOfRange { key, start, end, .. }) => {
                write!(
                    f,
                    "input cursor out of range: key={key}, allowed=[{start}, {end}]"
                )
            }
            (V::NextCursorOutOfRange, D::CursorOutOfRange { key, start, end, .. }) => {
                write!(
                    f,
                    "next cursor out of range: key={key}, allowed=[{start}, {end}]"
                )
            }
            (V::ItemKeyOutOfRange, D::ItemOutOfRange { index, key, start, end }) => {
                write!(
                    f,
                    "item key out of range at index {index}: key={key}, allowed=[{start}, {end})"
                )
            }
            (V::ItemsNotOrdered, D::NotOrdered { index, prev, next }) => {
                write!(
                    f,
                    "items not ordered at index {index}: prev={prev}, next={next}"
                )
            }
            (V::ItemsNotAfterCursor, D::NotAfterCursor { cursor, first_item }) => {
                write!(
                    f,
                    "items must start strictly after input cursor: cursor={cursor}, first_item={first_item}"
                )
            }
            (V::NextCursorMissing, D::NextCursorMissing) => {
                write!(f, "next_cursor.last_key is missing but items were returned")
            }
            (
                V::NextCursorBehindLastItem,
                D::NextCursorBehindLastItem {
                    next_cursor,
                    last_item,
                },
            ) => {
                write!(
                    f,
                    "next_cursor.last_key is behind last item: next_cursor={next_cursor}, last_item={last_item}"
                )
            }
            (V::CursorRegressed, D::CursorRegressed { input, next }) => {
                write!(f, "cursor regressed: input={input}, next={next}")
            }
            (V::EmptyPageCursorAdvanced, D::EmptyCursorAdvanced { input, next }) => {
                write!(
                    f,
                    "empty page advanced cursor: input={input:?}, next={next:?}"
                )
            }
            // Preserve a stable, non-panicking fallback if caller code builds an
            // inconsistent `(violation, details)` pair.
            _ => write!(f, "page validation violation: {:?}", self.violation),
        }
    }
}

impl std::error::Error for PageValidationError {}

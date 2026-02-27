//! Page-level connector contract diagnostic types.
//!
//! This module provides both the error vocabulary and pure validation helpers
//! for connector page results.
//!
//! ## Invariant surface
//!
//! The diagnostics encode failures for these page-level connector invariants:
//!
//! - **Spec range validity** -- the declared key bounds of a page spec must be
//!   internally consistent (`start <= end`) when both bounds are present.
//! - **Cursor membership** -- both the caller-supplied input cursor and the
//!   connector-returned next cursor must fall within the spec's cursor range.
//! - **Item membership** -- every emitted item key must fall within the spec's
//!   item range.
//! - **Item ordering** -- items must be in non-decreasing key order
//!   (lexicographic [`ItemKey`] order).
//! - **Cursor-relative progression** -- the first item must be strictly greater
//!   than the input cursor key, and the next cursor key must be >= the last
//!   item key.
//! - **Cursor monotonicity** -- the connector-returned next cursor must not
//!   regress behind the input cursor.
//! - **Continuation cursor presence** -- a non-empty page must carry a next
//!   cursor with a `last_key`.
//! - **Empty-page cursor stability** -- an empty page must not advance the
//!   cursor state.
//!
//! Empty `start`/`end` byte slices represent unbounded lower/upper limits.
//!
//! ## Range conventions and trade-off
//!
//! This validator intentionally uses two related bound conventions:
//!
//! - Item keys are checked against a half-open range `[start, end)`.
//! - Cursor keys are checked against a closed range `[start, end]`.
//!
//! Allowing `cursor == end` catches obvious out-of-range regressions while
//! remaining permissive for connectors that park continuation state at the
//! upper boundary. Callers that require strict half-open cursor membership must
//! enforce that policy separately.
//!
//! ## Error anatomy
//!
//! Each [`PageValidationError`] pairs a [`PageValidationViolation`] (a thin,
//! `Copy`-able discriminant for programmatic matching) with a
//! [`PageValidationDetails`] variant carrying redacted diagnostic context.
//! This two-layer design lets callers branch on the violation kind cheaply
//! while still having enough context for human-readable error messages and
//! metrics labels.
//!
//! ## Toxic-data policy
//!
//! Connector keys, refs, and tokens are toxic bytes. Diagnostics from this
//! module are hash-only and length-based; they never include raw byte payloads.
//! All byte content is redacted through [`ToxicDigest`], which stores the
//! original length and a full BLAKE3 hash but displays only a truncated
//! prefix (16 hex characters = first 8 bytes of the hash). `Debug` and
//! `Display` output is safe for logs and metrics.
//!
//! Note: the connector `types.rs` module uses a different display convention
//! for its toxic-byte wrappers (8 hex characters from first 4 bytes).
//! `ToxicDigest` uses a longer prefix because diagnostic errors benefit from
//! higher collision resistance when correlating across log lines.

use std::fmt;

use crate::coordination::ShardSpec;

use super::{Cursor, ItemKey, ScanItem};

/// A view of a page item that exposes its ordered key.
///
/// Validation logic needs to compare item keys for ordering and range
/// membership, but should not depend on the concrete item carrier. This trait
/// abstracts over both production [`ScanItem`] values and lightweight test
/// fixtures (e.g., a newtype around `Vec<u8>`), keeping the validator
/// generic.
///
/// `K` is the key type used for ordering comparisons -- typically [`ItemKey`]
/// in production, but tests may substitute a simpler ordered byte wrapper.
pub trait PageItem<K: ?Sized> {
    /// Returns a reference to the item's ordering key.
    fn item_key(&self) -> &K;
}

/// Delegates to [`ScanItem::item_key`], the inherent accessor.
impl PageItem<ItemKey> for ScanItem {
    fn item_key(&self) -> &ItemKey {
        self.item_key()
    }
}

/// Provides byte-level key access for [`validate_page`], which projects
/// cursor keys through `ItemKey::as_ref()` to `&[u8]` in order to unify
/// the `K` parameter across cursors and items. Without this impl the
/// generic `validate_page_range::<[u8], _>` instantiation cannot treat
/// `ScanItem` as a [`PageItem`].
impl PageItem<[u8]> for ScanItem {
    fn item_key(&self) -> &[u8] {
        ScanItem::item_key(self).as_ref()
    }
}

/// A hash-only, fixed-size representation of toxic bytes.
///
/// Connector keys and cursors are untrusted external data ("toxic bytes")
/// that must never appear raw in logs, error messages, or metrics. Instead
/// of carrying the original payload, `ToxicDigest` stores just:
///
/// - `len`: the byte length of the original input, and
/// - `hash`: a full 32-byte BLAKE3 digest.
///
/// ## Display format
///
/// Both `Display` and `Debug` emit the same compact, single-line form:
///
/// ```text
/// len=42, hash=0a1b2c3d4e5f6a7b
/// ```
///
/// Only the first 8 bytes of the hash are printed (16 hex characters),
/// which is enough for log-line correlation without bloating output.
///
/// ## Equality semantics
///
/// `PartialEq` and `Eq` compare the **full** 32-byte hash (plus length),
/// not just the truncated display prefix. Two digests that display
/// identically are overwhelmingly likely to be equal, but equality is
/// always decided on the complete hash.
///
/// ## Copy semantics
///
/// `ToxicDigest` is `Copy` (40 bytes on 64-bit targets). Error types in
/// this module embed digests by value, avoiding indirection for what are
/// fundamentally small, immutable tokens.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ToxicDigest {
    /// Byte length of the original input. Preserved so diagnostics can
    /// distinguish zero-length sentinels from short keys without revealing
    /// content.
    len: usize,
    /// Full 32-byte BLAKE3 digest of the original input. Only the first
    /// 8 bytes are shown in display output; equality uses all 32.
    hash: [u8; 32],
}

impl ToxicDigest {
    /// Digest a raw byte slice into a redacted, fixed-size representation.
    ///
    /// This is the low-level entry point. Prefer [`of`](Self::of) when working
    /// with typed wrappers like [`ItemKey`] that implement `AsRef<[u8]>`.
    #[must_use]
    pub fn of_bytes(bytes: &[u8]) -> Self {
        let hash = blake3::hash(bytes);
        Self {
            len: bytes.len(),
            hash: *hash.as_bytes(),
        }
    }

    /// Digest any value that can be viewed as bytes.
    ///
    /// This is the ergonomic entry point for typed connector keys and cursors.
    /// The `?Sized` bound allows passing both owned wrappers (`&ItemKey`) and
    /// plain slices (`&[u8]`) without an extra `.as_ref()` at the call site.
    #[must_use]
    pub fn of<K: AsRef<[u8]> + ?Sized>(k: &K) -> Self {
        Self::of_bytes(k.as_ref())
    }
}

impl fmt::Display for ToxicDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "len={}, hash=", self.len)?;
        // First 8 bytes => 16 hex characters. Enough for correlation, short
        // enough that multi-field error lines stay readable.
        for b in &self.hash[..8] {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

/// Delegates to `Display` so that `{:?}` formatting in error chains and
/// `Option<ToxicDigest>` debug output stays log-safe and compact.
impl fmt::Debug for ToxicDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// Identifies which cursor a violation refers to.
///
/// This discriminant exists because
/// [`PageValidationDetails::CursorOutOfRange`] is shared between the
/// `InputCursorOutOfRange` and `NextCursorOutOfRange` violations. Embedding
/// `CursorWhich` in the details variant avoids duplicating the
/// `{key, start, end}` field set while preserving full diagnostic specificity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CursorWhich {
    /// The caller-provided input cursor for this page request.
    Input,
    /// The connector-returned continuation cursor for the next request.
    Next,
}

/// The page-validation rule that was violated.
///
/// This is a thin, `Copy`-able discriminant designed for programmatic
/// matching and metrics labeling. It intentionally carries no payload --
/// all diagnostic context lives in the companion [`PageValidationDetails`]
/// variant inside [`PageValidationError`].
///
/// Variants are grouped by concern (spec, cursor membership, item checks,
/// and cursor progression). Runtime validation order is defined by
/// [`validate_page_range`], not by enum declaration order.
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
    /// Returned items are not in non-decreasing key order.
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

/// Redacted diagnostic details for page-validation violations.
///
/// Each variant carries the minimum context needed to diagnose a specific
/// class of failure: redacted key digests ([`ToxicDigest`]), positional
/// indices, and range bounds. No raw connector bytes are preserved.
///
/// Some variants serve multiple [`PageValidationViolation`] kinds. For
/// example, [`CursorOutOfRange`](Self::CursorOutOfRange) is used by both
/// `InputCursorOutOfRange` and `NextCursorOutOfRange`, distinguished by
/// the embedded [`CursorWhich`] field. This keeps the variant count small
/// while preserving full diagnostic specificity.
///
/// The range bound conventions follow the page spec contract:
/// - **Cursor ranges** are inclusive on both ends: `[start, end]`.
/// - **Item ranges** are inclusive-exclusive: `[start, end)`.
///
/// These conventions are reflected in the `Display` output of
/// [`PageValidationError`], which uses `[start, end]` for cursor ranges
/// and `[start, end)` for item ranges.
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

/// Structured page-validation error combining a rule discriminant with
/// redacted diagnostic context.
///
/// ## Two-field design
///
/// - `violation`: a `Copy`-able [`PageValidationViolation`] discriminant for
///   programmatic dispatch, metrics counters, and alert routing.
/// - `details`: a [`PageValidationDetails`] variant with the redacted byte
///   digests and indices needed to produce a human-readable error message.
///
/// ## Display output
///
/// `Display` produces a single-line, log-safe message that names the violated
/// rule and includes all redacted fields from the details variant. If the
/// `(violation, details)` pair is inconsistent (which should not happen under
/// normal use), the `Display` impl falls back to a generic message using the
/// violation's `Debug` representation rather than panicking.
///
/// ## Error trait
///
/// Implements [`std::error::Error`] with no `source()` chain, since page
/// validation failures are leaf errors -- they do not wrap an underlying cause.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PageValidationError {
    /// The violated rule, suitable for `match`-based dispatch and metrics labels.
    pub violation: PageValidationViolation,
    /// Redacted diagnostic context for the violation.
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
            (
                V::InputCursorOutOfRange,
                D::CursorOutOfRange {
                    key, start, end, ..
                },
            ) => {
                write!(
                    f,
                    "input cursor out of range: key={key}, allowed=[{start}, {end}]"
                )
            }
            (
                V::NextCursorOutOfRange,
                D::CursorOutOfRange {
                    key, start, end, ..
                },
            ) => {
                write!(
                    f,
                    "next cursor out of range: key={key}, allowed=[{start}, {end}]"
                )
            }
            (
                V::ItemKeyOutOfRange,
                D::ItemOutOfRange {
                    index,
                    key,
                    start,
                    end,
                },
            ) => {
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

/// Validate one connector page against ordering, membership, and cursor rules.
///
/// `start`/`end` define the shard range, with empty slices treated as
/// unbounded boundaries. Validation runs in a fixed order and returns on the
/// first failure:
///
/// 1. range sanity (`start <= end` for bounded ranges),
/// 2. input/next cursor membership,
/// 3. item membership,
/// 4. local item ordering,
/// 5. empty-page cursor stability,
/// 6. non-empty page requires `next_last_key`,
/// 7. first item must be strictly after `input_last_key`,
/// 8. next cursor must not regress behind input cursor,
/// 9. next cursor must be at least the last item key.
///
/// ## Range semantics
///
/// - Item keys are validated in `[start, end)`.
/// - Cursor keys are validated in `[start, end]`.
///
/// This asymmetry is deliberate: item membership follows shard half-open
/// semantics, while cursor checks stay slightly more permissive at the upper
/// boundary.
///
/// ## Comparison semantics
///
/// All ordering and membership comparisons operate on byte-level
/// representations (`key.as_ref()` slices), not on `K`'s `Ord` impl
/// directly. The `K: Ord` bound serves as a contract constraint -- it
/// prevents callers from accidentally instantiating the validator with an
/// unordered type -- but the actual comparison is always byte-lexicographic.
/// For the concrete types in this crate (`ItemKey`, `[u8]`, `Vec<u8>`),
/// byte-lexicographic order and `Ord` agree.
///
/// ## Performance
///
/// Validation is allocation-free on the success path. Toxic hashing is
/// performed only while constructing error payloads.
///
/// # Errors
///
/// Returns the first [`PageValidationError`] in the validation order listed
/// above.
#[allow(clippy::result_large_err)]
pub fn validate_page_range<K, I>(
    start: &K,
    end: &K,
    input_last_key: Option<&K>,
    items: &[I],
    next_last_key: Option<&K>,
) -> Result<(), PageValidationError>
where
    K: Ord + AsRef<[u8]> + ?Sized,
    I: PageItem<K>,
{
    let start_bytes = start.as_ref();
    let end_bytes = end.as_ref();
    let start_unbounded = start_bytes.is_empty();
    let end_unbounded = end_bytes.is_empty();

    // (a) Spec sanity: start <= end for bounded ranges.
    if !start_unbounded && !end_unbounded && start_bytes > end_bytes {
        return Err(PageValidationError {
            violation: PageValidationViolation::SpecRangeInvalid,
            details: PageValidationDetails::Spec {
                start: ToxicDigest::of(start),
                end: ToxicDigest::of(end),
            },
        });
    }

    // (b) Cursor range: input + next cursor keys must be in [start, end].
    let cursor_in_range = |key: &K| {
        let key_bytes = key.as_ref();
        (start_unbounded || key_bytes >= start_bytes) && (end_unbounded || key_bytes <= end_bytes)
    };

    if let Some(input) = input_last_key
        && !cursor_in_range(input)
    {
        return Err(PageValidationError {
            violation: PageValidationViolation::InputCursorOutOfRange,
            details: PageValidationDetails::CursorOutOfRange {
                which: CursorWhich::Input,
                key: ToxicDigest::of(input),
                start: ToxicDigest::of(start),
                end: ToxicDigest::of(end),
            },
        });
    }

    if let Some(next) = next_last_key
        && !cursor_in_range(next)
    {
        return Err(PageValidationError {
            violation: PageValidationViolation::NextCursorOutOfRange,
            details: PageValidationDetails::CursorOutOfRange {
                which: CursorWhich::Next,
                key: ToxicDigest::of(next),
                start: ToxicDigest::of(start),
                end: ToxicDigest::of(end),
            },
        });
    }

    // (c) Membership: every item key must be in [start, end).
    for (index, item) in items.iter().enumerate() {
        let key = item.item_key();
        let key_bytes = key.as_ref();
        let in_range = (start_unbounded || key_bytes >= start_bytes)
            && (end_unbounded || key_bytes < end_bytes);
        if in_range {
            continue;
        }
        return Err(PageValidationError {
            violation: PageValidationViolation::ItemKeyOutOfRange,
            details: PageValidationDetails::ItemOutOfRange {
                index,
                key: ToxicDigest::of(key),
                start: ToxicDigest::of(start),
                end: ToxicDigest::of(end),
            },
        });
    }

    // (d) Ordering: item keys must be non-decreasing.
    // Sliding-window comparison: seed `prev` with the first item key, then
    // iterate from index 1, comparing each item against its predecessor.
    let mut prev = items.first().map(PageItem::item_key);
    for (index, item) in items.iter().enumerate().skip(1) {
        let next = item.item_key();
        if let Some(prev_key) = prev
            && prev_key.as_ref() > next.as_ref()
        {
            return Err(PageValidationError {
                violation: PageValidationViolation::ItemsNotOrdered,
                details: PageValidationDetails::NotOrdered {
                    index,
                    prev: ToxicDigest::of(prev_key),
                    next: ToxicDigest::of(next),
                },
            });
        }
        prev = Some(next);
    }

    // (e) Empty-page rule: cursor must not advance.
    // The `!=` compares Option<&K> by value (K: PartialEq), not by pointer
    // identity, so `Some(&"a") != Some(&"a")` is false as expected.
    if items.is_empty() && input_last_key != next_last_key {
        return Err(PageValidationError {
            violation: PageValidationViolation::EmptyPageCursorAdvanced,
            details: PageValidationDetails::EmptyCursorAdvanced {
                input: input_last_key.map(ToxicDigest::of),
                next: next_last_key.map(ToxicDigest::of),
            },
        });
    }

    // (f) Next cursor exists: non-empty pages must include next_last_key.
    if !items.is_empty() && next_last_key.is_none() {
        return Err(PageValidationError {
            violation: PageValidationViolation::NextCursorMissing,
            details: PageValidationDetails::NextCursorMissing,
        });
    }

    // (g) Items after cursor: first item must be strictly greater than input cursor.
    if let (Some(input), Some(first_item)) = (input_last_key, items.first()) {
        let first_key = first_item.item_key();
        if first_key.as_ref() <= input.as_ref() {
            return Err(PageValidationError {
                violation: PageValidationViolation::ItemsNotAfterCursor,
                details: PageValidationDetails::NotAfterCursor {
                    cursor: ToxicDigest::of(input),
                    first_item: ToxicDigest::of(first_key),
                },
            });
        }
    }

    // (h) Cursor monotonicity: next cursor must not move behind input cursor.
    if let (Some(input), Some(next)) = (input_last_key, next_last_key)
        && next.as_ref() < input.as_ref()
    {
        return Err(PageValidationError {
            violation: PageValidationViolation::CursorRegressed,
            details: PageValidationDetails::CursorRegressed {
                input: ToxicDigest::of(input),
                next: ToxicDigest::of(next),
            },
        });
    }

    // (i) Cursor consistency: next cursor must be >= last item key.
    if let (Some(next), Some(last_item)) = (next_last_key, items.last()) {
        let last_key = last_item.item_key();
        if next.as_ref() < last_key.as_ref() {
            return Err(PageValidationError {
                violation: PageValidationViolation::NextCursorBehindLastItem,
                details: PageValidationDetails::NextCursorBehindLastItem {
                    next_cursor: ToxicDigest::of(next),
                    last_item: ToxicDigest::of(last_key),
                },
            });
        }
    }

    Ok(())
}

/// Validate a concrete connector scan page against a [`ShardSpec`] and cursors.
///
/// This is a thin adapter over [`validate_page_range`] for the common connector
/// runtime types (`ShardSpec`, [`Cursor`], and [`ScanItem`]). It does not add
/// additional policy checks; callers get the same invariant set, range
/// conventions, and first-failure behavior as [`validate_page_range`].
///
/// # Errors
///
/// Forwards any [`PageValidationError`] produced by [`validate_page_range`].
#[allow(clippy::result_large_err)]
pub fn validate_page(
    spec: &ShardSpec,
    input_cursor: &Cursor,
    items: &[ScanItem],
    next_cursor: &Cursor,
) -> Result<(), PageValidationError> {
    // ShardSpec returns `&[u8]` for range bounds, and cursor keys are
    // projected through `ItemKey::as_ref()` to `&[u8]`, so the generic
    // instantiation is `validate_page_range::<[u8], ScanItem>`. This
    // requires `ScanItem: PageItem<[u8]>` (see the impl above).
    validate_page_range(
        spec.key_range_start(),
        spec.key_range_end(),
        input_cursor.last_key().map(|key| key.as_ref()),
        items,
        next_cursor.last_key().map(|key| key.as_ref()),
    )
}

#[cfg(test)]
mod tests {
    use super::{PageItem, PageValidationViolation, validate_page_range};

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct Item {
        k: Vec<u8>,
    }

    impl PageItem<Vec<u8>> for Item {
        fn item_key(&self) -> &Vec<u8> {
            &self.k
        }
    }

    fn key(bytes: &[u8]) -> Vec<u8> {
        bytes.to_vec()
    }

    fn item(bytes: &[u8]) -> Item {
        Item { k: key(bytes) }
    }

    #[test]
    fn rejects_out_of_range_item_key() {
        let start = key(b"a");
        let end = key(b"c");
        let next = key(b"c");
        let items = vec![item(b"c")];

        let err = validate_page_range(&start, &end, None, &items, Some(&next)).unwrap_err();
        assert_eq!(err.violation, PageValidationViolation::ItemKeyOutOfRange);
    }

    #[test]
    fn rejects_unsorted_items() {
        let start = key(b"a");
        let end = key(b"z");
        let next = key(b"b");
        let items = vec![item(b"b"), item(b"a")];

        let err = validate_page_range(&start, &end, None, &items, Some(&next)).unwrap_err();
        assert_eq!(err.violation, PageValidationViolation::ItemsNotOrdered);
    }

    #[test]
    fn rejects_item_not_after_cursor() {
        let start = key(b"a");
        let end = key(b"z");
        let input = key(b"b");
        let next = key(b"b");
        let items = vec![item(b"b")];

        let err = validate_page_range(&start, &end, Some(&input), &items, Some(&next)).unwrap_err();
        assert_eq!(err.violation, PageValidationViolation::ItemsNotAfterCursor);
    }

    #[test]
    fn rejects_next_cursor_behind_last_item() {
        let start = key(b"a");
        let end = key(b"z");
        let next = key(b"c");
        let items = vec![item(b"b"), item(b"d")];

        let err = validate_page_range(&start, &end, None, &items, Some(&next)).unwrap_err();
        assert_eq!(
            err.violation,
            PageValidationViolation::NextCursorBehindLastItem
        );
    }

    #[test]
    fn rejects_cursor_regression() {
        let start = key(b"a");
        let end = key(b"z");
        let input = key(b"c");
        let next = key(b"b");
        let items = vec![item(b"d")];

        let err = validate_page_range(&start, &end, Some(&input), &items, Some(&next)).unwrap_err();
        assert_eq!(err.violation, PageValidationViolation::CursorRegressed);
    }

    #[test]
    fn rejects_empty_page_cursor_advance() {
        let start = key(b"a");
        let end = key(b"z");
        let input = key(b"a");
        let next = key(b"b");
        let items = Vec::<Item>::new();

        let err = validate_page_range(&start, &end, Some(&input), &items, Some(&next)).unwrap_err();
        assert_eq!(
            err.violation,
            PageValidationViolation::EmptyPageCursorAdvanced
        );
    }

    #[test]
    fn accepts_valid_page() {
        let start = key(b"a");
        let end = key(b"z");
        let input = key(b"b");
        let next = key(b"d");
        let items = vec![item(b"c"), item(b"d")];

        let result = validate_page_range(&start, &end, Some(&input), &items, Some(&next));
        assert!(result.is_ok());
    }
}

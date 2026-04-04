//! Shared paging vocabulary for connector enumeration pages.
//!
//! This module defines the reusable page container and validation helpers that
//! connector families use to emit ordered enumeration results without
//! re-specifying page shape rules at each family boundary.
//!
//! ## Surface overview
//!
//! | Type | Role |
//! |------|------|
//! | [`PageBuf`] | Non-empty typed page container |
//! | [`PageState`] | Terminal vs resumable page completion state |
//! | [`PageShapeError`] | Page validation failure taxonomy |
//! | [`PagingCapabilities`] | Optional paging behavior flags for a connector family |
//! | [`KeyedPageItem`] | Trait for items that participate in ordered page emission |
//! | [`validate_filled_page`] | Validates ordering, uniqueness, and shard bounds |
//! | [`PageSequenceViolation`] | Inter-page sequence violation taxonomy |
//! | [`validate_page_sequence`] | Validates shape + cursor advance + HasMore invariants |
//!
//! ## Bound semantics
//!
//! [`validate_filled_page`] accepts raw shard bounds as byte slices to mirror
//! coordination's `ShardSpec` model. Empty bounds mean "unbounded", so callers
//! can pass `shard.key_range_start()` / `shard.key_range_end()` directly.
//!
//! # Algorithms
//!
//! Sequence validation processes pages in four sequential rules:
//! 1. Intra-page shape validation (non-empty, increasing keys, shard bounds).
//! 2. Inter-page cursor advance (keys must strictly advance).
//! 3. HasMore state requires a valid last key token.
//! 4. The HasMore token must align exactly with the last item emitted.
//!
//! # Design Trade-offs
//!
//! - Pages own a `Vec<T>` instead of yielding iterators, forcing bulk processing.
//!   This prevents connectors from leaking asynchronous borrow lifetimes across
//!   the enumeration boundaries.

use std::slice;

use super::{Cursor, ItemKey, ScanItem};

/// Connector page containing one or more items plus a completion state.
///
/// This constructor enforces only the non-empty invariant. Call
/// [`validate_filled_page`] when the page items must also satisfy ordering,
/// uniqueness, and shard-bound rules.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PageBuf<T> {
    items: Vec<T>,
    state: PageState,
}

impl<T> PageBuf<T> {
    /// Construct a non-empty page.
    ///
    /// # Errors
    ///
    /// Returns [`PageShapeError::EmptyPage`] when `items` is empty.
    pub fn try_new(items: Vec<T>, state: PageState) -> Result<Self, PageShapeError> {
        if items.is_empty() {
            return Err(PageShapeError::EmptyPage);
        }
        Ok(Self { items, state })
    }

    /// Construct a non-empty page after validating ordering, uniqueness, and shard bounds.
    ///
    /// Combines [`PageBuf::try_new`] non-empty check with [`validate_filled_page`]
    /// shape validation in a single step.
    ///
    /// # Errors
    ///
    /// Returns [`PageShapeError`] if the page is empty, keys are not strictly
    /// increasing, any key falls outside the `[shard_start, shard_end)` bounds,
    /// or both bounds are non-empty with `shard_start >= shard_end`
    /// ([`PageShapeError::InvertedBounds`]).
    pub fn try_new_validated(
        items: Vec<T>,
        state: PageState,
        shard_start: &[u8],
        shard_end: &[u8],
    ) -> Result<Self, PageShapeError>
    where
        T: KeyedPageItem,
    {
        validate_filled_page(&items, shard_start, shard_end)?;
        Self::try_new(items, state)
    }

    /// Returns the items in this page.
    #[inline]
    #[must_use]
    pub fn items(&self) -> &[T] {
        &self.items
    }

    /// Returns the completion state for this page.
    #[inline]
    #[must_use]
    pub fn state(&self) -> &PageState {
        &self.state
    }

    /// Returns the number of items in this page.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Returns `false`; valid pages are always non-empty.
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
    }

    /// Iterate over the items in this page.
    #[inline]
    pub fn iter(&self) -> slice::Iter<'_, T> {
        self.items.iter()
    }

    /// Consume the page and return its owned items and state.
    #[must_use]
    pub fn into_parts(self) -> (Vec<T>, PageState) {
        (self.items, self.state)
    }
}

/// Borrowed iteration preserves the page state so callers can inspect items
/// while still deciding whether to resume from the current page.
impl<'a, T> IntoIterator for &'a PageBuf<T> {
    type Item = &'a T;
    type IntoIter = slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Owned iteration consumes the items and discards the [`PageState`].
/// Use [`PageBuf::into_parts`] when both items and completion state are needed.
impl<T> IntoIterator for PageBuf<T> {
    type Item = T;
    type IntoIter = std::vec::IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        self.items.into_iter()
    }
}

/// Whether a page completes the current enumeration scope or requires resume.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PageState {
    /// The caller must resume with the supplied cursor. A resume cursor does
    /// not guarantee another in-scope item will be returned on the next call;
    /// connectors may emit a cursor at a boundary-crossing page and signal
    /// completion on the subsequent (possibly empty) call.
    HasMore { cursor: Cursor },
    /// This page is terminal for the current enumeration scope.
    Complete,
}

impl PageState {
    /// Returns the next-page cursor when the page is resumable.
    #[inline]
    #[must_use]
    pub fn next_cursor(&self) -> Option<&Cursor> {
        match self {
            Self::HasMore { cursor } => Some(cursor),
            Self::Complete => None,
        }
    }

    /// Returns `true` when this page is terminal.
    #[inline]
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        matches!(self, Self::Complete)
    }
}

/// Optional paging behavior flags exposed by a connector family.
///
/// These flags advertise which paging features a family is capable of
/// producing. They do not override per-call validation requirements; callers
/// must still validate any emitted page or cursor against the actual payload.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PagingCapabilities {
    /// Whether the family produces strictly ordered page keys.
    pub ordered_keys: bool,
    /// Whether the family may return connector-opaque resume tokens.
    pub resumable: bool,
    /// Whether the family can emit split-point hints.
    pub splittable: bool,
}

/// Trait for items that participate in ordered page emission.
pub trait KeyedPageItem {
    /// Returns the ordered key used for page progression.
    ///
    /// Must be deterministic: successive calls on the same receiver must return
    /// an identical `ItemKey`. Validation and paging logic depend on key stability.
    fn item_key(&self) -> &ItemKey;

    /// Returns the optional item byte-size estimate used for budget tracking.
    fn size_hint(&self) -> Option<u64>;
}

impl KeyedPageItem for ScanItem {
    #[inline]
    fn item_key(&self) -> &ItemKey {
        ScanItem::item_key(self)
    }

    #[inline]
    fn size_hint(&self) -> Option<u64> {
        ScanItem::size_hint(self)
    }
}

/// Page validation failures for filled connector pages.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PageShapeError {
    /// Filled pages must contain at least one item.
    #[error("page must contain at least one item")]
    EmptyPage,
    /// A key regressed relative to the previous item.
    #[error("page item keys must be strictly increasing (index {index})")]
    UnsortedKeys { index: usize },
    /// Two adjacent keys were identical.
    #[error("page item keys must be unique (index {index})")]
    DuplicateKeys { index: usize },
    /// An item key fell outside the shard's half-open `[start, end)` bounds.
    #[error("{}", if *below_start {
        format!("page item key is below shard start bound (index {index})")
    } else {
        format!("page item key is at or above shard end bound (index {index})")
    })]
    KeyOutsideShardBounds { index: usize, below_start: bool },
    /// Both shard bounds are present but start >= end.
    #[error("shard bounds are inverted (start >= end)")]
    InvertedBounds,
}

/// Validate a non-empty ordered page against shard bounds.
///
/// `shard_start` and `shard_end` use the same convention as
/// `ShardSpec::key_range_start()` / `key_range_end()`: empty slices mean the
/// bound is unbounded. Validation rules:
///
/// - page is non-empty;
/// - when both bounds are present, `start < end` (rejects inverted bounds);
/// - keys are strictly increasing (duplicates are rejected);
/// - keys stay within the half-open interval `[start, end)`.
///
/// # Errors
///
/// Returns [`PageShapeError`] describing the first detected shape violation.
pub fn validate_filled_page<T: KeyedPageItem>(
    items: &[T],
    shard_start: &[u8],
    shard_end: &[u8],
) -> Result<(), PageShapeError> {
    let (first, rest) = items.split_first().ok_or(PageShapeError::EmptyPage)?;
    if !shard_start.is_empty() && !shard_end.is_empty() && shard_start >= shard_end {
        return Err(PageShapeError::InvertedBounds);
    }
    let mut previous = first.item_key().as_bytes();

    if !shard_start.is_empty() && previous < shard_start {
        return Err(PageShapeError::KeyOutsideShardBounds {
            index: 0,
            below_start: true,
        });
    }
    if !shard_end.is_empty() && previous >= shard_end {
        return Err(PageShapeError::KeyOutsideShardBounds {
            index: 0,
            below_start: false,
        });
    }

    for (offset, item) in rest.iter().enumerate() {
        let index = offset + 1;
        let key = item.item_key().as_bytes();
        match key.cmp(previous) {
            std::cmp::Ordering::Less => return Err(PageShapeError::UnsortedKeys { index }),
            std::cmp::Ordering::Equal => return Err(PageShapeError::DuplicateKeys { index }),
            std::cmp::Ordering::Greater => {}
        }
        if !shard_end.is_empty() && key >= shard_end {
            return Err(PageShapeError::KeyOutsideShardBounds {
                index,
                below_start: false,
            });
        }
        previous = key;
    }

    Ok(())
}

/// Violation detected by [`validate_page_sequence`] when a page breaks one of
/// the four page-sequence invariants: shape, cursor advance, HasMore last-key
/// presence, or cursor-page alignment.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PageSequenceViolation {
    /// The page failed intra-page shape validation (ordering, bounds, non-empty).
    #[error("page shape: {0}")]
    Shape(#[from] PageShapeError),
    /// The first key on this page did not strictly advance past the previous
    /// page's (or initial cursor's) last key.
    #[error(
        "page did not advance past previous last key \
             (previous_last={previous_last:?}, first_key={first_key:?})"
    )]
    CursorDidNotAdvance {
        previous_last: Vec<u8>,
        first_key: Vec<u8>,
    },
    /// A `HasMore` page returned a cursor without a `last_key`.
    #[error("HasMore cursor is missing a last_key")]
    HasMoreWithoutLastKey,
    /// A `HasMore` cursor's `last_key` does not match the page's actual last
    /// emitted key.
    #[error(
        "HasMore cursor last_key does not match page's last emitted key \
             (cursor_last={cursor_last:?}, page_last={page_last:?})"
    )]
    CursorPageMismatch {
        cursor_last: Vec<u8>,
        page_last: Vec<u8>,
    },
}

/// Validate a page against both intra-page shape rules and inter-page sequence
/// invariants.
///
/// Runs four checks in order:
///
/// 1. **Shape** — delegates to [`validate_filled_page`] (non-empty, strictly
///    increasing keys within `[shard_start, shard_end)`).
/// 2. **Cursor advance** — when `previous_last_key` is `Some`, the page's
///    first key must be strictly greater.
/// 3. **HasMore last-key presence** — a `HasMore` cursor must carry a
///    `last_key`.
/// 4. **Cursor-page alignment** — the `HasMore` cursor's `last_key` must
///    match the page's actual last emitted key.
///
/// `previous_last_key` is expected to come from the last item emitted in the
/// current enumeration scope. Passing a key from another shard or scope can
/// cause valid pages to fail the cursor-advance check.
///
/// # Errors
///
/// Returns [`PageSequenceViolation`] describing the first detected violation.
pub fn validate_page_sequence<T: KeyedPageItem>(
    items: &[T],
    page_state: &PageState,
    previous_last_key: Option<&ItemKey>,
    shard_start: &[u8],
    shard_end: &[u8],
) -> Result<(), PageSequenceViolation> {
    validate_filled_page(items, shard_start, shard_end)?;

    let first_key = items
        .first()
        .expect("validate_filled_page guarantees non-empty")
        .item_key();
    if let Some(prev) = previous_last_key
        && first_key <= prev
    {
        return Err(PageSequenceViolation::CursorDidNotAdvance {
            previous_last: prev.as_bytes().to_vec(),
            first_key: first_key.as_bytes().to_vec(),
        });
    }

    if let PageState::HasMore { cursor } = page_state {
        let Some(cursor_last) = cursor.last_key() else {
            return Err(PageSequenceViolation::HasMoreWithoutLastKey);
        };
        let page_last = items
            .last()
            .expect("validate_filled_page guarantees non-empty")
            .item_key();
        if cursor_last != page_last {
            return Err(PageSequenceViolation::CursorPageMismatch {
                cursor_last: cursor_last.as_bytes().to_vec(),
                page_last: page_last.as_bytes().to_vec(),
            });
        }
    }

    Ok(())
}

#[cfg(test)]
#[path = "common_tests.rs"]
mod tests;

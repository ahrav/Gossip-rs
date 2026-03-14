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
//!
//! ## Bound semantics
//!
//! [`validate_filled_page`] accepts raw shard bounds as byte slices to mirror
//! coordination's `ShardSpec` model. Empty bounds mean "unbounded", so callers
//! can pass `shard.key_range_start()` / `shard.key_range_end()` directly.

use std::{fmt, slice};

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
        // Delegate to try_new so any future invariants added there are enforced.
        // validate_filled_page already guarantees non-empty, so try_new succeeds.
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

impl<'a, T> IntoIterator for &'a PageBuf<T> {
    type Item = &'a T;
    type IntoIter = slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PageShapeError {
    /// Filled pages must contain at least one item.
    EmptyPage,
    /// A key regressed relative to the previous item.
    UnsortedKeys { index: usize },
    /// Two adjacent keys were identical.
    DuplicateKeys { index: usize },
    /// An item key fell outside the shard's half-open `[start, end)` bounds.
    KeyOutsideShardBounds { index: usize, below_start: bool },
    /// Both shard bounds are present but start >= end.
    InvertedBounds,
}

impl fmt::Display for PageShapeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPage => f.write_str("page must contain at least one item"),
            Self::UnsortedKeys { index } => {
                write!(
                    f,
                    "page item keys must be strictly increasing (index {index})"
                )
            }
            Self::DuplicateKeys { index } => {
                write!(f, "page item keys must be unique (index {index})")
            }
            Self::KeyOutsideShardBounds { index, below_start } => {
                if *below_start {
                    write!(
                        f,
                        "page item key is below shard start bound (index {index})"
                    )
                } else {
                    write!(
                        f,
                        "page item key is at or above shard end bound (index {index})"
                    )
                }
            }
            Self::InvertedBounds => f.write_str("shard bounds are inverted (start >= end)"),
        }
    }
}

impl std::error::Error for PageShapeError {}

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

    // Strictly increasing keys guarantee all subsequent items exceed the first,
    // which was already verified against shard_start.
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

#[cfg(test)]
#[path = "common_tests.rs"]
mod tests;

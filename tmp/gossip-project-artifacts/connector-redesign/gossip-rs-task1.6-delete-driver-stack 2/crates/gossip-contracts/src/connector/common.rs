//! Shared paging primitives used by connector source families.
//!
//! This module does **not** define a universal connector trait. Instead, it
//! provides the common vocabulary that multiple connector families reuse:
//!
//! - runtime-owned page buffers ([`PageBuf`])
//! - page completion state ([`PageState`])
//! - paging feature flags ([`PagingCapabilities`])
//! - keyed work-unit projection ([`KeyedPageItem`])
//! - deterministic page validation ([`validate_filled_page`])
//!
//! ## Design intent
//!
//! Different source families have different execution models:
//!
//! - ordered content sources page [`ScanItem`] values and expose bytes;
//! - Git discovery sources page repo targets;
//! - later feed/export families may page other work-unit types.
//!
//! The shared thread is therefore *paged ordered work*, not one fake universal
//! connector trait.
//!
//! ## Runtime contract
//!
//! For any family using these primitives:
//!
//! - `Cursor.last_key` is the authoritative checkpoint position.
//! - `Cursor.token` is optional acceleration state only.
//! - `PageState::Exhausted` is the only terminal empty-page signal.
//! - `PageState::Progress { .. }` requires a non-empty [`PageBuf`].
//! - If a runtime commits only a strict prefix of a page, it must drop the
//!   token and checkpoint only `Cursor::with_last_key(...)` for the committed
//!   prefix.
//!
//! Validation in this module checks page-shape correctness only; it does not
//! make tokens authoritative.

use std::{error::Error, fmt};

use crate::coordination::ShardSpec;

use super::{Budgets, Cursor, ItemKey, ScanItem};

/// Runtime-owned reusable buffer for one discovered page of work units.
///
/// The runtime owns this buffer and reuses its allocation across calls. Source
/// families treat it as scratch output only.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PageBuf<T> {
    items: Vec<T>,
}

impl<T> PageBuf<T> {
    /// Construct an empty page buffer.
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self { items: Vec::new() }
    }

    /// Construct an empty page buffer with reserved capacity.
    #[inline]
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            items: Vec::with_capacity(capacity),
        }
    }

    /// Remove all items while retaining allocation for reuse.
    #[inline]
    pub fn clear(&mut self) {
        self.items.clear();
    }

    /// Returns `true` if the buffer currently holds no items.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Returns the number of items currently stored.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Borrow all items currently in the buffer.
    #[inline]
    #[must_use]
    pub fn items(&self) -> &[T] {
        &self.items
    }

    /// Append one item to the buffer.
    #[inline]
    pub fn push(&mut self, item: T) {
        self.items.push(item);
    }

    /// Borrow the final item in the buffer, if any.
    #[inline]
    #[must_use]
    pub fn last(&self) -> Option<&T> {
        self.items.last()
    }
}

/// Outcome of one bounded page fill.
///
/// `Progress { exhausted: true }` represents the final non-empty page.
/// `Exhausted` is the terminal empty-page EOF signal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PageState {
    /// The page buffer contains a non-empty ordered set of work units.
    Progress { next_cursor: Cursor, exhausted: bool },
    /// No further work units remain at or after the supplied cursor.
    Exhausted,
}

impl PageState {
    /// Borrow the next cursor for non-empty progress pages.
    #[inline]
    #[must_use]
    pub fn next_cursor(&self) -> Option<&Cursor> {
        match self {
            Self::Progress { next_cursor, .. } => Some(next_cursor),
            Self::Exhausted => None,
        }
    }

    /// Returns `true` when no further work remains after this state.
    #[inline]
    #[must_use]
    pub fn exhausted(&self) -> bool {
        match self {
            Self::Progress { exhausted, .. } => *exhausted,
            Self::Exhausted => true,
        }
    }
}

/// Shared paging feature flags used by family-specific capabilities.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PagingCapabilities {
    /// Whether the family can resume correctly from `Cursor.last_key` alone.
    pub seek_by_key: bool,
    /// Whether the family may emit a connector-opaque token in addition to the
    /// ordered key cursor.
    pub token_resume: bool,
    /// Whether the family can cheaply provide split hints.
    pub split_hints: bool,
}

impl PagingCapabilities {
    /// Construct paging capability flags.
    #[inline]
    #[must_use]
    pub const fn new(seek_by_key: bool, token_resume: bool, split_hints: bool) -> Self {
        Self {
            seek_by_key,
            token_resume,
            split_hints,
        }
    }
}

/// Trait for page items that participate in ordered cursor validation.
///
/// Any work-unit type that can be paged over an ordered shard range should
/// expose its frontier key through this trait.
pub trait KeyedPageItem {
    /// Ordered page key used for bounds checks and checkpoint validation.
    fn page_key(&self) -> &ItemKey;
}

impl KeyedPageItem for ScanItem {
    #[inline]
    fn page_key(&self) -> &ItemKey {
        self.item_key()
    }
}

/// Deterministic validation failures for a filled page.
///
/// These indicate a source-family contract bug or an unsupported capability
/// shape, not a transient runtime condition.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PageShapeError {
    /// The runtime requires key-authoritative paging.
    SeekByKeyRequired,
    /// `PageState::Exhausted` was returned with a non-empty output buffer.
    NonEmptyOnExhausted,
    /// `PageState::Progress` was returned with an empty output buffer.
    EmptyProgressPage,
    /// The source returned more items than the page budget allows.
    TooManyItems { max: usize, actual: usize },
    /// `next_cursor.last_key()` did not match the final returned item key.
    CursorLastKeyMismatch,
    /// `next_cursor.last_key()` failed to advance beyond `prior_cursor`.
    CursorRegression,
    /// The source returned a token without advertising token support.
    TokenWithoutCapability,
    /// An item key regressed or duplicated relative to `prior_cursor` or a
    /// previous item in the page.
    ItemKeyRegression { index: usize },
    /// An item key fell outside the shard's `[start, end)` range.
    ItemKeyOutOfRange { index: usize },
}

impl fmt::Display for PageShapeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SeekByKeyRequired => {
                f.write_str("ordered paging requires seek_by_key=true")
            }
            Self::NonEmptyOnExhausted => {
                f.write_str("exhausted page state must have an empty output buffer")
            }
            Self::EmptyProgressPage => {
                f.write_str("progress page must contain at least one item")
            }
            Self::TooManyItems { max, actual } => {
                write!(f, "progress page exceeded max_items budget: actual={actual}, max={max}")
            }
            Self::CursorLastKeyMismatch => {
                f.write_str("next_cursor.last_key does not match last item key")
            }
            Self::CursorRegression => {
                f.write_str("next_cursor regressed relative to prior cursor")
            }
            Self::TokenWithoutCapability => {
                f.write_str("page returned a token but token_resume=false")
            }
            Self::ItemKeyRegression { index } => {
                write!(f, "item key regressed or duplicated at page index {index}")
            }
            Self::ItemKeyOutOfRange { index } => {
                write!(f, "item key fell outside shard range at page index {index}")
            }
        }
    }
}

impl Error for PageShapeError {}

/// Validate a filled page against shard bounds, prior cursor progress, and
/// declared paging capabilities.
///
/// This checks page-shape correctness only. A returned token is still
/// non-authoritative: callers may retain it only when they durably commit the
/// entire page.
pub fn validate_filled_page<T: KeyedPageItem>(
    out: &PageBuf<T>,
    state: &PageState,
    shard: &ShardSpec,
    prior_cursor: &Cursor,
    caps: PagingCapabilities,
    budgets: Budgets,
) -> Result<(), PageShapeError> {
    if !caps.seek_by_key {
        return Err(PageShapeError::SeekByKeyRequired);
    }

    match state {
        PageState::Exhausted => {
            if !out.is_empty() {
                return Err(PageShapeError::NonEmptyOnExhausted);
            }
            Ok(())
        }
        PageState::Progress { next_cursor, .. } => {
            if out.is_empty() {
                return Err(PageShapeError::EmptyProgressPage);
            }

            let actual = out.len();
            let max = budgets.max_items();
            if actual > max {
                return Err(PageShapeError::TooManyItems { max, actual });
            }

            if !caps.token_resume && next_cursor.token().is_some() {
                return Err(PageShapeError::TokenWithoutCapability);
            }

            let start = shard.key_range_start();
            let end = shard.key_range_end();
            let mut prev_key = prior_cursor.last_key().map(|key| key.as_bytes());

            for (index, item) in out.items().iter().enumerate() {
                let key = item.page_key().as_bytes();

                if !start.is_empty() && key < start {
                    return Err(PageShapeError::ItemKeyOutOfRange { index });
                }
                if !end.is_empty() && key >= end {
                    return Err(PageShapeError::ItemKeyOutOfRange { index });
                }

                if let Some(prev) = prev_key {
                    if key <= prev {
                        return Err(PageShapeError::ItemKeyRegression { index });
                    }
                }

                prev_key = Some(key);
            }

            let last_key = out.last().expect("validated non-empty progress page").page_key();
            if next_cursor.last_key() != Some(last_key) {
                return Err(PageShapeError::CursorLastKeyMismatch);
            }

            if let Some(prior_last_key) = prior_cursor.last_key() {
                let next_last_key = next_cursor
                    .last_key()
                    .expect("validated above: progress next_cursor must carry last_key");
                if next_last_key.as_bytes() <= prior_last_key.as_bytes() {
                    return Err(PageShapeError::CursorRegression);
                }
            }

            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{
        connector::{ItemRef, TokenBytes, VersionId},
        identity::{ObjectVersionId, StableItemId},
    };

    fn key(bytes: &[u8]) -> ItemKey {
        ItemKey::try_from_slice(bytes).expect("item key")
    }

    fn item_ref(bytes: &[u8]) -> ItemRef {
        ItemRef::try_from_slice(bytes).expect("item ref")
    }

    fn item(seed: u8, key_bytes: &[u8]) -> ScanItem {
        ScanItem::new(
            key(key_bytes),
            item_ref(key_bytes),
            StableItemId::from_bytes([seed; 32]),
            VersionId::Strong(ObjectVersionId::from_bytes([seed.wrapping_add(1); 32])),
        )
    }

    fn budgets(max_items: usize) -> Budgets {
        Budgets::try_new(max_items, 1024, None).expect("budgets")
    }

    fn caps() -> PagingCapabilities {
        PagingCapabilities::new(true, false, true)
    }

    #[test]
    fn scan_item_implements_keyed_page_item() {
        let scan_item = item(1, b"b");
        assert_eq!(scan_item.page_key().as_bytes(), b"b");
    }

    #[test]
    fn exhausted_requires_empty_output() {
        let mut out = PageBuf::new();
        out.push(item(1, b"b"));

        let err = validate_filled_page(
            &out,
            &PageState::Exhausted,
            &ShardSpec::with_range(b"a", b"z"),
            &Cursor::initial(),
            caps(),
            budgets(8),
        )
        .expect_err("non-empty exhausted page must fail");

        assert_eq!(err, PageShapeError::NonEmptyOnExhausted);
    }

    #[test]
    fn progress_requires_non_empty_output() {
        let out = PageBuf::<ScanItem>::new();
        let state = PageState::Progress {
            next_cursor: Cursor::with_last_key(key(b"b")),
            exhausted: false,
        };

        let err = validate_filled_page(
            &out,
            &state,
            &ShardSpec::with_range(b"a", b"z"),
            &Cursor::initial(),
            caps(),
            budgets(8),
        )
        .expect_err("empty progress page must fail");

        assert_eq!(err, PageShapeError::EmptyProgressPage);
    }

    #[test]
    fn validate_accepts_sorted_in_range_progress_page() {
        let mut out = PageBuf::new();
        out.push(item(1, b"b"));
        out.push(item(2, b"c"));

        let state = PageState::Progress {
            next_cursor: Cursor::with_last_key(key(b"c")),
            exhausted: false,
        };

        assert_eq!(
            validate_filled_page(
                &out,
                &state,
                &ShardSpec::with_range(b"a", b"z"),
                &Cursor::with_last_key(key(b"a")),
                caps(),
                budgets(8),
            ),
            Ok(())
        );
    }

    #[test]
    fn validate_rejects_unsorted_or_duplicate_item_keys() {
        let mut out = PageBuf::new();
        out.push(item(1, b"c"));
        out.push(item(2, b"b"));

        let state = PageState::Progress {
            next_cursor: Cursor::with_last_key(key(b"b")),
            exhausted: false,
        };

        let err = validate_filled_page(
            &out,
            &state,
            &ShardSpec::with_range(b"a", b"z"),
            &Cursor::initial(),
            caps(),
            budgets(8),
        )
        .expect_err("unsorted page must fail");

        assert_eq!(err, PageShapeError::ItemKeyRegression { index: 1 });
    }

    #[test]
    fn validate_rejects_out_of_range_items() {
        let mut out = PageBuf::new();
        out.push(item(1, b"0"));

        let state = PageState::Progress {
            next_cursor: Cursor::with_last_key(key(b"0")),
            exhausted: false,
        };

        let err = validate_filled_page(
            &out,
            &state,
            &ShardSpec::with_range(b"a", b"z"),
            &Cursor::initial(),
            caps(),
            budgets(8),
        )
        .expect_err("out-of-range page must fail");

        assert_eq!(err, PageShapeError::ItemKeyOutOfRange { index: 0 });
    }

    #[test]
    fn validate_rejects_token_when_capability_is_false() {
        let mut out = PageBuf::new();
        out.push(item(1, b"b"));

        let token = TokenBytes::try_from_slice(b"tok").expect("token");
        let state = PageState::Progress {
            next_cursor: Cursor::with_token(key(b"b"), token),
            exhausted: false,
        };

        let err = validate_filled_page(
            &out,
            &state,
            &ShardSpec::with_range(b"a", b"z"),
            &Cursor::initial(),
            PagingCapabilities::new(true, false, true),
            budgets(8),
        )
        .expect_err("token without capability must fail");

        assert_eq!(err, PageShapeError::TokenWithoutCapability);
    }

    #[test]
    fn validate_rejects_seek_by_key_false() {
        let err = validate_filled_page(
            &PageBuf::<ScanItem>::new(),
            &PageState::Exhausted,
            &ShardSpec::unbounded(),
            &Cursor::initial(),
            PagingCapabilities::new(false, false, false),
            budgets(8),
        )
        .expect_err("seek_by_key=false must fail");

        assert_eq!(err, PageShapeError::SeekByKeyRequired);
    }

    #[test]
    fn validate_rejects_page_that_exceeds_item_budget() {
        let mut out = PageBuf::new();
        out.push(item(1, b"b"));
        out.push(item(2, b"c"));
        out.push(item(3, b"d"));

        let state = PageState::Progress {
            next_cursor: Cursor::with_last_key(key(b"d")),
            exhausted: false,
        };

        let err = validate_filled_page(
            &out,
            &state,
            &ShardSpec::with_range(b"a", b"z"),
            &Cursor::initial(),
            caps(),
            budgets(2),
        )
        .expect_err("oversized page must fail");

        assert_eq!(err, PageShapeError::TooManyItems { max: 2, actual: 3 });
    }

    #[test]
    fn validate_rejects_cursor_last_key_mismatch() {
        let mut out = PageBuf::new();
        out.push(item(1, b"b"));
        out.push(item(2, b"c"));

        let state = PageState::Progress {
            next_cursor: Cursor::with_last_key(key(b"b")),
            exhausted: false,
        };

        let err = validate_filled_page(
            &out,
            &state,
            &ShardSpec::with_range(b"a", b"z"),
            &Cursor::initial(),
            caps(),
            budgets(8),
        )
        .expect_err("mismatched cursor must fail");

        assert_eq!(err, PageShapeError::CursorLastKeyMismatch);
    }

    #[test]
    fn validate_rejects_cursor_regression_against_prior_cursor() {
        let mut out = PageBuf::new();
        out.push(item(1, b"b"));

        let state = PageState::Progress {
            next_cursor: Cursor::with_last_key(key(b"b")),
            exhausted: false,
        };

        let err = validate_filled_page(
            &out,
            &state,
            &ShardSpec::with_range(b"a", b"z"),
            &Cursor::with_last_key(key(b"c")),
            caps(),
            budgets(8),
        )
        .expect_err("regressing cursor must fail");

        assert_eq!(err, PageShapeError::ItemKeyRegression { index: 0 });
    }
}

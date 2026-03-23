//! Reusable ordered-content connector conformance harness.
//!
//! The ordered-content contract needs more than page-local validation. Callers
//! also need confidence that page sequences advance monotonically, resume from
//! `last_key` even when tokens are stale or corrupt, terminate cleanly with an
//! exhausted-empty `None` call, and do not leak connector-root fragments into
//! emitted [`ItemRef`] values.
//!
//! This module provides a reusable test kit for that purpose. It assumes the
//! factory passed to [`run_ordered_content_conformance`] produces fresh sources
//! over the same fixed source view.

use std::{error::Error, fmt};

use crate::{
    connector::{
        Budgets, ConnectorInputError, Cursor, EnumerateError, ItemKey, ItemRef, PageShapeError,
        PageState, ScanItem, TokenBytes, ToxicDigest, VersionId, ordered::OrderedContentSource,
        validate_filled_page,
    },
    coordination::ShardSpec,
    identity::StableItemId,
};

/// Safety cap on page count during a single drain. Prevents unbounded looping
/// when a source never transitions to `Complete` or returns `None`.
const DEFAULT_MAX_PAGES: usize = 4096;

/// Arbitrary non-empty byte payload injected as a corrupt opaque token during
/// the token-fallback probe. The specific value is irrelevant — any non-empty
/// `TokenBytes` that differs from whatever the source originally emitted will
/// exercise the fallback-to-key-only resume path.
const CORRUPT_TOKEN_BYTES: &[u8] = b"ordered-content-conformance-corrupt-token";

/// Stable snapshot of one emitted [`ScanItem`] for conformance comparisons.
///
/// Omits `content_hints` and `location` from [`ScanItem`], which are
/// presentation-only metadata irrelevant to ordered-content conformance
/// checks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservedScanItem {
    item_key: ItemKey,
    item_ref: ItemRef,
    stable_item_id: StableItemId,
    version: VersionId,
    size_hint: Option<u64>,
}

impl ObservedScanItem {
    /// Returns the ordered item key.
    #[must_use]
    pub fn item_key(&self) -> &ItemKey {
        &self.item_key
    }

    /// Returns the connector-opaque item reference.
    #[must_use]
    pub fn item_ref(&self) -> &ItemRef {
        &self.item_ref
    }

    /// Returns the stable item identity.
    #[must_use]
    pub fn stable_item_id(&self) -> StableItemId {
        self.stable_item_id
    }

    /// Returns the connector-provided version claim.
    #[must_use]
    pub fn version(&self) -> VersionId {
        self.version
    }

    /// Returns the optional size hint.
    #[must_use]
    pub fn size_hint(&self) -> Option<u64> {
        self.size_hint
    }
}

impl From<&ScanItem> for ObservedScanItem {
    fn from(item: &ScanItem) -> Self {
        Self {
            item_key: item.item_key().clone(),
            item_ref: item.item_ref().clone(),
            stable_item_id: item.stable_item_id(),
            version: item.version(),
            size_hint: item.size_hint(),
        }
    }
}

/// Exhaustive ordered drain of one source instance.
///
/// `page_lengths` preserves the connector's page partitioning under the given
/// budgets so the harness can detect nondeterministic repacking even when the
/// item set itself is stable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrderedContentDrain {
    items: Vec<ObservedScanItem>,
    page_lengths: Vec<usize>,
}

impl OrderedContentDrain {
    /// Constructs a drain from pre-collected items and their page partitioning.
    ///
    /// `page_lengths` must exactly partition `items`: every entry must be
    /// positive and `sum(page_lengths) == items.len()`.
    fn new(items: Vec<ObservedScanItem>, page_lengths: Vec<usize>) -> Self {
        debug_assert_eq!(
            page_lengths.iter().sum::<usize>(),
            items.len(),
            "page_lengths must partition items exactly"
        );
        debug_assert!(
            page_lengths.iter().all(|&len| len > 0),
            "every page must be non-empty"
        );
        Self {
            items,
            page_lengths,
        }
    }

    /// Returns all emitted items in order.
    #[must_use]
    pub fn items(&self) -> &[ObservedScanItem] {
        &self.items
    }

    /// Returns the length of each emitted page in order.
    #[must_use]
    pub fn page_lengths(&self) -> &[usize] {
        &self.page_lengths
    }

    /// Returns the total number of emitted items.
    #[must_use]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Returns whether the drain emitted no items.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

/// Failure reported by the ordered-content conformance harness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OrderedContentConformanceError {
    /// The caller passed an invalid zero budget.
    InvalidBudgets(ConnectorInputError),
    /// The source returned an enumeration error while the harness was probing
    /// conformance.
    Enumerate {
        phase: &'static str,
        page_index: usize,
        source: EnumerateError,
    },
    /// The source returned a non-empty page that failed page-shape validation.
    InvalidPage {
        page_index: usize,
        source: PageShapeError,
    },
    /// A `HasMore` page returned a cursor without a `last_key`.
    HasMoreWithoutLastKey { page_index: usize },
    /// A `HasMore` cursor's `last_key` did not match the last emitted key.
    ResumeCursorMismatch {
        page_index: usize,
        expected_last: ItemKey,
        actual_last: ItemKey,
    },
    /// A later page or resume cursor regressed or stalled instead of advancing.
    ///
    /// `observed_key` is the key that failed to advance past `previous_last`.
    /// It may be the first key of a new page (page-level regression) or the
    /// `last_key` on a `HasMore` cursor (cursor-level stall).
    CursorDidNotAdvance {
        page_index: usize,
        previous_last: ItemKey,
        observed_key: ItemKey,
    },
    /// After a `Complete` page, the suffix call still produced more items.
    CompletePageDidNotExhaust { page_index: usize },
    /// The source returned `None` mid-drain (after a prior `HasMore`), but a
    /// retry with the same key position found additional items.
    NoneDidNotExhaust { page_index: usize },
    /// The harness exceeded its hard safety cap on page count.
    TooManyPages { limit: usize },
    /// Two fresh sources over the same fixed view produced different drains.
    DeterminismMismatch {
        /// Index of the first item where the two drains diverged, or `None`
        /// when the drains matched on items but differed on page partitioning.
        first_divergent_item: Option<usize>,
    },
    /// Key-only resume and corrupt-token resume produced different suffixes.
    TokenFallbackMismatch {
        /// Index of the first item where the two suffixes diverged, or `None`
        /// when the suffixes matched on items but differed on page partitioning.
        first_divergent_item: Option<usize>,
    },
    /// An emitted item reference contained a caller-supplied forbidden byte
    /// fragment.
    ForbiddenItemRefFragment {
        item_index: usize,
        fragment: ToxicDigest,
        item_ref: ToxicDigest,
    },
}

impl fmt::Display for OrderedContentConformanceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBudgets(err) => write!(f, "invalid conformance budgets: {err}"),
            Self::Enumerate {
                phase,
                page_index,
                source,
            } => write!(
                f,
                "ordered-content conformance enumerate failure during {phase} at page {page_index}: {source}"
            ),
            Self::InvalidPage { page_index, source } => write!(
                f,
                "ordered-content conformance received invalid page at page {page_index}: {source}"
            ),
            Self::HasMoreWithoutLastKey { page_index } => write!(
                f,
                "ordered-content conformance page {page_index} returned HasMore without last_key"
            ),
            Self::ResumeCursorMismatch {
                page_index,
                expected_last,
                actual_last,
            } => write!(
                f,
                "ordered-content conformance page {page_index} returned resume cursor last_key {actual_last} but expected {expected_last}"
            ),
            Self::CursorDidNotAdvance {
                page_index,
                previous_last,
                observed_key,
            } => write!(
                f,
                "ordered-content conformance page {page_index} did not advance: previous_last={previous_last}, observed_key={observed_key}"
            ),
            Self::CompletePageDidNotExhaust { page_index } => write!(
                f,
                "ordered-content conformance page {page_index} reported Complete but a suffix call still returned more items"
            ),
            Self::NoneDidNotExhaust { page_index } => write!(
                f,
                "ordered-content conformance page {page_index}: source returned None mid-drain but a retry with the same key position produced items"
            ),
            Self::TooManyPages { limit } => write!(
                f,
                "ordered-content conformance exceeded the safety cap of {limit} pages"
            ),
            Self::DeterminismMismatch {
                first_divergent_item,
            } => match first_divergent_item {
                Some(idx) => write!(
                    f,
                    "ordered-content conformance fresh drains diverged at item {idx}"
                ),
                None => write!(
                    f,
                    "ordered-content conformance fresh drains matched on items but diverged on page partitioning"
                ),
            },
            Self::TokenFallbackMismatch {
                first_divergent_item,
            } => match first_divergent_item {
                Some(idx) => write!(
                    f,
                    "ordered-content conformance corrupt-token resume diverged from key-only resume at item {idx}"
                ),
                None => write!(
                    f,
                    "ordered-content conformance corrupt-token resume matched on items but diverged on page partitioning"
                ),
            },
            Self::ForbiddenItemRefFragment {
                item_index,
                fragment,
                item_ref,
            } => write!(
                f,
                "ordered-content conformance item_ref leak at item {item_index}: item_ref ({item_ref}) contained forbidden fragment ({fragment})"
            ),
        }
    }
}

impl Error for OrderedContentConformanceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidBudgets(err) => Some(err),
            Self::Enumerate { source, .. } => Some(source),
            Self::InvalidPage { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Run the standard ordered-content conformance suite on a fresh-source
/// factory.
///
/// `factory` must produce fresh, independent source instances over the same
/// fixed data view each time it is called. The harness calls it multiple times
/// to test determinism and resume behavior.
///
/// `max_items` and `max_bytes` set the per-page budgets passed to each
/// `fill_page` call during drains. Choose values small enough to force
/// multi-page sequences so the harness exercises cursor advancement.
///
/// `forbidden_item_ref_fragments` lists byte substrings that must not appear
/// anywhere inside any emitted `ItemRef`. Use this to detect root-path or
/// secret leakage (e.g., pass the filesystem root directory name). Empty
/// fragments are silently ignored.
///
/// The suite performs four checks:
///
/// 1. Drain page sequences while validating page shape, cursor advancement,
///    and exhausted-empty behavior after a terminal page.
/// 2. Repeat the drain on a fresh source and require an identical item
///    sequence and identical page partitioning.
/// 3. Force a multi-page probe and require that a corrupt opaque token with
///    the same `last_key` resumes to the same suffix as a key-only cursor.
/// 4. Optionally verify that emitted item refs do not contain any
///    caller-supplied forbidden byte fragments.
///
/// **Note**: The corrupt-token probe requires at least two items under the
/// probe budget to produce a `HasMore` page. Sources with zero or one item
/// skip the token-fallback check silently.
///
/// Returns the drain from the first pass on success.
pub fn run_ordered_content_conformance<F, S>(
    mut factory: F,
    shard: &ShardSpec,
    max_items: usize,
    max_bytes: u64,
    forbidden_item_ref_fragments: &[&[u8]],
) -> Result<OrderedContentDrain, OrderedContentConformanceError>
where
    F: FnMut() -> S,
    S: OrderedContentSource,
{
    let drain = assert_repeatable_drain(&mut factory, shard, max_items, max_bytes)?;
    assert_no_item_ref_contains(&drain, forbidden_item_ref_fragments)?;
    assert_resume_after_corrupt_token(&mut factory, shard, 1, max_items, max_bytes)?;
    Ok(drain)
}

/// Drain one ordered-content source to exhaustion under fixed budgets.
pub fn drain_ordered_source<S>(
    source: &mut S,
    shard: &ShardSpec,
    max_items: usize,
    max_bytes: u64,
) -> Result<OrderedContentDrain, OrderedContentConformanceError>
where
    S: OrderedContentSource,
{
    let budgets = Budgets::try_new(max_items, max_bytes, None)
        .map_err(OrderedContentConformanceError::InvalidBudgets)?;
    drain_from_cursor(source, shard, Cursor::initial(), budgets, DEFAULT_MAX_PAGES)
}

/// Require that two fresh drains over the same factory-produced view are
/// identical.
pub fn assert_repeatable_drain<F, S>(
    factory: &mut F,
    shard: &ShardSpec,
    max_items: usize,
    max_bytes: u64,
) -> Result<OrderedContentDrain, OrderedContentConformanceError>
where
    F: FnMut() -> S,
    S: OrderedContentSource,
{
    let mut first_source = factory();
    let first = drain_ordered_source(&mut first_source, shard, max_items, max_bytes)?;

    let mut second_source = factory();
    let second = drain_ordered_source(&mut second_source, shard, max_items, max_bytes)?;

    if first != second {
        return Err(OrderedContentConformanceError::DeterminismMismatch {
            first_divergent_item: first_divergent_index(&first, &second),
        });
    }
    Ok(first)
}

/// Require that resume with a corrupt token falls back to key-only resume.
///
/// Fetches one page using `first_page_max_items` as the item budget, then
/// resumes from that page's `last_key` twice: once with a key-only cursor and
/// once with the same key paired with a fabricated corrupt token. Both suffixes
/// must be identical, proving the source does not depend on token contents for
/// correct resume.
pub fn assert_resume_after_corrupt_token<F, S>(
    factory: &mut F,
    shard: &ShardSpec,
    first_page_max_items: usize,
    drain_max_items: usize,
    max_bytes: u64,
) -> Result<(), OrderedContentConformanceError>
where
    F: FnMut() -> S,
    S: OrderedContentSource,
{
    let first_budgets = Budgets::try_new(first_page_max_items, max_bytes, None)
        .map_err(OrderedContentConformanceError::InvalidBudgets)?;
    let drain_budgets = Budgets::try_new(drain_max_items, max_bytes, None)
        .map_err(OrderedContentConformanceError::InvalidBudgets)?;

    let mut probe_source = factory();
    let first_page = probe_source
        .fill_page(shard, &Cursor::initial(), first_budgets)
        .map_err(|source| OrderedContentConformanceError::Enumerate {
            phase: "token-fallback-probe",
            page_index: 0,
            source,
        })?;
    let Some(first_page) = first_page else {
        return Ok(());
    };

    validate_filled_page(
        first_page.items(),
        shard.key_range_start(),
        shard.key_range_end(),
    )
    .map_err(|source| OrderedContentConformanceError::InvalidPage {
        page_index: 0,
        source,
    })?;

    let PageState::HasMore { cursor } = first_page.state() else {
        return Ok(());
    };
    let Some(resume_key) = cursor.last_key().cloned() else {
        return Err(OrderedContentConformanceError::HasMoreWithoutLastKey { page_index: 0 });
    };

    let mut clean_source = factory();
    let clean = drain_from_cursor(
        &mut clean_source,
        shard,
        Cursor::with_last_key(resume_key.clone()),
        drain_budgets,
        DEFAULT_MAX_PAGES,
    )?;

    let corrupt_token = TokenBytes::try_from_slice(CORRUPT_TOKEN_BYTES)
        .expect("built-in corrupt-token probe must be a valid non-empty token");
    let mut corrupt_source = factory();
    let corrupt = drain_from_cursor(
        &mut corrupt_source,
        shard,
        Cursor::with_token(resume_key, corrupt_token),
        drain_budgets,
        DEFAULT_MAX_PAGES,
    )?;

    if clean != corrupt {
        return Err(OrderedContentConformanceError::TokenFallbackMismatch {
            first_divergent_item: first_divergent_index(&clean, &corrupt),
        });
    }
    Ok(())
}

/// Require that no emitted item reference contains any forbidden byte
/// fragment. Empty fragments are ignored.
pub fn assert_no_item_ref_contains(
    drain: &OrderedContentDrain,
    forbidden_item_ref_fragments: &[&[u8]],
) -> Result<(), OrderedContentConformanceError> {
    for (item_index, item) in drain.items().iter().enumerate() {
        let item_ref = item.item_ref().as_bytes();
        for fragment in forbidden_item_ref_fragments.iter().copied() {
            if fragment.is_empty() {
                continue;
            }
            if item_ref
                .windows(fragment.len())
                .any(|window| window == fragment)
            {
                return Err(OrderedContentConformanceError::ForbiddenItemRefFragment {
                    item_index,
                    fragment: ToxicDigest::of_bytes(fragment),
                    item_ref: ToxicDigest::of(item.item_ref()),
                });
            }
        }
    }
    Ok(())
}

/// Returns the index of the first item that differs between two drains, or
/// `None` when items match but page partitioning diverges.
fn first_divergent_index(a: &OrderedContentDrain, b: &OrderedContentDrain) -> Option<usize> {
    let idx = a
        .items()
        .iter()
        .zip(b.items().iter())
        .position(|(ai, bi)| ai != bi);
    if idx.is_some() {
        return idx;
    }
    // Items match up to the shorter length — a length difference is an item
    // divergence at the shorter length.
    if a.items().len() != b.items().len() {
        return Some(a.items().len().min(b.items().len()));
    }
    // Items are identical; page_lengths must differ.
    None
}

/// Page-by-page drain with per-page validation.
///
/// Iterates `fill_page` calls from `cursor` until the source returns `None`
/// (exhausted before first page) or `Complete`. On each page the loop:
///
/// 1. Validates page shape via [`validate_filled_page`].
/// 2. Checks that the first key on each page strictly advances past the
///    previous page's last key.
/// 3. For `HasMore` pages, verifies the resume cursor's `last_key` matches
///    the page's actual last emitted key.
/// 4. After a `Complete` page, issues one additional suffix call to confirm
///    the source truly has no more items.
fn drain_from_cursor<S>(
    source: &mut S,
    shard: &ShardSpec,
    mut cursor: Cursor,
    budgets: Budgets,
    max_pages: usize,
) -> Result<OrderedContentDrain, OrderedContentConformanceError>
where
    S: OrderedContentSource,
{
    let mut items = Vec::new();
    let mut page_lengths = Vec::new();
    let mut previous_last: Option<ItemKey> = cursor.last_key().cloned();

    for page_index in 0..max_pages {
        let page = source
            .fill_page(shard, &cursor, budgets)
            .map_err(|source| OrderedContentConformanceError::Enumerate {
                phase: "drain",
                page_index,
                source,
            })?;
        let Some(page) = page else {
            // When prior pages were consumed, verify the source does not produce
            // more items on a retry with the same cursor position.
            if let Some(prev_key) = previous_last.as_ref() {
                let probe = source
                    .fill_page(shard, &Cursor::with_last_key(prev_key.clone()), budgets)
                    .map_err(|source| OrderedContentConformanceError::Enumerate {
                        phase: "post-none-exhaustion-check",
                        page_index,
                        source,
                    })?;
                if probe.is_some() {
                    return Err(OrderedContentConformanceError::NoneDidNotExhaust { page_index });
                }
            }
            return Ok(OrderedContentDrain::new(items, page_lengths));
        };

        validate_filled_page(page.items(), shard.key_range_start(), shard.key_range_end())
            .map_err(|source| OrderedContentConformanceError::InvalidPage { page_index, source })?;

        let first_key = page
            .items()
            .first()
            .expect("validated page must be non-empty")
            .item_key()
            .clone();
        if let Some(prev) = previous_last.as_ref()
            && first_key <= *prev
        {
            return Err(OrderedContentConformanceError::CursorDidNotAdvance {
                page_index,
                previous_last: prev.clone(),
                observed_key: first_key,
            });
        }

        let last_key = page
            .items()
            .last()
            .expect("validated page must be non-empty")
            .item_key()
            .clone();
        page_lengths.push(page.len());
        items.extend(page.items().iter().map(ObservedScanItem::from));

        match page.state() {
            PageState::HasMore {
                cursor: next_cursor,
            } => {
                let Some(next_last) = next_cursor.last_key().cloned() else {
                    return Err(OrderedContentConformanceError::HasMoreWithoutLastKey {
                        page_index,
                    });
                };
                if next_last != last_key {
                    return Err(OrderedContentConformanceError::ResumeCursorMismatch {
                        page_index,
                        expected_last: last_key,
                        actual_last: next_last,
                    });
                }
                if let Some(prev) = previous_last.as_ref()
                    && next_last <= *prev
                {
                    return Err(OrderedContentConformanceError::CursorDidNotAdvance {
                        page_index,
                        previous_last: prev.clone(),
                        observed_key: next_last,
                    });
                }
                previous_last = Some(next_last.clone());
                cursor = next_cursor.clone();
            }
            PageState::Complete => {
                let exhausted = source
                    .fill_page(shard, &Cursor::with_last_key(last_key.clone()), budgets)
                    .map_err(|source| OrderedContentConformanceError::Enumerate {
                        phase: "post-complete-exhaustion-check",
                        page_index,
                        source,
                    })?;
                if exhausted.is_some() {
                    return Err(OrderedContentConformanceError::CompletePageDidNotExhaust {
                        page_index,
                    });
                }
                return Ok(OrderedContentDrain::new(items, page_lengths));
            }
        }
    }

    Err(OrderedContentConformanceError::TooManyPages { limit: max_pages })
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io;

    use crate::{
        connector::{PageBuf, ReadError, ordered::OrderedContentCapabilities},
        identity::ObjectVersionId,
    };

    #[derive(Clone)]
    struct ScriptedSource {
        steps: Vec<Result<Option<PageBuf<ScanItem>>, EnumerateError>>,
        next: usize,
    }

    impl ScriptedSource {
        fn new(steps: Vec<Result<Option<PageBuf<ScanItem>>, EnumerateError>>) -> Self {
            Self { steps, next: 0 }
        }
    }

    impl OrderedContentSource for ScriptedSource {
        fn capabilities(&self) -> OrderedContentCapabilities {
            OrderedContentCapabilities::default()
        }

        fn fill_page(
            &mut self,
            _shard: &ShardSpec,
            _cursor: &Cursor,
            _budgets: Budgets,
        ) -> Result<Option<PageBuf<ScanItem>>, EnumerateError> {
            let out = self.steps.get(self.next).cloned().unwrap_or(Ok(None));
            self.next += 1;
            out
        }

        fn open(
            &mut self,
            _item_ref: &ItemRef,
            _budgets: Budgets,
        ) -> Result<Box<dyn io::Read + Send>, ReadError> {
            Err(ReadError::unsupported("unused in conformance tests"))
        }
    }

    #[derive(Clone)]
    struct CursorAwareSource {
        items: Vec<ScanItem>,
        page_len: usize,
    }

    impl OrderedContentSource for CursorAwareSource {
        fn capabilities(&self) -> OrderedContentCapabilities {
            OrderedContentCapabilities::default()
        }

        fn fill_page(
            &mut self,
            _shard: &ShardSpec,
            cursor: &Cursor,
            budgets: Budgets,
        ) -> Result<Option<PageBuf<ScanItem>>, EnumerateError> {
            let start = cursor
                .last_key()
                .map(|last_key| {
                    self.items
                        .iter()
                        .position(|item| item.item_key() > last_key)
                        .unwrap_or(self.items.len())
                })
                .unwrap_or(0);
            if start >= self.items.len() {
                return Ok(None);
            }

            let page_len = self.page_len.min(budgets.max_items());
            let end = (start + page_len).min(self.items.len());
            let page_items = self.items[start..end].to_vec();
            let state = if end == self.items.len() {
                PageState::Complete
            } else {
                PageState::HasMore {
                    cursor: Cursor::with_last_key(
                        page_items
                            .last()
                            .expect("page_items is non-empty")
                            .item_key()
                            .clone(),
                    ),
                }
            };

            Ok(Some(
                PageBuf::try_new_validated(page_items, state, b"", b"")
                    .expect("cursor-aware source emits valid pages"),
            ))
        }

        fn open(
            &mut self,
            _item_ref: &ItemRef,
            _budgets: Budgets,
        ) -> Result<Box<dyn io::Read + Send>, ReadError> {
            Err(ReadError::unsupported("unused in conformance tests"))
        }
    }

    fn scan_item(key: &[u8], seed: u8) -> ScanItem {
        let key = ItemKey::try_from_slice(key).expect("valid key");
        let item_ref = ItemRef::try_from_slice(key.as_bytes()).expect("valid item_ref");
        ScanItem::new(
            key,
            item_ref,
            StableItemId::from_bytes([seed; 32]),
            VersionId::Weak(ObjectVersionId::from_bytes([seed.wrapping_add(1); 32])),
        )
        .with_size_hint(seed as u64 + 1)
    }

    fn page(items: Vec<ScanItem>, state: PageState) -> PageBuf<ScanItem> {
        PageBuf::try_new_validated(items, state, b"", b"").expect("valid scripted page")
    }

    #[test]
    fn run_conformance_accepts_valid_scripted_source() {
        let drain = run_ordered_content_conformance(
            || CursorAwareSource {
                items: vec![scan_item(b"a", 1), scan_item(b"b", 2), scan_item(b"c", 3)],
                page_len: 2,
            },
            &ShardSpec::unbounded(),
            2,
            u64::MAX,
            &[],
        )
        .expect("scripted source should pass conformance");

        let keys: Vec<&[u8]> = drain
            .items()
            .iter()
            .map(|item| item.item_key().as_bytes())
            .collect();
        assert_eq!(
            keys,
            vec![b"a".as_slice(), b"b".as_slice(), b"c".as_slice()]
        );
        assert_eq!(drain.page_lengths(), &[2, 1]);
    }

    #[test]
    fn drain_rejects_complete_page_followed_by_more() {
        let script = vec![
            Ok(Some(page(vec![scan_item(b"a", 1)], PageState::Complete))),
            Ok(Some(page(vec![scan_item(b"b", 2)], PageState::Complete))),
        ];
        let mut source = ScriptedSource::new(script);

        let err = drain_ordered_source(&mut source, &ShardSpec::unbounded(), 8, u64::MAX)
            .expect_err("complete page followed by more items must fail");
        assert!(matches!(
            err,
            OrderedContentConformanceError::CompletePageDidNotExhaust { page_index: 0 }
        ));
    }

    #[test]
    fn drain_rejects_resume_cursor_mismatch() {
        let script = vec![Ok(Some(page(
            vec![scan_item(b"a", 1)],
            PageState::HasMore {
                cursor: Cursor::with_last_key(ItemKey::try_from_slice(b"b").unwrap()),
            },
        )))];
        let mut source = ScriptedSource::new(script);

        let err = drain_ordered_source(&mut source, &ShardSpec::unbounded(), 8, u64::MAX)
            .expect_err("mismatched resume cursor must fail");
        assert!(matches!(
            err,
            OrderedContentConformanceError::ResumeCursorMismatch { page_index: 0, .. }
        ));
    }

    #[test]
    fn no_item_ref_contains_rejects_forbidden_fragment() {
        let drain = OrderedContentDrain::new(
            vec![ObservedScanItem::from(&scan_item(b"safe/secret.txt", 9))],
            vec![1],
        );

        let err = assert_no_item_ref_contains(&drain, &[b"secret".as_slice()])
            .expect_err("forbidden fragment must be rejected");
        assert!(matches!(
            err,
            OrderedContentConformanceError::ForbiddenItemRefFragment { item_index: 0, .. }
        ));
    }

    #[test]
    fn drain_rejects_cursor_that_does_not_advance() {
        // Page 2's first key ("a") does not advance past page 1's last key
        // ("b"), so the harness must detect the regression.
        let script = vec![
            Ok(Some(page(
                vec![scan_item(b"b", 1)],
                PageState::HasMore {
                    cursor: Cursor::with_last_key(ItemKey::try_from_slice(b"b").unwrap()),
                },
            ))),
            Ok(Some(page(vec![scan_item(b"a", 2)], PageState::Complete))),
        ];
        let mut source = ScriptedSource::new(script);

        let err = drain_ordered_source(&mut source, &ShardSpec::unbounded(), 8, u64::MAX)
            .expect_err("regressing cursor must fail");
        assert!(matches!(
            err,
            OrderedContentConformanceError::CursorDidNotAdvance { page_index: 1, .. }
        ));
    }

    #[test]
    fn drain_rejects_source_exceeding_max_pages() {
        // Source that always returns HasMore with a properly advancing key.
        // With max_pages=2 the harness must bail after two pages.
        struct InfiniteSource {
            next_key: u32,
        }

        impl OrderedContentSource for InfiniteSource {
            fn capabilities(&self) -> OrderedContentCapabilities {
                OrderedContentCapabilities::default()
            }

            fn fill_page(
                &mut self,
                _shard: &ShardSpec,
                _cursor: &Cursor,
                _budgets: Budgets,
            ) -> Result<Option<PageBuf<ScanItem>>, EnumerateError> {
                let key_bytes = format!("key-{:08x}", self.next_key);
                self.next_key += 1;
                let item = scan_item(key_bytes.as_bytes(), (self.next_key & 0xff) as u8);
                let last_key = item.item_key().clone();
                Ok(Some(
                    PageBuf::try_new_validated(
                        vec![item],
                        PageState::HasMore {
                            cursor: Cursor::with_last_key(last_key),
                        },
                        b"",
                        b"",
                    )
                    .expect("infinite source emits valid pages"),
                ))
            }

            fn open(
                &mut self,
                _item_ref: &ItemRef,
                _budgets: Budgets,
            ) -> Result<Box<dyn io::Read + Send>, ReadError> {
                Err(ReadError::unsupported("unused"))
            }
        }

        let budgets = Budgets::try_new(8, u64::MAX, None).expect("valid budgets");
        let mut source = InfiniteSource { next_key: 0 };
        let err = drain_from_cursor(
            &mut source,
            &ShardSpec::unbounded(),
            Cursor::initial(),
            budgets,
            2,
        )
        .expect_err("source exceeding max_pages must fail");
        assert!(matches!(
            err,
            OrderedContentConformanceError::TooManyPages { limit: 2 }
        ));
    }

    #[test]
    fn drain_rejects_has_more_without_last_key() {
        // HasMore cursor with no last_key violates the ordered-content
        // contract — the harness must reject it.
        let script = vec![Ok(Some(page(
            vec![scan_item(b"a", 1)],
            PageState::HasMore {
                cursor: Cursor::initial(),
            },
        )))];
        let mut source = ScriptedSource::new(script);

        let err = drain_ordered_source(&mut source, &ShardSpec::unbounded(), 8, u64::MAX)
            .expect_err("HasMore without last_key must fail");
        assert!(matches!(
            err,
            OrderedContentConformanceError::HasMoreWithoutLastKey { page_index: 0 }
        ));
    }

    #[test]
    fn repeatable_drain_rejects_nondeterministic_factory() {
        // Factory returns different items on the second call.
        let call_count = std::cell::Cell::new(0u32);
        let err = assert_repeatable_drain(
            &mut || {
                let n = call_count.get();
                call_count.set(n + 1);
                let items = if n == 0 {
                    vec![scan_item(b"a", 1), scan_item(b"b", 2)]
                } else {
                    vec![scan_item(b"a", 1), scan_item(b"c", 3)]
                };
                CursorAwareSource { items, page_len: 8 }
            },
            &ShardSpec::unbounded(),
            8,
            u64::MAX,
        )
        .expect_err("nondeterministic factory must fail");
        assert!(matches!(
            err,
            OrderedContentConformanceError::DeterminismMismatch {
                first_divergent_item: Some(1),
            }
        ));
    }

    #[test]
    fn resume_after_corrupt_token_rejects_token_sensitive_source() {
        // Source that changes its output when the cursor carries a token,
        // violating the key-only fallback requirement.
        struct TokenSensitiveSource {
            items: Vec<ScanItem>,
            page_len: usize,
        }

        impl OrderedContentSource for TokenSensitiveSource {
            fn capabilities(&self) -> OrderedContentCapabilities {
                OrderedContentCapabilities::default()
            }

            fn fill_page(
                &mut self,
                _shard: &ShardSpec,
                cursor: &Cursor,
                budgets: Budgets,
            ) -> Result<Option<PageBuf<ScanItem>>, EnumerateError> {
                let start = cursor
                    .last_key()
                    .and_then(|last_key| {
                        self.items
                            .iter()
                            .position(|item| item.item_key() == last_key)
                            .map(|index| index + 1)
                    })
                    .unwrap_or(0);

                // When a token is present, skip an extra item — this violates
                // the contract because key-only and token resume must agree.
                let start = if cursor.token().is_some() {
                    (start + 1).min(self.items.len())
                } else {
                    start
                };

                if start >= self.items.len() {
                    return Ok(None);
                }

                let page_len = self.page_len.min(budgets.max_items());
                let end = (start + page_len).min(self.items.len());
                let page_items = self.items[start..end].to_vec();
                let state = if end == self.items.len() {
                    PageState::Complete
                } else {
                    PageState::HasMore {
                        cursor: Cursor::with_last_key(
                            page_items.last().unwrap().item_key().clone(),
                        ),
                    }
                };

                Ok(Some(
                    PageBuf::try_new_validated(page_items, state, b"", b"")
                        .expect("token-sensitive source emits valid pages"),
                ))
            }

            fn open(
                &mut self,
                _item_ref: &ItemRef,
                _budgets: Budgets,
            ) -> Result<Box<dyn io::Read + Send>, ReadError> {
                Err(ReadError::unsupported("unused"))
            }
        }

        // Needs 3+ items so the first-page probe (max_items=1) gets HasMore,
        // and the clean vs corrupt suffixes differ.
        let err = assert_resume_after_corrupt_token(
            &mut || TokenSensitiveSource {
                items: vec![
                    scan_item(b"a", 1),
                    scan_item(b"b", 2),
                    scan_item(b"c", 3),
                    scan_item(b"d", 4),
                ],
                page_len: 8,
            },
            &ShardSpec::unbounded(),
            1,
            8,
            u64::MAX,
        )
        .expect_err("token-sensitive source must fail");
        assert!(matches!(
            err,
            OrderedContentConformanceError::TokenFallbackMismatch {
                first_divergent_item: Some(_),
            }
        ));
    }

    #[test]
    fn drain_rejects_zero_budget() {
        let mut source = CursorAwareSource {
            items: vec![scan_item(b"a", 1)],
            page_len: 8,
        };
        let err = drain_ordered_source(&mut source, &ShardSpec::unbounded(), 0, u64::MAX)
            .expect_err("zero max_items budget must fail");
        assert!(matches!(
            err,
            OrderedContentConformanceError::InvalidBudgets(_)
        ));
    }

    #[test]
    fn drain_propagates_enumerate_error() {
        let script = vec![Err(EnumerateError::retryable("simulated transient fault"))];
        let mut source = ScriptedSource::new(script);

        let err = drain_ordered_source(&mut source, &ShardSpec::unbounded(), 8, u64::MAX)
            .expect_err("source error must propagate");
        assert!(matches!(
            err,
            OrderedContentConformanceError::Enumerate {
                phase: "drain",
                page_index: 0,
                ..
            }
        ));
    }

    #[test]
    fn drain_rejects_invalid_page() {
        // Build a page with out-of-order keys via try_new (which skips shape
        // validation). The drain loop's validate_filled_page call catches it.
        let bad_page = PageBuf::try_new(
            vec![scan_item(b"z", 1), scan_item(b"a", 2)],
            PageState::Complete,
        )
        .expect("try_new only checks non-empty");
        let script = vec![Ok(Some(bad_page))];
        let mut source = ScriptedSource::new(script);

        let err = drain_ordered_source(&mut source, &ShardSpec::unbounded(), 8, u64::MAX)
            .expect_err("out-of-order keys must fail page validation");
        assert!(matches!(
            err,
            OrderedContentConformanceError::InvalidPage { page_index: 0, .. }
        ));
    }

    #[test]
    fn drain_rejects_has_more_then_none_then_non_empty() {
        // Source returns HasMore, then None, then a non-empty page on retry.
        // The harness must detect this inconsistency via the post-None
        // exhaustion probe.
        let script = vec![
            Ok(Some(page(
                vec![scan_item(b"a", 1)],
                PageState::HasMore {
                    cursor: Cursor::with_last_key(ItemKey::try_from_slice(b"a").unwrap()),
                },
            ))),
            Ok(None),
            Ok(Some(page(vec![scan_item(b"b", 2)], PageState::Complete))),
        ];
        let mut source = ScriptedSource::new(script);

        let err = drain_ordered_source(&mut source, &ShardSpec::unbounded(), 8, u64::MAX)
            .expect_err("has-more then none with remaining items must fail");
        assert!(matches!(
            err,
            OrderedContentConformanceError::NoneDidNotExhaust { page_index: 1 }
        ));
    }
}

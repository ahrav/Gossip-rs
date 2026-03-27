//! Reusable ordered-content connector conformance harness.
//!
//! The connector boundary requires more than page-local validation: callers
//! also need confidence that page sequences advance monotonically, resume from
//! `last_key` even when tokens are stale or corrupt, terminate cleanly with an
//! exhausted-empty `None` call, and do not leak connector-root credentials into
//! emitted [`ItemRef`] values.
//!
//! This module provides a small, reusable test kit for that purpose. It is
//! intentionally strict and assumes the factory passed to
//! [`run_ordered_content_conformance`] produces fresh sources over the same
//! fixed source view. That matches the intended filesystem ordered-content MVP.

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

const DEFAULT_MAX_PAGES: usize = 4096;
const CORRUPT_TOKEN_BYTES: &[u8] = b"ordered-content-conformance-corrupt-token";

/// Stable snapshot of one emitted [`ScanItem`] for conformance comparisons.
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
/// budgets. Keeping both the flattened items and page lengths lets the harness
/// detect nondeterministic repacking even when the item set itself is stable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrderedContentDrain {
    items: Vec<ObservedScanItem>,
    page_lengths: Vec<usize>,
}

impl OrderedContentDrain {
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
    HasMoreWithoutLastKey {
        page_index: usize,
    },
    /// A `HasMore` cursor's `last_key` did not match the last emitted key.
    ResumeCursorMismatch {
        page_index: usize,
        expected_last: ItemKey,
        actual_last: ItemKey,
    },
    /// A later page or resume cursor regressed or stalled instead of advancing.
    CursorDidNotAdvance {
        page_index: usize,
        previous_last: ItemKey,
        next_last: ItemKey,
    },
    /// After a `Complete` page, the suffix call still produced more items.
    CompletePageDidNotExhaust {
        page_index: usize,
    },
    /// The harness exceeded its hard safety cap on page count.
    TooManyPages {
        limit: usize,
    },
    /// Two fresh sources over the same fixed view produced different drains.
    DeterminismMismatch,
    /// Key-only resume and corrupt-token resume produced different suffixes.
    TokenFallbackMismatch,
    /// An emitted item reference contained a caller-supplied forbidden byte
    /// fragment (for example a root-path credential canary).
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
                next_last,
            } => write!(
                f,
                "ordered-content conformance page {page_index} did not advance: previous_last={previous_last}, next_last={next_last}"
            ),
            Self::CompletePageDidNotExhaust { page_index } => write!(
                f,
                "ordered-content conformance page {page_index} reported Complete but a suffix call still returned more items"
            ),
            Self::TooManyPages { limit } => write!(
                f,
                "ordered-content conformance exceeded the safety cap of {limit} pages"
            ),
            Self::DeterminismMismatch => write!(
                f,
                "ordered-content conformance fresh drains over the same view were not identical"
            ),
            Self::TokenFallbackMismatch => write!(
                f,
                "ordered-content conformance corrupt-token resume diverged from key-only resume"
            ),
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

/// Run the standard ordered-content conformance suite on a fresh-source factory.
///
/// The suite performs four checks:
///
/// 1. **Page-sequence validation** — drains the full source while checking
///    page-shape validation, strict cursor advancement, and exhausted-empty
///    behavior after a terminal page.
/// 2. **Determinism** — repeats the drain on a fresh source and requires an
///    identical item sequence and identical page partitioning.
/// 3. **Token fallback** — forces a multi-page probe and requires that a
///    corrupt opaque token with the same `last_key` resumes to the same suffix
///    as a key-only cursor.
/// 4. **No-credential item refs** — optionally verifies that emitted item
///    refs do not contain any caller-supplied forbidden byte fragments.
///
/// The returned [`OrderedContentDrain`] is the first successful drain, which
/// callers can use for connector-specific assertions about the exact item set.
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
///
/// The harness validates each non-empty page with [`validate_filled_page`],
/// requires `HasMore.cursor.last_key()` to equal the page's last emitted key,
/// and performs the required exhausted-empty suffix call after a `Complete`
/// page.
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
        return Err(OrderedContentConformanceError::DeterminismMismatch);
    }
    Ok(first)
}

/// Require that resume with a corrupt token falls back to key-only resume.
///
/// `first_page_max_items` should usually be `1` so the probe is forced to stop
/// after the first item when the source contains more than one item.
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

    validate_filled_page(first_page.items(), shard.key_range_start(), shard.key_range_end())
        .map_err(|source| OrderedContentConformanceError::InvalidPage {
            page_index: 0,
            source,
        })?;

    let PageState::HasMore { cursor } = first_page.state() else {
        return Ok(());
    };
    let Some(resume_key) = cursor.last_key().cloned() else {
        return Err(OrderedContentConformanceError::HasMoreWithoutLastKey {
            page_index: 0,
        });
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
        return Err(OrderedContentConformanceError::TokenFallbackMismatch);
    }
    Ok(())
}

/// Require that no emitted item reference contains any forbidden byte fragment.
///
/// Empty fragments are ignored.
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
            if item_ref.windows(fragment.len()).any(|window| window == fragment) {
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
            return Ok(OrderedContentDrain { items, page_lengths });
        };

        validate_filled_page(page.items(), shard.key_range_start(), shard.key_range_end()).map_err(
            |source| OrderedContentConformanceError::InvalidPage { page_index, source },
        )?;

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
                next_last: first_key,
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
            PageState::HasMore { cursor: next_cursor } => {
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
                        next_last,
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
                return Ok(OrderedContentDrain { items, page_lengths });
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
        let script = vec![
            Ok(Some(page(
                vec![scan_item(b"a", 1), scan_item(b"b", 2)],
                PageState::HasMore {
                    cursor: Cursor::with_last_key(ItemKey::try_from_slice(b"b").unwrap()),
                },
            ))),
            Ok(Some(page(vec![scan_item(b"c", 3)], PageState::Complete))),
        ];

        let drain = run_ordered_content_conformance(
            || ScriptedSource::new(script.clone()),
            &ShardSpec::unbounded(),
            2,
            u64::MAX,
            &[],
        )
        .expect("scripted source should pass conformance");

        let keys: Vec<&[u8]> = drain.items().iter().map(|item| item.item_key().as_bytes()).collect();
        assert_eq!(keys, vec![b"a".as_slice(), b"b".as_slice(), b"c".as_slice()]);
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
        let drain = OrderedContentDrain {
            items: vec![ObservedScanItem::from(&scan_item(b"safe/secret.txt", 9))],
            page_lengths: vec![1],
        };

        let err = assert_no_item_ref_contains(&drain, &[b"secret".as_slice()])
            .expect_err("forbidden fragment must be rejected");
        assert!(matches!(
            err,
            OrderedContentConformanceError::ForbiddenItemRefFragment { item_index: 0, .. }
        ));
    }
}

//! Ordered-content connector family contract.
//!
//! This module defines the first concrete source family built on top of the
//! shared paging vocabulary from [`super::common`]. It is the contract for
//! sources whose worker loop is naturally:
//!
//! 1. discover a bounded ordered page of content items,
//! 2. optionally skip already-durable items,
//! 3. open or range-read item bytes,
//! 4. scan content,
//! 5. durably commit results,
//! 6. checkpoint the committed prefix.
//!
//! ## Intended sources
//!
//! This family is appropriate for content namespaces such as:
//!
//! - filesystem trees,
//! - object stores,
//! - manifest-backed content sources once materialized as [`ScanItem`]s,
//! - document and attachment APIs,
//! - hosted-code metadata surfaces such as pull request bodies or comments.
//!
//! ## Not intended for
//!
//! This family is intentionally **not** the contract for Git history or
//! repo-native execution. Those live in a separate Git family because flattening
//! repo execution into `ScanItem/open/read_range` would throw away the richer
//! execution model already present in `scanner-git`.
//!
//! ## Runtime contract
//!
//! Implementations must obey the shared paging invariants from
//! [`super::common`], plus the following family-specific rules:
//!
//! - `fill_page(...)` produces [`ScanItem`] values in canonical source order.
//! - `fill_page(...)` must treat the supplied [`PageBuf`] as scratch output.
//! - on `Ok(PageState::Progress { .. })`, the output buffer must be non-empty.
//! - on `Ok(PageState::Exhausted)`, the output buffer must be empty.
//! - on `Err(...)`, the output buffer must be empty.
//! - `Cursor.last_key` remains the authoritative progress primitive.
//! - a returned token is acceleration only; if the runtime commits only a strict
//!   prefix of a page it must drop the token and checkpoint only the committed
//!   prefix key.
//!
//! The runtime owns retry, backoff, lease handling, and persistence ordering.
//! This module defines the connector-side contract only.

use std::io;

use crate::coordination::ShardSpec;

use super::{
    Budgets, ConnectorCapabilities, EnumerateError, ItemKey, ItemRef, ReadError, ScanItem,
};
use super::common::{PageBuf, PageState, PagingCapabilities};

/// Family-specific capability declaration for [`OrderedContentSource`].
///
/// This is intentionally narrower than a fake universal capability matrix. The
/// ordered-content family reuses shared paging flags and adds only one extra
/// bit: whether byte-range reads are supported.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OrderedContentCapabilities {
    /// Shared ordered-paging capability flags.
    pub paging: PagingCapabilities,
    /// Whether the source can serve byte-range reads for item content.
    pub range_read: bool,
}

impl OrderedContentCapabilities {
    /// Construct an ordered-content capability set from explicit booleans.
    #[inline]
    #[must_use]
    pub const fn new(
        seek_by_key: bool,
        token_resume: bool,
        split_hints: bool,
        range_read: bool,
    ) -> Self {
        Self {
            paging: PagingCapabilities::new(seek_by_key, token_resume, split_hints),
            range_read,
        }
    }

    /// Construct an ordered-content capability set from shared paging flags.
    #[inline]
    #[must_use]
    pub const fn from_paging(paging: PagingCapabilities, range_read: bool) -> Self {
        Self { paging, range_read }
    }
}

impl From<OrderedContentCapabilities> for ConnectorCapabilities {
    #[inline]
    fn from(value: OrderedContentCapabilities) -> Self {
        Self {
            seek_by_key: value.paging.seek_by_key,
            token_resume: value.paging.token_resume,
            range_read: value.range_read,
            split_hints: value.paging.split_hints,
        }
    }
}

impl From<ConnectorCapabilities> for OrderedContentCapabilities {
    #[inline]
    fn from(value: ConnectorCapabilities) -> Self {
        Self {
            paging: PagingCapabilities::new(
                value.seek_by_key,
                value.token_resume,
                value.split_hints,
            ),
            range_read: value.range_read,
        }
    }
}

/// Ordered content source contract.
///
/// This trait is deliberately narrow. It is for finite, ordered content scans
/// where work units are individual [`ScanItem`]s and content is read through
/// [`open`](Self::open) or optionally [`read_range`](Self::read_range).
///
/// It is not the contract for Git repo-native execution or push/feed style
/// sources.
pub trait OrderedContentSource: Send {
    /// Static capability declaration for this ordered-content source.
    fn capabilities(&self) -> OrderedContentCapabilities;

    /// Fill one bounded, ordered page of [`ScanItem`]s into `out`.
    ///
    /// The source must honor `budgets.max_items()` as a hard cap. The
    /// `budgets.max_bytes()` value is a best-effort planning bound used to keep
    /// page discovery bounded; it must not force a zero-item progress page when
    /// the next item is individually large.
    ///
    /// Deadline or budget expiry should surface as
    /// [`EnumerateError::retryable(...)`](EnumerateError::retryable), not as an
    /// empty non-terminal page.
    fn fill_page(
        &mut self,
        shard: &ShardSpec,
        after: &super::Cursor,
        budgets: Budgets,
        out: &mut PageBuf<ScanItem>,
    ) -> Result<PageState, EnumerateError>;

    /// Suggest a split point strictly inside the remaining shard suffix.
    ///
    /// Returned keys are advisory only. The runtime must still validate that a
    /// suggested key is greater than `after.last_key()` and less than the
    /// shard's exclusive upper bound before issuing a residual split.
    fn choose_split_point(
        &mut self,
        shard: &ShardSpec,
        after: &super::Cursor,
        budgets: Budgets,
    ) -> Result<Option<ItemKey>, EnumerateError>;

    /// Open the full content for an item.
    fn open(
        &mut self,
        item_ref: &ItemRef,
        budgets: Budgets,
    ) -> Result<Box<dyn io::Read + Send>, ReadError>;

    /// Read a byte range from item content.
    ///
    /// The default implementation reports an unsupported operation. Sources
    /// that advertise `range_read = true` must override this method.
    fn read_range(
        &mut self,
        _item_ref: &ItemRef,
        _offset: u64,
        _dst: &mut [u8],
        _budgets: Budgets,
    ) -> Result<usize, ReadError> {
        Err(ReadError::unsupported("range_read"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Cursor as IoCursor;

    use crate::{
        connector::{Cursor, ItemRef, VersionId},
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

    struct DummySource {
        caps: OrderedContentCapabilities,
    }

    impl OrderedContentSource for DummySource {
        fn capabilities(&self) -> OrderedContentCapabilities {
            self.caps
        }

        fn fill_page(
            &mut self,
            _shard: &ShardSpec,
            _after: &Cursor,
            _budgets: Budgets,
            out: &mut PageBuf<ScanItem>,
        ) -> Result<PageState, EnumerateError> {
            out.clear();
            out.push(item(1, b"b"));
            Ok(PageState::Progress {
                next_cursor: Cursor::with_last_key(key(b"b")),
                exhausted: false,
            })
        }

        fn choose_split_point(
            &mut self,
            _shard: &ShardSpec,
            _after: &Cursor,
            _budgets: Budgets,
        ) -> Result<Option<ItemKey>, EnumerateError> {
            Ok(None)
        }

        fn open(
            &mut self,
            _item_ref: &ItemRef,
            _budgets: Budgets,
        ) -> Result<Box<dyn io::Read + Send>, ReadError> {
            Ok(Box::new(IoCursor::new(Vec::<u8>::new())))
        }
    }

    #[test]
    fn ordered_content_capabilities_convert_to_connector_capabilities() {
        let caps = OrderedContentCapabilities::new(true, false, true, true);
        let shared: ConnectorCapabilities = caps.into();

        assert_eq!(
            shared,
            ConnectorCapabilities {
                seek_by_key: true,
                token_resume: false,
                range_read: true,
                split_hints: true,
            }
        );
    }

    #[test]
    fn ordered_content_capabilities_convert_from_connector_capabilities() {
        let shared = ConnectorCapabilities {
            seek_by_key: true,
            token_resume: true,
            range_read: false,
            split_hints: true,
        };
        let caps = OrderedContentCapabilities::from(shared);

        assert_eq!(caps.paging, PagingCapabilities::new(true, true, true));
        assert!(!caps.range_read);
    }

    #[test]
    fn default_read_range_is_unsupported() {
        let mut source = DummySource {
            caps: OrderedContentCapabilities::new(true, false, false, false),
        };

        let err = source
            .read_range(&item_ref(b"b"), 0, &mut [0_u8; 8], budgets(8))
            .expect_err("default read_range must report unsupported");

        assert!(!err.is_retryable());
        assert_eq!(err.message(), "range_read not supported");
    }

    #[test]
    fn fill_page_output_validates_with_common_page_rules() {
        let mut source = DummySource {
            caps: OrderedContentCapabilities::new(true, false, true, false),
        };
        let shard = ShardSpec::with_range(b"a", b"z");
        let mut out = PageBuf::new();
        let state = source
            .fill_page(&shard, &Cursor::initial(), budgets(8), &mut out)
            .expect("page fill should succeed");

        let result = super::super::common::validate_filled_page(
            &out,
            &state,
            &shard,
            &Cursor::initial(),
            source.capabilities().paging,
            budgets(8),
        );

        assert_eq!(result, Ok(()));
    }
}

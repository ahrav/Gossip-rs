//! Ordered-content connector family contract.
//!
//! Defines a source family built on the shared paging vocabulary ([`PageBuf`],
//! [`super::PageState`]). It models sources where the worker loop executes the
//! following sequence:
//!
//! 1. Fill a bounded ordered page of [`ScanItem`] values.
//! 2. Scan or skip committed items.
//! 3. Open or range-read item bytes.
//! 4. Checkpoint durable progress using the page's terminal state.
//!
//! ## Design Trade-offs
//! This model is intentionally narrower than a universal connector trait. Sources
//! operating on aggregate states (e.g., full Git repositories) rather than
//! item-by-item byte reads belong in separate, specialized families.

use std::io;

use crate::coordination::ShardSpec;

use super::common::PageBuf;
use super::{Budgets, Cursor, EnumerateError, ItemKey, ItemRef, ReadError, ScanItem};

/// Capability flags specific to ordered-content sources.
///
/// `Default` produces a conservative "no optional features" profile.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OrderedContentCapabilities {
    /// Whether the source can serve byte-range reads for item content.
    pub range_read: bool,
    /// Whether the source can emit split-point hints for re-sharding.
    pub split_hints: bool,
    /// Whether the source may require a connector-opaque resume token in
    /// addition to the ordered key cursor.
    pub token_resume: bool,
}

/// Ordered content source contract.
///
/// Implementations enumerate [`ScanItem`] values in canonical source order and
/// expose corresponding bytes through [`open`](Self::open) and optionally
/// [`read_range`](Self::read_range).
///
/// ## Mutability
/// Methods take `&mut self` because implementations maintain mutable internal
/// state (e.g., connection handles, cached pagination position, directory
/// iterators, or lazy index structures). For concurrent multi-shard enumeration,
/// clone the source instance or wrap in `Arc<Mutex<dyn OrderedContentSource>>`.
pub trait OrderedContentSource: Send {
    fn capabilities(&self) -> OrderedContentCapabilities;

    /// Fills one bounded page of ordered content items within `shard`.
    ///
    /// ## Guarantees
    /// Returns `Ok(Some(page))` with a non-empty page of items, or `Ok(None)`
    /// to signal terminal completion when no in-scope items remain.
    ///
    /// ## Errors
    /// Returns `EnumerateError` if enumeration fails or budgets are exhausted.
    fn fill_page(
        &mut self,
        shard: &ShardSpec,
        cursor: &Cursor,
        budgets: Budgets,
    ) -> Result<Option<PageBuf<ScanItem>>, EnumerateError>;

    /// Suggests a split point strictly inside the remaining shard suffix.
    ///
    /// ## Guarantees
    /// Returns `Ok(None)` if the source does not support split hints or has
    /// no suggestion for the current position.
    ///
    /// ## Errors
    /// Returns `EnumerateError` if hint generation fails.
    fn choose_split_point(
        &mut self,
        _shard: &ShardSpec,
        _cursor: &Cursor,
        _budgets: Budgets,
    ) -> Result<Option<ItemKey>, EnumerateError> {
        Ok(None)
    }

    /// Opens the full content stream for an item.
    ///
    /// ## Errors
    /// Returns `ReadError` if the item stream cannot be opened.
    fn open(
        &mut self,
        item_ref: &ItemRef,
        budgets: Budgets,
    ) -> Result<Box<dyn io::Read + Send>, ReadError>;

    /// Reads a byte range from item content.
    ///
    /// ## Guarantees
    /// Returns the number of bytes written into `dst` (may be less than `dst.len()`).
    /// Returns `Ok(0)` when `offset` is at or past the end of item content.
    ///
    /// ## Errors
    /// - Returns `ReadError::unsupported` if the source does not advertise `range_read`.
    /// - Returns `ReadError` if `offset + dst.len()` would overflow `u64`.
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

    struct StubSource;

    impl OrderedContentSource for StubSource {
        fn capabilities(&self) -> OrderedContentCapabilities {
            OrderedContentCapabilities::default()
        }

        fn fill_page(
            &mut self,
            _shard: &ShardSpec,
            _cursor: &Cursor,
            _budgets: Budgets,
        ) -> Result<Option<PageBuf<ScanItem>>, EnumerateError> {
            Err(EnumerateError::permanent("stub"))
        }

        fn open(
            &mut self,
            _item_ref: &ItemRef,
            _budgets: Budgets,
        ) -> Result<Box<dyn io::Read + Send>, ReadError> {
            Err(ReadError::permanent("stub"))
        }
    }

    #[test]
    fn default_capabilities_are_conservative() {
        let caps = OrderedContentCapabilities::default();
        assert!(!caps.range_read);
        assert!(!caps.split_hints);
        assert!(!caps.token_resume);
    }

    #[test]
    fn ordered_content_source_requires_send() {
        fn assert_send<T: Send>() {}
        fn assert_source<T: OrderedContentSource>() {}

        assert_send::<StubSource>();
        assert_source::<StubSource>();
    }

    #[test]
    fn ordered_content_source_is_object_safe() {
        fn assert_object_safe(_: &dyn OrderedContentSource) {}
        let _ = assert_object_safe;
    }

    #[test]
    fn default_choose_split_point_returns_none() {
        let shard = ShardSpec::unbounded();
        let cursor = Cursor::initial();
        let budgets = Budgets::try_new(1, 1, None).unwrap();
        let mut src = StubSource;
        assert_eq!(
            src.choose_split_point(&shard, &cursor, budgets).unwrap(),
            None,
        );
    }

    #[test]
    fn default_read_range_returns_unsupported() {
        let item_ref = ItemRef::try_from_vec(vec![1]).unwrap();
        let budgets = Budgets::try_new(1, 1, None).unwrap();
        let mut src = StubSource;
        let err = src
            .read_range(&item_ref, 0, &mut [0u8; 4], budgets)
            .unwrap_err();
        assert!(!err.is_retryable());
        assert!(
            err.message().contains("range_read"),
            "expected 'range_read' in message, got: {}",
            err.message()
        );
    }
}

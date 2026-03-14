//! Ordered-content connector family contract.
//!
//! This module defines the first concrete source family built on top of the
//! shared paging vocabulary ([`PageBuf`], [`super::PageState`]). It models
//! sources whose worker loop is naturally:
//! worker loop is naturally:
//!
//! 1. fill a bounded ordered page of [`ScanItem`] values,
//! 2. scan or skip committed items,
//! 3. open or range-read item bytes,
//! 4. checkpoint durable progress using the page's terminal state.
//!
//! This family is intentionally narrower than a fake one-trait-fits-all
//! connector model. Git repo-native execution is not an ordered-content source;
//! it belongs in its own family because it operates on whole repositories
//! rather than item-by-item byte reads.

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
/// expose the corresponding bytes through [`open`](Self::open) and optionally
/// [`read_range`](Self::read_range).
///
/// ## Mutability
///
/// Methods take `&mut self` because implementations typically maintain mutable
/// internal state: connection handles, cached pagination position, directory
/// iterators, or index structures built lazily on first call. For concurrent
/// multi-shard enumeration, clone the source instance or wrap in
/// `Arc<Mutex<dyn OrderedContentSource>>`.
pub trait OrderedContentSource: Send {
    /// Returns the ordered-content features this source supports.
    fn capabilities(&self) -> OrderedContentCapabilities;

    /// Fill one bounded page of ordered content items within `shard`.
    ///
    /// Returns `Ok(Some(page))` with a non-empty page of items, or `Ok(None)`
    /// to signal terminal completion when no in-scope items remain (the empty
    /// terminal call in the two-call shard completion pattern).
    fn fill_page(
        &mut self,
        shard: &ShardSpec,
        cursor: &Cursor,
        budgets: Budgets,
    ) -> Result<Option<PageBuf<ScanItem>>, EnumerateError>;

    /// Suggest a split point strictly inside the remaining shard suffix.
    ///
    /// Returns `Ok(None)` when the source does not support split hints
    /// (the default) or has no suggestion for the current position.
    fn choose_split_point(
        &mut self,
        _shard: &ShardSpec,
        _cursor: &Cursor,
        _budgets: Budgets,
    ) -> Result<Option<ItemKey>, EnumerateError> {
        Ok(None)
    }

    /// Open the full content for an item.
    fn open(
        &mut self,
        item_ref: &ItemRef,
        budgets: Budgets,
    ) -> Result<Box<dyn io::Read + Send>, ReadError>;

    /// Read a byte range from item content.
    ///
    /// Returns the number of bytes written into `dst`, which may be less than
    /// `dst.len()`. Returns `Ok(0)` when `offset` is at or past the end of
    /// item content. Implementations must return an error if `offset + dst.len()`
    /// would overflow `u64`.
    ///
    /// Sources that do not advertise
    /// [`range_read`](OrderedContentCapabilities::range_read) return
    /// [`ReadError::unsupported`] (the default).
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
}

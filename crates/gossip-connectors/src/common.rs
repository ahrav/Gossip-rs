//! Shared connector utilities: shard-bound validation, binary search,
//! pooled page assembly, split-point selection, and identity derivation.

use std::sync::Arc;

use gossip_contracts::{
    connector::{
        ConnectorInputError, EnumerateError, ItemKey, ItemRef, MAX_ITEM_KEY_SIZE, PooledByteSlab,
        TokenBytes,
    },
    identity::{ConnectorTag, ItemIdentityKey, StableItemId},
};
use gossip_stdx::{ByteSlab, ByteSlot};

/// Parse an 8-byte big-endian `u64` from a byte slice.
///
/// Returns `None` for non-8-byte payloads, letting callers decide whether to
/// treat malformed values as permanent errors ([`ItemRef`] decoding) or as
/// advisory-state misses ([`Cursor`] tokens).
///
/// [`ItemRef`]: gossip_contracts::connector::ItemRef
/// [`Cursor`]: gossip_contracts::connector::Cursor
pub(crate) fn parse_u64_be(bytes: &[u8]) -> Option<u64> {
    let array: [u8; 8] = bytes.try_into().ok()?;
    Some(u64::from_be_bytes(array))
}

/// Derive a stable per-key identity via the canonical [`ItemIdentityKey`] path.
///
/// The hash input includes both the [`ConnectorTag`] and the key bytes under
/// domain-separated BLAKE3, so identical key bytes from different connectors
/// produce distinct IDs.
pub(crate) fn derive_stable_item_id(tag: ConnectorTag, key: &ItemKey) -> StableItemId {
    ItemIdentityKey::new(tag, key.as_bytes()).stable_id()
}

/// Validate a shard key-range bound where `[]` (empty) means unbounded.
///
/// Empty bounds are treated as unbounded to match [`ShardSpec`] semantics.
/// Non-empty bounds are validated allocation-free against [`ItemKey`] size
/// limits and then returned as borrowed slices, so callers can run binary
/// search without materializing temporary `ItemKey` wrappers.
///
/// This helper intentionally validates only boundary shape (`empty` vs
/// `<= MAX_ITEM_KEY_SIZE`): connector bound resolution is byte-lexicographic,
/// so no additional per-bound decoding is required.
/// Malformed payloads produce a permanent error including `which` for
/// diagnostics.
///
/// [`ShardSpec`]: gossip_contracts::coordination::ShardSpec
pub(crate) fn borrowed_shard_bound<'a>(
    bound: &'a [u8],
    which: &'static str,
) -> Result<Option<&'a [u8]>, EnumerateError> {
    if bound.is_empty() {
        return Ok(None);
    }
    if bound.len() > MAX_ITEM_KEY_SIZE {
        let err = ConnectorInputError::TooLarge {
            field: "ItemKey",
            size: bound.len(),
            max: MAX_ITEM_KEY_SIZE,
        };
        return Err(EnumerateError::permanent(format!(
            "invalid shard {which} bound: {err}"
        )));
    }
    Ok(Some(bound))
}

/// Trait abstraction for entries that expose a key byte slice.
///
/// Enables generic binary search (`lower_bound`, `upper_bound`) over both
/// `FileEntry` (filesystem connector) and `PreparedItem` (in-memory connector).
pub(crate) trait KeyedEntry {
    fn key_bytes(&self) -> &[u8];
}

/// Return the first index whose key is `>= key`.
pub(crate) fn lower_bound<T: KeyedEntry>(items: &[T], key: &[u8]) -> usize {
    items.partition_point(|item| item.key_bytes() < key)
}

/// Return the first index whose key is `> key`.
///
/// Used for resume progression so the last emitted key is never re-emitted.
pub(crate) fn upper_bound<T: KeyedEntry>(items: &[T], key: &[u8]) -> usize {
    items.partition_point(|item| item.key_bytes() <= key)
}

/// Trait abstraction for entries that expose a byte size.
///
/// Enables the generic [`choose_split_index`] to work over both
/// `FileEntry` (`.size`) and `PreparedItem` (`.size_hint`).
pub(crate) trait SizedEntry {
    fn entry_size(&self) -> u64;
}

/// Round a logical byte length to the slab allocation size.
///
/// Mirrors `ByteSlab`'s size-class rule: `0 -> 0`, otherwise
/// `max(len, 16).next_power_of_two()`.
/// Returns `None` when the rounded size overflows `usize`.
#[inline]
fn page_slab_alloc_size(len: usize) -> Option<usize> {
    if len == 0 {
        return Some(0);
    }
    len.max(gossip_stdx::MIN_BLOCK as usize)
        .checked_next_power_of_two()
}

/// Compute slab capacity needed for a page's staged byte fields.
///
/// Connectors pass all key/ref/token lengths for the page; this helper rounds
/// each field to the same size classes used by `ByteSlab` and sums the result.
///
/// Pre-sizing up front avoids partial staging work followed by a late slab-full
/// failure. Any failure here is treated as permanent because the inputs come
/// from already-validated boundary values.
///
/// # Errors
///
/// Returns `EnumerateError::permanent` when:
/// - any rounded field size overflows `usize`,
/// - the total rounded capacity overflows `usize`, or
/// - the final capacity exceeds `u32::MAX` (the slab offset domain).
pub(crate) fn page_slab_capacity(
    lengths: impl IntoIterator<Item = usize>,
) -> Result<usize, EnumerateError> {
    let mut capacity = 0usize;
    for len in lengths {
        let rounded = page_slab_alloc_size(len).ok_or_else(|| {
            EnumerateError::permanent(format!(
                "page slab field size overflow: len={len} exceeds rounding domain"
            ))
        })?;
        capacity = capacity.checked_add(rounded).ok_or_else(|| {
            EnumerateError::permanent(format!(
                "page slab capacity overflow: {capacity} + {rounded} exceeds usize::MAX"
            ))
        })?;
    }
    // When all fields are zero-length, ByteSlab returns EMPTY slots without
    // consuming slab space, so allocating a MIN_BLOCK-sized slab is wasted.
    if capacity == 0 {
        return Ok(0);
    }
    let capacity = capacity.max(gossip_stdx::MIN_BLOCK as usize);
    if capacity > u32::MAX as usize {
        return Err(EnumerateError::permanent(
            "page slab capacity exceeds u32::MAX",
        ));
    }
    Ok(capacity)
}

/// Materialized page of pooled toxic-byte wrappers.
///
/// Produced by [`assemble_pooled_page`] (generic two-slot path) and
/// [`assemble_pooled_page_shared_key_ref`] (shared-slot path for key==ref
/// connectors). Callers zip the returned `wrappers` with their
/// connector-specific metadata (e.g., `StableItemId`, `VersionId`, size
/// hints) to build [`ScanItem`]s.
pub(crate) struct StagedPage {
    /// Materialized (ItemKey, ItemRef) pairs, ready to zip with caller metadata.
    /// Each wrapper holds an `Arc<PooledByteSlab>` internally, keeping the
    /// backing slab alive as long as any wrapper exists.
    pub wrappers: Vec<(ItemKey, ItemRef)>,
    /// Optional continuation token (present when `emit_token` is true).
    pub token: Option<TokenBytes>,
}

/// Allocate the continuation-token slot into the page slab.
///
/// When `emit_token` is true, encodes `start_idx + item_count` as a
/// big-endian `u64` and stages it into `page_slab`. Returns `Ok(None)`
/// when token emission is disabled.
///
/// # Errors
///
/// Returns `EnumerateError::permanent` on index overflow or slab
/// allocation failure.
#[inline]
fn stage_token_slot(
    page_slab: &mut PooledByteSlab,
    emit_token: bool,
    start_idx: usize,
    item_count: usize,
) -> Result<Option<ByteSlot>, EnumerateError> {
    if !emit_token {
        return Ok(None);
    }
    let next_idx = start_idx
        .checked_add(item_count)
        .and_then(|sum| u64::try_from(sum).ok())
        .ok_or_else(|| EnumerateError::permanent("next index exceeds capacity"))?;
    let token_bytes = next_idx.to_be_bytes();
    page_slab.allocate(&token_bytes).map(Some).map_err(|err| {
        EnumerateError::permanent(format!("failed to stage token in page slab: {err}"))
    })
}

/// Stage key/ref byte pairs into a page-local slab and materialize wrappers.
///
/// Accepts an `ExactSizeIterator` of `(key_bytes, ref_bytes)` pairs. The
/// iterator is cloned internally: once for capacity pre-sizing, once for
/// staging. Callers supply the byte-pair iterator; this function handles
/// slab allocation, Arc wrapping, and wrapper reconstruction.
///
/// When `emit_token` is true, a big-endian `u64` token encoding `start_idx +
/// item_count` is staged into the same slab and returned as `StagedPage::token`.
///
/// # Errors
///
/// Returns `EnumerateError::permanent` on capacity overflow, key/ref/token
/// staging failures, token-index overflow, or wrapper reconstruction failure.
/// These indicate internal accounting/resource-exhaustion conditions because
/// inputs come from already-validated contract values.
pub(crate) fn assemble_pooled_page<'a>(
    key_ref_pairs: impl ExactSizeIterator<Item = (&'a [u8], &'a [u8])> + Clone,
    emit_token: bool,
    start_idx: usize,
) -> Result<StagedPage, EnumerateError> {
    let take = key_ref_pairs.len();

    // Phase 1: pre-size slab using ByteSlab size classes.
    let slab_capacity = page_slab_capacity(
        key_ref_pairs
            .clone()
            .flat_map(|(k, r)| [k.len(), r.len()])
            .chain(emit_token.then_some(std::mem::size_of::<u64>())),
    )?;

    // Phase 2: allocate and stage key/ref slots.
    let mut page_slab = PooledByteSlab::new(ByteSlab::with_capacity(slab_capacity));
    let mut staged: Vec<(ByteSlot, ByteSlot)> = Vec::with_capacity(take);
    for (item_idx, (key_bytes, ref_bytes)) in key_ref_pairs.enumerate() {
        let key_slot = page_slab.allocate(key_bytes).map_err(|err| {
            EnumerateError::permanent(format!(
                "failed to stage item key in page slab (item {item_idx}/{take}): {err}"
            ))
        })?;
        let ref_slot = page_slab.allocate(ref_bytes).map_err(|err| {
            EnumerateError::permanent(format!(
                "failed to stage item_ref in page slab (item {item_idx}/{take}): {err}"
            ))
        })?;
        staged.push((key_slot, ref_slot));
    }

    if staged.len() != take {
        return Err(EnumerateError::permanent(format!(
            "staged wrapper count mismatch: wrappers={}, expected={take}",
            staged.len()
        )));
    }

    // Phase 3: optionally stage continuation token.
    let token_slot = stage_token_slot(&mut page_slab, emit_token, start_idx, staged.len())?;

    // Phase 4: wrap in Arc for shared read access, reconstruct wrappers.
    let slab = Arc::new(page_slab);
    let mut wrappers = Vec::with_capacity(staged.len());
    for (key_slot, ref_slot) in staged {
        let item_key = ItemKey::try_from_slot(key_slot, Arc::clone(&slab))
            .map_err(|err| EnumerateError::permanent(format!("invalid staged item key: {err}")))?;
        let item_ref = ItemRef::try_from_slot(ref_slot, Arc::clone(&slab))
            .map_err(|err| EnumerateError::permanent(format!("invalid staged item_ref: {err}")))?;
        wrappers.push((item_key, item_ref));
    }

    let token = match token_slot {
        Some(slot) => Some(
            TokenBytes::try_from_slot(slot, Arc::clone(&slab))
                .map_err(|err| EnumerateError::permanent(format!("invalid staged token: {err}")))?,
        ),
        None => None,
    };

    Ok(StagedPage { wrappers, token })
}

/// Stage key bytes once and materialize both key/ref wrappers from one slot.
///
/// Filesystem enumeration uses this path because `ItemRef` bytes are
/// identical-by-construction to `ItemKey` bytes (encoded relative path).
/// This avoids redundant per-item slot staging while preserving pooled wrapper
/// behavior and shared continuation-token encoding.
///
/// Invariant: use this helper only when key bytes and ref bytes are exactly
/// equal for every item. The debug pointer-equality assertion verifies the
/// shared-slot contract in debug builds; release builds rely on caller
/// correctness.
///
/// # Errors
///
/// Returns `EnumerateError::permanent` on slab capacity overflow, staging
/// failure, wrapper reconstruction failure, or token-index overflow.
pub(crate) fn assemble_pooled_page_shared_key_ref<'a>(
    key_bytes: impl ExactSizeIterator<Item = &'a [u8]> + Clone,
    emit_token: bool,
    start_idx: usize,
) -> Result<StagedPage, EnumerateError> {
    let take = key_bytes.len();

    // One slot per key; refs reuse the same slot bytes.
    let slab_capacity = page_slab_capacity(
        key_bytes
            .clone()
            .map(|k| k.len())
            .chain(emit_token.then_some(std::mem::size_of::<u64>())),
    )?;

    let mut page_slab = PooledByteSlab::new(ByteSlab::with_capacity(slab_capacity));
    let mut staged: Vec<ByteSlot> = Vec::with_capacity(take);
    for (item_idx, key) in key_bytes.enumerate() {
        let slot = page_slab.allocate(key).map_err(|err| {
            EnumerateError::permanent(format!(
                "failed to stage filesystem key/item_ref in page slab (item {item_idx}/{take}): {err}"
            ))
        })?;
        staged.push(slot);
    }

    let token_slot = stage_token_slot(&mut page_slab, emit_token, start_idx, staged.len())?;

    let slab = Arc::new(page_slab);
    let mut wrappers = Vec::with_capacity(staged.len());
    for slot in staged {
        let item_key = ItemKey::try_from_slot(slot, Arc::clone(&slab))
            .map_err(|err| EnumerateError::permanent(format!("invalid staged item key: {err}")))?;
        let item_ref = ItemRef::try_from_slot(slot, Arc::clone(&slab))
            .map_err(|err| EnumerateError::permanent(format!("invalid staged item_ref: {err}")))?;
        debug_assert_eq!(
            item_key.as_bytes().as_ptr(),
            item_ref.as_bytes().as_ptr(),
            "filesystem key/ref wrappers must share staged backing bytes"
        );
        wrappers.push((item_key, item_ref));
    }
    if wrappers.len() != take {
        return Err(EnumerateError::permanent(format!(
            "staged wrapper count mismatch: wrappers={}, expected={take}",
            wrappers.len()
        )));
    }

    let token = match token_slot {
        Some(slot) => Some(
            TokenBytes::try_from_slot(slot, Arc::clone(&slab))
                .map_err(|err| EnumerateError::permanent(format!("invalid staged token: {err}")))?,
        ),
        None => None,
    };

    Ok(StagedPage { wrappers, token })
}

/// Byte-weighted median split-point selection.
///
/// Given a slice of items at indices `[start_idx, range_end)`, returns the
/// index where cumulative byte size crosses the halfway mark, producing
/// shards balanced by total byte volume rather than item count.
///
/// Falls back to a count-balanced midpoint when:
/// - All entries are zero-size (`total_bytes == 0`).
/// - All weight concentrates in the leading entry (`split_idx == start_idx`),
///   which would produce a zero-item left shard.
///
/// The result is clamped to `[start_idx + 1, range_end - 1]` to guarantee
/// at least one item on each side.
///
/// Returns `None` when fewer than two items remain in the range.
pub(crate) fn choose_split_index<T: SizedEntry>(
    items: &[T],
    start_idx: usize,
    range_end: usize,
) -> Option<usize> {
    if range_end.saturating_sub(start_idx) < 2 {
        return None;
    }

    let range = &items[start_idx..range_end];
    let total_bytes: u64 = range
        .iter()
        .map(|e| e.entry_size())
        .fold(0u64, u64::saturating_add);

    let split_idx = if total_bytes == 0 {
        start_idx + range.len() / 2
    } else {
        let half = total_bytes / 2;
        let mut cumulative = 0u64;
        let mut idx = start_idx;
        for (i, entry) in range.iter().enumerate() {
            cumulative = cumulative.saturating_add(entry.entry_size());
            if cumulative >= half {
                idx = start_idx + i;
                break;
            }
        }
        // Guard: if all weight concentrates in the first item, fall back
        // to count-balanced midpoint.
        if idx == start_idx {
            start_idx + (range_end - start_idx) / 2
        } else {
            idx
        }
    };

    // Clamp to ensure at least one item on each side.
    Some(split_idx.max(start_idx + 1).min(range_end - 1))
}

#[cfg(test)]
pub(crate) mod test_util {
    use gossip_contracts::connector::{Budgets, ItemKey};

    pub fn make_key(s: &[u8]) -> ItemKey {
        ItemKey::try_from_slice(s).expect("test key")
    }

    pub fn default_budgets() -> Budgets {
        Budgets::try_new(100, u64::MAX, None).unwrap()
    }

    pub fn small_page_budgets(max_items: usize) -> Budgets {
        Budgets::try_new(max_items, u64::MAX, None).unwrap()
    }
}

/// Tests for page-local slab capacity calculations.
///
/// These tests verify that `page_slab_alloc_size` and `page_slab_capacity`
/// correctly mirror `ByteSlab`'s size-class rounding and enforce overflow
/// protection. The rounding logic must match the slab allocator exactly so
/// pre-sizing eliminates mid-loop staging failures.
#[cfg(test)]
mod page_slab_tests {
    use super::*;

    #[test]
    fn alloc_size_zero_returns_zero() {
        assert_eq!(page_slab_alloc_size(0), Some(0));
    }

    #[test]
    fn alloc_size_small_values_round_to_min_block() {
        for n in 1..=gossip_stdx::MIN_BLOCK as usize {
            assert_eq!(
                page_slab_alloc_size(n),
                Some(gossip_stdx::MIN_BLOCK as usize),
                "page_slab_alloc_size({n}) should round to MIN_BLOCK"
            );
        }
    }

    #[test]
    fn alloc_size_power_of_two_identity() {
        for &n in &[32, 64, 128, 256, 1024, 4096] {
            assert_eq!(
                page_slab_alloc_size(n),
                Some(n),
                "page_slab_alloc_size({n}) should be identity for power-of-two"
            );
        }
    }

    #[test]
    fn alloc_size_rounds_up_non_power_of_two() {
        assert_eq!(page_slab_alloc_size(17), Some(32));
        assert_eq!(page_slab_alloc_size(33), Some(64));
        assert_eq!(page_slab_alloc_size(100), Some(128));
    }

    #[test]
    fn capacity_sums_rounded_fields() {
        // Two fields of 10 bytes each: both round to 16, total = 32.
        // Floor is MIN_BLOCK (16), so 32 >= 16 → result is 32.
        let cap = page_slab_capacity([10, 10]).unwrap();
        assert_eq!(cap, 32);
    }

    #[test]
    fn capacity_all_zero_returns_zero() {
        // All zero-length fields produce a zero sum. ByteSlab returns EMPTY
        // for zero-length allocations without consuming slab space, so a
        // zero capacity avoids wasting a MIN_BLOCK-sized slab.
        let cap = page_slab_capacity([0]).unwrap();
        assert_eq!(cap, 0);
    }

    #[test]
    fn capacity_errors_on_overflow() {
        // usize::MAX cannot be rounded to a power of two.
        let result = page_slab_capacity([usize::MAX]);
        assert!(result.is_err(), "expected overflow error for usize::MAX");
    }

    #[test]
    fn capacity_empty_iterator_returns_zero() {
        // No fields at all → zero capacity.
        let cap = page_slab_capacity(std::iter::empty::<usize>()).unwrap();
        assert_eq!(cap, 0);
    }

    #[test]
    fn capacity_mixed_zero_and_nonzero_applies_min_block() {
        // One zero-length field + one 10-byte field: zero rounds to 0,
        // 10 rounds to MIN_BLOCK (16). Total = 16, which is >= MIN_BLOCK.
        let cap = page_slab_capacity([0, 10]).unwrap();
        assert_eq!(cap, gossip_stdx::MIN_BLOCK as usize);
    }
}

#[cfg(test)]
mod borrowed_shard_bound_tests {
    use super::*;
    use gossip_contracts::connector::MAX_ITEM_KEY_SIZE;

    #[test]
    fn empty_bound_returns_none() {
        let result = borrowed_shard_bound(b"", "start").unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn valid_bound_returns_some() {
        let result = borrowed_shard_bound(b"abc", "start").unwrap();
        assert_eq!(result, Some(b"abc".as_slice()));
    }

    #[test]
    fn exact_max_size_returns_some() {
        let key = vec![b'x'; MAX_ITEM_KEY_SIZE];
        let result = borrowed_shard_bound(&key, "end").unwrap();
        assert_eq!(result, Some(key.as_slice()));
    }

    #[test]
    fn oversized_bound_returns_permanent_error() {
        let key = vec![b'x'; MAX_ITEM_KEY_SIZE + 1];
        let err = borrowed_shard_bound(&key, "start").expect_err("should reject oversized bound");
        assert!(!err.is_retryable(), "oversized bound should be permanent");
    }

    #[test]
    fn error_message_contains_which_param() {
        let key = vec![b'x'; MAX_ITEM_KEY_SIZE + 1];
        let err = borrowed_shard_bound(&key, "start").unwrap_err();
        assert!(
            err.message().contains("start"),
            "error should mention 'start': {}",
            err.message()
        );

        let err = borrowed_shard_bound(&key, "end").unwrap_err();
        assert!(
            err.message().contains("end"),
            "error should mention 'end': {}",
            err.message()
        );
    }
}

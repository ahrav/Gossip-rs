//! Shared utilities used by multiple connector implementations.

use gossip_contracts::{
    connector::{EnumerateError, ItemKey},
    identity::{ConnectorTag, ItemIdentityKey, StableItemId},
};

/// Must match `gossip_stdx::byte_slab::MIN_BLOCK` (16 bytes).
///
/// Keeping a local constant avoids exposing `gossip-stdx` internals from this
/// module while preserving identical size-class rounding.
const PAGE_SLAB_MIN_BLOCK: usize = 16;

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

/// Decode a shard key-range bound where `[]` (empty) means unbounded.
///
/// Empty bounds are treated as unbounded to match [`ShardSpec`] semantics.
/// Non-empty bounds are validated via [`ItemKey::try_from_slice`]; invalid
/// payloads produce a permanent error including `which` for diagnostics.
///
/// [`ShardSpec`]: gossip_contracts::coordination::ShardSpec
pub(crate) fn shard_bound(
    bound: &[u8],
    which: &'static str,
) -> Result<Option<ItemKey>, EnumerateError> {
    if bound.is_empty() {
        return Ok(None);
    }
    ItemKey::try_from_slice(bound)
        .map(Some)
        .map_err(|err| EnumerateError::permanent(format!("invalid shard {which} bound: {err}")))
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
    len.max(PAGE_SLAB_MIN_BLOCK).checked_next_power_of_two()
}

/// Compute exact slab capacity needed for a page's staged byte fields.
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
        let rounded = page_slab_alloc_size(len)
            .ok_or_else(|| EnumerateError::permanent("page slab field size overflow"))?;
        capacity = capacity
            .checked_add(rounded)
            .ok_or_else(|| EnumerateError::permanent("page slab capacity overflow"))?;
    }
    let capacity = capacity.max(PAGE_SLAB_MIN_BLOCK);
    if capacity > u32::MAX as usize {
        return Err(EnumerateError::permanent(
            "page slab capacity exceeds u32::MAX",
        ));
    }
    Ok(capacity)
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

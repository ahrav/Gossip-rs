//! Shared connector utilities: shard-bound validation, binary search,
//! pooled page assembly, split-point selection, and identity derivation.

use std::{
    io,
    path::{Path, PathBuf},
    sync::Arc,
    time::Instant,
};

#[cfg(unix)]
use std::{ffi::OsString, os::unix::ffi::OsStringExt};

use gossip_contracts::{
    connector::{
        Budgets, ConnectorInputError, Cursor, EnumerateError, ItemKey, ItemRef, MAX_ITEM_KEY_SIZE,
        PooledByteSlab, ReadError, TokenBytes,
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

/// Half-open index range `[range_start, range_end)` within a sorted item slice.
///
/// Produced by [`resolve_page_bounds`] and [`resolve_bounds`]. Callers combine
/// these indices with connector-specific cursor resume logic to determine the
/// effective start position.
pub(crate) struct ResolvedBounds {
    /// Inclusive lower bound index (first item whose key is `>= shard start`,
    /// or `0` when the shard start is unbounded).
    pub range_start: usize,
    /// Exclusive upper bound index (first item whose key is `>= shard end`,
    /// or `items.len()` when the shard end is unbounded).
    pub range_end: usize,
}

/// Validate shard bounds and map them to indices via binary search.
///
/// This is the pure bound-resolution kernel shared by both page enumeration and
/// split-point selection. It validates `start <= end` and converts byte bounds
/// to half-open indices via [`lower_bound`].
///
/// # Errors
///
/// Returns `EnumerateError::permanent` when `start > end`.
pub(crate) fn resolve_bounds<T: KeyedEntry>(
    items: &[T],
    start: Option<&[u8]>,
    end: Option<&[u8]>,
) -> Result<ResolvedBounds, EnumerateError> {
    if let (Some(s), Some(e)) = (start, end)
        && s > e
    {
        return Err(EnumerateError::permanent("shard start key exceeds end key"));
    }

    let range_start = start.map_or(0, |bound| lower_bound(items, bound));
    let range_end = end.map_or(items.len(), |bound| lower_bound(items, bound));

    Ok(ResolvedBounds {
        range_start,
        range_end,
    })
}

/// Validate shard bounds + budget deadline for one enumeration page.
///
/// Adds a deadline gate on top of [`resolve_bounds`]. Page-enumeration callers
/// use this; split-point callers use [`resolve_bounds`] directly since split
/// selection is a metadata-only operation.
///
/// # Errors
///
/// Returns `EnumerateError::retryable` on budget deadline expiry, or
/// `EnumerateError::permanent` when `start > end`.
pub(crate) fn resolve_page_bounds<T: KeyedEntry>(
    items: &[T],
    start: Option<&[u8]>,
    end: Option<&[u8]>,
    budgets: Budgets,
) -> Result<ResolvedBounds, EnumerateError> {
    if budgets.is_expired_at(Instant::now()) {
        return Err(EnumerateError::retryable("budget deadline expired"));
    }

    resolve_bounds(items, start, end)
}

/// Key-authoritative cursor resume: first index past the last emitted key.
///
/// Returns the O(log N) `upper_bound` position for `cursor.last_key()`,
/// clamped to `range_start` when no key is present. Callers use this as the
/// floor for resume; connector-specific token logic may advance further but
/// never behind this position.
pub(crate) fn key_resume_start<T: KeyedEntry>(
    items: &[T],
    cursor: &Cursor,
    range_start: usize,
) -> usize {
    cursor.last_key().map_or(range_start, |last_key| {
        upper_bound(items, last_key.as_bytes()).max(range_start)
    })
}

/// Check whether a split candidate advances past the cursor and stays below
/// the upper shard bound.
///
/// Both connectors apply identical post-selection guards after choosing a
/// byte-weighted split index. This helper centralizes the check so the guards
/// stay in sync.
pub(crate) fn is_valid_split_candidate(
    candidate: &[u8],
    cursor: &Cursor,
    end: Option<&[u8]>,
) -> bool {
    let past_cursor = cursor
        .last_key()
        .is_none_or(|last| candidate > last.as_bytes());
    let below_end = end.is_none_or(|upper| candidate < upper);
    past_cursor && below_end
}

/// Decode the optional cursor token as an absolute next-index.
///
/// Returns `None` when the cursor has no token, the token is malformed, or the
/// decoded index does not fit in `usize`.
///
/// Token bytes are intentionally treated as advisory here; connector-specific
/// call sites decide whether to trust, validate, or ignore the decoded index.
#[inline]
pub(crate) fn cursor_token_index(cursor: &Cursor) -> Option<usize> {
    cursor
        .token()
        .and_then(|token| parse_u64_be(token.as_bytes()))
        .and_then(|idx| usize::try_from(idx).ok())
}

/// Build the next continuation cursor from an emitted last key.
///
/// When `emit_tokens` is true, this helper encodes `next_idx` as an 8-byte
/// big-endian token and attaches it to the cursor.
/// The encoded value is the next absolute index (not the last emitted index),
/// so token-capable connectors can resume at O(1) when token/key state agrees.
///
/// # Errors
///
/// Returns `EnumerateError::permanent` when `next_idx` overflows `u64` or
/// the encoded token bytes fail [`TokenBytes`] construction.
pub(crate) fn build_next_cursor(
    last_key: ItemKey,
    next_idx: usize,
    emit_tokens: bool,
) -> Result<Cursor, EnumerateError> {
    if !emit_tokens {
        return Ok(Cursor::with_last_key(last_key));
    }

    let next_idx_u64 = u64::try_from(next_idx)
        .map_err(|_| EnumerateError::permanent("next index exceeds capacity"))?;
    let token = TokenBytes::try_from_slice(&next_idx_u64.to_be_bytes())
        .map_err(|err| EnumerateError::permanent(format!("invalid token: {err}")))?;
    Ok(Cursor::with_token(last_key, token))
}

/// Build the next continuation cursor, preserving a staged pooled token when available.
///
/// `start_idx + item_count` is computed with overflow checks to keep token
/// semantics centralized. If token emission is enabled and `staged_token` is
/// present, the pooled token is reused directly to preserve pooled-byte tests.
/// This avoids re-encoding/allocating a second token wrapper after staging.
///
/// # Errors
///
/// Returns `EnumerateError::permanent` when `start_idx + item_count` overflows
/// or when delegation to [`build_next_cursor`] fails (index overflow or token
/// construction failure).
pub(crate) fn build_next_cursor_from_staged(
    last_key: ItemKey,
    start_idx: usize,
    item_count: usize,
    emit_tokens: bool,
    staged_token: Option<TokenBytes>,
) -> Result<Cursor, EnumerateError> {
    let next_idx = start_idx
        .checked_add(item_count)
        .ok_or_else(|| EnumerateError::permanent("next index exceeds capacity"))?;

    if emit_tokens && let Some(token) = staged_token {
        return Ok(Cursor::with_token(last_key, token));
    }

    build_next_cursor(last_key, next_idx, emit_tokens)
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
///
/// # Why this matters
///
/// Pre-computing the exact allocation size allows us to pre-size slabs
/// accurately, eliminating mid-loop allocation failures. The rounding
/// must exactly match `ByteSlab`'s internal size-class logic or we'll
/// underestimate capacity and fail during staging.
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
/// # Token encoding invariant
///
/// The token encodes the next item's index (not the last emitted index).
/// This allows O(1) resume: the connector can jump directly to `token_idx`
/// without needing to search for `last_key + 1`. The trade-off is that
/// token validation requires checking `items[token_idx - 1].key == last_key`.
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

// ---------------------------------------------------------------------------
// I/O error classification
// ---------------------------------------------------------------------------

/// Returns `true` for I/O errors that are deterministically permanent.
///
/// Structural filesystem errors — missing files, permission denials, type
/// mismatches, and symlink loops — will not resolve on retry. Everything
/// else (interrupted, would-block, connection-reset, etc.) is assumed
/// transient and therefore retryable.
pub(crate) fn is_permanent_io_error(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::NotFound
            | io::ErrorKind::PermissionDenied
            | io::ErrorKind::InvalidInput
            | io::ErrorKind::InvalidFilename
            | io::ErrorKind::NotADirectory
            | io::ErrorKind::IsADirectory
    ) || is_symlink_loop(err)
}

/// Detect `ELOOP` (too many levels of symbolic links) on Unix.
#[cfg(unix)]
pub(crate) fn is_symlink_loop(err: &io::Error) -> bool {
    err.raw_os_error() == Some(libc::ELOOP)
}

/// Non-Unix stub: symlink loops cannot be detected via `raw_os_error`.
#[cfg(not(unix))]
pub(crate) fn is_symlink_loop(_err: &io::Error) -> bool {
    false
}

/// Map an I/O error to an [`EnumerateError`], classifying permanence.
///
/// Includes the failing path in the error message for diagnostics.
pub(crate) fn classify_io_enumerate_error(
    op: &str,
    path: &Path,
    err: &io::Error,
) -> EnumerateError {
    if is_permanent_io_error(err) {
        EnumerateError::permanent(format!("{op} failed for {}: {err}", path.display()))
    } else {
        EnumerateError::retryable(format!("{op} failed for {}: {err}", path.display()))
    }
}

/// Map an I/O error to a [`ReadError`], classifying permanence.
///
/// When `path` is `Some`, the path is included in the message for
/// diagnostics; when `None`, only the operation and error are reported.
pub(crate) fn classify_io_read_error(op: &str, path: Option<&Path>, err: &io::Error) -> ReadError {
    let msg = match path {
        Some(p) => format!("{op} failed for {}: {err}", p.display()),
        None => format!("{op} failed: {err}"),
    };
    if is_permanent_io_error(err) {
        ReadError::permanent(msg)
    } else {
        ReadError::retryable(msg)
    }
}

/// Bridge an [`EnumerateError`] into a [`ReadError`], preserving retryability.
pub(crate) fn enumerate_error_to_read(error: EnumerateError) -> ReadError {
    if error.is_retryable() {
        ReadError::retryable(error.into_message())
    } else {
        ReadError::permanent(error.into_message())
    }
}

// ---------------------------------------------------------------------------
// Platform-aware path ↔ byte conversions
// ---------------------------------------------------------------------------

/// Convert raw path bytes to a [`PathBuf`] losslessly on Unix.
#[cfg(unix)]
pub fn path_buf_from_bytes(bytes: &[u8]) -> PathBuf {
    PathBuf::from(OsString::from_vec(bytes.to_vec()))
}

/// Convert raw path bytes to a [`PathBuf`] on non-Unix platforms.
///
/// Invalid UTF-8 sequences are replaced with U+FFFD. This is lossy but
/// avoids panicking; in practice, non-UTF-8 paths are rare on platforms
/// where this fallback applies (e.g., Windows).
#[cfg(not(unix))]
pub fn path_buf_from_bytes(bytes: &[u8]) -> PathBuf {
    PathBuf::from(String::from_utf8_lossy(bytes).into_owned())
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
    use proptest::prelude::*;
    use rstest::rstest;

    const MB: usize = gossip_stdx::MIN_BLOCK as usize;

    // -- page_slab_alloc_size: (input → expected) mappings --

    #[rstest]
    #[case::zero(0, Some(0))]
    #[case::one(1, Some(MB))]
    #[case::min_block(MB, Some(MB))]
    #[case::seventeen(17, Some(32))]
    #[case::thirty_three(33, Some(64))]
    #[case::hundred(100, Some(128))]
    #[case::pow2_32(32, Some(32))]
    #[case::pow2_64(64, Some(64))]
    #[case::pow2_128(128, Some(128))]
    #[case::pow2_256(256, Some(256))]
    #[case::pow2_1024(1024, Some(1024))]
    #[case::pow2_4096(4096, Some(4096))]
    fn alloc_size_cases(#[case] input: usize, #[case] expected: Option<usize>) {
        assert_eq!(page_slab_alloc_size(input), expected);
    }

    proptest! {
        /// For all values in `1..=MIN_BLOCK`, the rounded size is exactly
        /// `MIN_BLOCK`. This replaces the former bounded loop with a
        /// continuous-range property test.
        #[test]
        fn alloc_size_small_values_always_min_block(n in 1..=MB) {
            prop_assert_eq!(page_slab_alloc_size(n), Some(MB));
        }
    }

    // -- page_slab_capacity: ok cases --

    #[rstest]
    #[case::two_tens(&[10, 10], 32)]
    #[case::single_zero(&[0], 0)]
    #[case::empty_iter(&[], 0)]
    #[case::mixed_zero_nonzero(&[0, 10], MB)]
    #[case::triple_zero(&[0, 0, 0], 0)]
    fn capacity_ok_cases(#[case] lengths: &[usize], #[case] expected: usize) {
        let cap = page_slab_capacity(lengths.iter().copied()).unwrap();
        assert_eq!(cap, expected);
    }

    // -- page_slab_capacity: error cases --

    #[rstest]
    #[case::single_usize_max(&[usize::MAX])]
    #[case::sum_overflow(&[usize::MAX / 2 + 1, usize::MAX / 2 + 1])]
    #[case::exceeds_u32_max(&[u32::MAX as usize + 1])]
    fn capacity_error_cases(#[case] lengths: &[usize]) {
        assert!(page_slab_capacity(lengths.iter().copied()).is_err());
    }

    /// Boundary test: 2^31 fits in u32, but two 2^31 fields sum to 2^32
    /// which exceeds u32::MAX. This exercises both sides of the u32 cap
    /// in one test and doesn't consolidate cleanly into either rstest group.
    #[test]
    fn capacity_at_u32_max_boundary() {
        let half = 1usize << 31;
        assert!(page_slab_capacity([half]).is_ok());
        assert!(page_slab_capacity([half, half]).is_err());
    }
}

/// Tests for byte-weighted split-point selection.
///
/// Exact-value cases are consolidated into an rstest parameterized test.
/// Inequality/range assertions remain as individual tests because their
/// assertion style differs. A proptest verifies the clamping invariant
/// over random size distributions.
#[cfg(test)]
mod choose_split_tests {
    use super::*;
    use proptest::prelude::*;
    use rstest::rstest;

    struct TestEntry {
        size: u64,
    }

    impl SizedEntry for TestEntry {
        fn entry_size(&self) -> u64 {
            self.size
        }
    }

    fn entries(sizes: &[u64]) -> Vec<TestEntry> {
        sizes.iter().map(|&size| TestEntry { size }).collect()
    }

    // -- Exact-value cases: identical assertion structure --

    #[rstest]
    #[case::empty_range(&[10, 20], 1, 1, None)]
    #[case::single_item(&[10, 20, 30], 1, 2, None)]
    #[case::two_items(&[10, 20], 0, 2, Some(1))]
    #[case::all_zero_count_midpoint(&[0, 0, 0, 0], 0, 4, Some(2))]
    #[case::first_heavy_count_fallback(&[100, 1, 1, 1], 0, 4, Some(2))]
    #[case::middle_heavy_byte_weight(&[1, 1, 100, 1], 0, 4, Some(2))]
    fn split_index_exact(
        #[case] sizes: &[u64],
        #[case] start: usize,
        #[case] end: usize,
        #[case] expected: Option<usize>,
    ) {
        let items = entries(sizes);
        assert_eq!(choose_split_index(&items, start, end), expected);
    }

    // -- Inequality/range assertions: kept individual --

    #[test]
    fn clamp_prevents_empty_left_shard() {
        let items = entries(&[0, 100]);
        let split = choose_split_index(&items, 0, 2).unwrap();
        assert!(split >= 1, "split must leave at least one item on the left");
    }

    #[test]
    fn clamp_prevents_empty_right_shard() {
        let items = entries(&[0, 0, 0, 100]);
        let split = choose_split_index(&items, 0, 4).unwrap();
        assert!(
            split <= 3,
            "split must leave at least one item on the right"
        );
    }

    #[test]
    fn nonzero_start_idx_offset() {
        let items = entries(&[99, 99, 10, 20, 30]);
        let split = choose_split_index(&items, 2, 5).unwrap();
        assert!((3..=4).contains(&split), "split {split} out of [3, 4]");
    }

    // -- Property: clamping invariant over random size distributions --

    proptest! {
        #[test]
        fn split_index_bounds_invariant(
            sizes in proptest::collection::vec(0..10_000u64, 0..20),
        ) {
            let items = entries(&sizes);
            let len = items.len();
            // Test the full range [0, len).
            if let Some(split) = choose_split_index(&items, 0, len) {
                prop_assert!(split >= 1, "split {split} must be >= start_idx + 1");
                prop_assert!(split <= len - 1, "split {split} must be <= range_end - 1");
            } else {
                prop_assert!(len < 2, "None only when fewer than 2 items, got {len}");
            }
        }
    }
}

/// Tests for generic binary search helpers (`lower_bound`, `upper_bound`).
///
/// Uses rstest parameterized cases since all non-empty-slice cases share the
/// identical structure: build sorted items, search for key, assert index.
/// Empty-slice cases remain standalone because their setup differs.
#[cfg(test)]
mod binary_search_tests {
    use super::*;
    use rstest::rstest;

    struct TestKey(Vec<u8>);

    impl KeyedEntry for TestKey {
        fn key_bytes(&self) -> &[u8] {
            &self.0
        }
    }

    fn sample_items() -> Vec<TestKey> {
        // Sorted: "b", "d", "f"
        vec![
            TestKey(b"b".to_vec()),
            TestKey(b"d".to_vec()),
            TestKey(b"f".to_vec()),
        ]
    }

    // -- lower_bound: first index where key >= target --

    #[test]
    fn lower_bound_empty_slice() {
        let items: Vec<TestKey> = vec![];
        assert_eq!(lower_bound(&items, b"x"), 0);
    }

    #[rstest]
    #[case::before_all(b"a", 0)]
    #[case::equal_to_first(b"b", 0)]
    #[case::between_b_and_d(b"c", 1)]
    #[case::equal_to_middle(b"d", 1)]
    #[case::between_d_and_f(b"e", 2)]
    #[case::after_all(b"z", 3)]
    fn lower_bound_cases(#[case] key: &[u8], #[case] expected: usize) {
        let items = sample_items();
        assert_eq!(lower_bound(&items, key), expected);
    }

    // -- upper_bound: first index where key > target --

    #[test]
    fn upper_bound_empty_slice() {
        let items: Vec<TestKey> = vec![];
        assert_eq!(upper_bound(&items, b"x"), 0);
    }

    #[rstest]
    #[case::before_all(b"a", 0)]
    #[case::equal_to_first(b"b", 1)]
    #[case::between_b_and_d(b"c", 1)]
    #[case::equal_to_middle(b"d", 2)]
    #[case::equal_to_last(b"f", 3)]
    #[case::after_all(b"z", 3)]
    fn upper_bound_cases(#[case] key: &[u8], #[case] expected: usize) {
        let items = sample_items();
        assert_eq!(upper_bound(&items, key), expected);
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

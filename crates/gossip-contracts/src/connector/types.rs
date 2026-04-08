//! Connector boundary value types and validation errors.
//!
//! This module defines "toxic-byte" wrappers used by connector enumeration
//! and paging flows. Toxic bytes may contain sensitive or user-controlled data
//! and must never be formatted as raw bytes in logs.
//!
//! ## Types at a glance
//!
//! | Type | Role | Limit | Ordered? |
//! |------|------|-------|----------|
//! | [`ItemKey`] | Enumeration position for sharding and cursor progression | 4 KiB | Yes (lexicographic) |
//! | [`ItemRef`] | Opaque handle a connector returns for read/open | 16 KiB | No |
//! | [`TokenBytes`] | Pagination/resume token the connector round-trips | 16 KiB | No |
//!
//! ## Additional boundary types
//!
//! - [`Cursor`] owns connector paging state and bridges to borrowed
//!   [`CursorUpdate`] for coordination APIs.
//! - [`VersionId`] records whether a connector's version evidence is strong or
//!   weak while preserving the same [`ObjectVersionId`] representation.
//! - [`ContentHints`] and [`Location`] are bounded metadata carriers for
//!   presentation and downstream routing decisions.
//! - [`ScanItem`] bundles validated boundary fields for
//!   connector scan handoff.
//! - [`Budgets`] carries scan-level stop conditions (count, bytes, deadline).
//!
//! ## Core contract
//!
//! - Constructors enforce non-empty bytes and hard upper bounds.
//! - Wrappers support both owned (`Box<[u8]>`) and pooled (`ByteSlot` +
//!   `Arc<PooledByteSlab>`) storage so COLD/WARM paths stay simple while HOT
//!   enumeration paths avoid per-item heap allocation.
//!   Pooled values are page-scoped: key/ref/token wrappers cloned out of a page
//!   keep that page slab alive until the last clone is dropped.
//! - Formatting is always redacted (`len + short hash prefix`), so logs can be
//!   correlated without leaking payload contents. The hash is a truncated
//!   BLAKE3 digest prefix -- fast and deterministic, but intentionally short for
//!   correlation rather than cryptographic collision guarantees.
//! - `MAX_ITEM_KEY_SIZE` and `MAX_TOKEN_SIZE` intentionally track coordination
//!   cursor limits to keep connector paging contracts aligned.
//!   `MAX_ITEM_REF_SIZE` is independent; it bounds connector-specific handles
//!   that never enter the cursor path.
//! - Cursor states with `token` but no `last_key` are invalid by contract and
//!   rejected when crossing the coordination boundary.

/// A hash-only, fixed-size representation of toxic bytes.
///
/// Connector keys and cursors are untrusted external data ("toxic bytes")
/// that must never appear raw in logs, error messages, or metrics. Instead
/// of carrying the original payload, `ToxicDigest` stores just:
///
/// - `len`: the byte length of the original input, and
/// - `hash`: a full 32-byte BLAKE3 digest.
///
/// ## Display format
///
/// Both `Display` and `Debug` emit the same compact, single-line form:
///
/// ```text
/// len=42, hash=0a1b2c3d4e5f6a7b
/// ```
///
/// Only the first 8 bytes of the hash are printed (16 hex characters),
/// which is enough for log-line correlation without bloating output.
///
/// ## Equality semantics
///
/// `PartialEq` and `Eq` compare the **full** 32-byte hash (plus length),
/// not just the truncated display prefix. Two digests that display
/// identically are overwhelmingly likely to be equal, but equality is
/// always decided on the complete hash.
///
/// ## Copy semantics
///
/// `ToxicDigest` is `Copy` (40 bytes on 64-bit targets). Error types
/// embed digests by value, avoiding indirection for what are
/// fundamentally small, immutable tokens.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ToxicDigest {
    /// Byte length of the original input. Preserved so diagnostics can
    /// distinguish zero-length sentinels from short keys without revealing
    /// content.
    len: usize,
    /// Full 32-byte BLAKE3 digest of the original input. Only the first
    /// 8 bytes are shown in display output; equality uses all 32.
    hash: [u8; 32],
}

impl ToxicDigest {
    /// Digest a raw byte slice into a redacted, fixed-size representation.
    ///
    /// This is the low-level entry point. Prefer [`of`](Self::of) when working
    /// with typed wrappers like [`ItemKey`] that implement `AsRef<[u8]>`.
    #[must_use]
    pub fn of_bytes(bytes: &[u8]) -> Self {
        let hash = blake3::hash(bytes);
        Self {
            len: bytes.len(),
            hash: *hash.as_bytes(),
        }
    }

    /// Digest any value that can be viewed as bytes.
    ///
    /// This is the ergonomic entry point for typed connector keys and cursors.
    /// The `?Sized` bound allows passing both owned wrappers (`&ItemKey`) and
    /// plain slices (`&[u8]`) without an extra `.as_ref()` at the call site.
    #[must_use]
    pub fn of<K: AsRef<[u8]> + ?Sized>(k: &K) -> Self {
        Self::of_bytes(k.as_ref())
    }
}

impl std::fmt::Display for ToxicDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "len={}, hash=", self.len)?;
        // First 8 bytes => 16 hex characters. Enough for correlation, short
        // enough that multi-field error lines stay readable.
        for b in &self.hash[..8] {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

/// Delegates to `Display` so that `{:?}` formatting in error chains and
/// `Option<ToxicDigest>` debug output stays log-safe and compact.
impl std::fmt::Debug for ToxicDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

use std::{
    fmt,
    num::{NonZeroU64, NonZeroUsize},
    sync::Arc,
    time::Instant,
};

use gossip_stdx::{ByteSlab, ByteSlot};

use crate::coordination::CursorUpdate;
use crate::identity::{ObjectVersionId, StableItemId};

/// Maximum size of an [`ItemKey`] in bytes (4 KiB).
///
/// Kept in lock-step with the coordination cursor `last_key` limit
/// (`coordination::cursor::MAX_KEY_SIZE`) so that every valid connector key
/// can be stored directly in a cursor without truncation. Alignment is
/// verified by the `constants_align_with_coordination_limits` test.
pub const MAX_ITEM_KEY_SIZE: usize = 4_096;

/// Maximum size of an [`ItemRef`] in bytes (16 KiB).
///
/// Unlike `MAX_ITEM_KEY_SIZE` and `MAX_TOKEN_SIZE`, this limit is not
/// derived from coordination cursor fields -- `ItemRef` values never enter
/// the cursor path. The bound exists purely as a defense-in-depth cap on
/// connector-supplied handles.
pub const MAX_ITEM_REF_SIZE: usize = 16_384;

/// Maximum size of a [`TokenBytes`] value in bytes (16 KiB).
///
/// Kept in lock-step with the coordination cursor `token` limit
/// (`coordination::cursor::MAX_TOKEN_SIZE`, re-exported as
/// `CursorMaxTokenSize`) so that pagination tokens can be persisted in
/// cursor state without size mismatch. Alignment is verified by the
/// `constants_align_with_coordination_limits` test.
pub const MAX_TOKEN_SIZE: usize = 16_384;

/// Maximum size of [`ContentHints::media_type`] in bytes.
const MAX_CONTENT_HINT_MEDIA_TYPE_SIZE: usize = 256;

/// Maximum size of [`ContentHints::encoding`] in bytes.
const MAX_CONTENT_HINT_ENCODING_SIZE: usize = 128;

/// Maximum size of [`Location::display`] in bytes.
pub const MAX_LOCATION_DISPLAY_SIZE: usize = 4_096;

/// Maximum size of [`Location::url`] in bytes.
pub const MAX_LOCATION_URL_SIZE: usize = 4_096;

/// Input validation errors for connector boundary value types.
///
/// This single error surface keeps connector-boundary failures easy to route:
///
/// - [`Empty`](ConnectorInputError::Empty) and
///   [`TooLarge`](ConnectorInputError::TooLarge) capture field validation
///   failures from `ItemKey` / `ItemRef` / `TokenBytes`, and from bounded
///   metadata constructors ([`ContentHints::try_new`], [`Location::try_new`]).
/// - [`TokenWithoutLastKey`](ConnectorInputError::TokenWithoutLastKey)
///   captures a violated paging invariant when converting from coordination's
///   borrowed [`CursorUpdate`] into owned [`Cursor`].
/// - [`ZeroBudget`](ConnectorInputError::ZeroBudget) rejects zero-valued
///   budget fields in [`Budgets::try_new`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConnectorInputError {
    /// A required field was empty (zero-length byte slice).
    #[error("{field} must not be empty")]
    Empty { field: &'static str },
    /// A field exceeded its hard size limit.
    #[error("{field} too large ({size} bytes, max {max})")]
    TooLarge {
        field: &'static str,
        /// Actual byte length of the rejected input.
        size: usize,
        /// Upper bound for this field (one of the `MAX_*` constants).
        max: usize,
    },
    /// Cursor update had `token` without `last_key`.
    #[error("token must not be present without last_key")]
    TokenWithoutLastKey,
    /// A budget field was zero, which would make the budget vacuous.
    #[error("{field} must be non-zero")]
    ZeroBudget { field: &'static str },
}

/// Returns the first 4 bytes of the BLAKE3 digest of `bytes`.
///
/// Used exclusively by [`fmt_toxic_bytes`], which renders these 4 bytes as
/// 8 lowercase hex characters for log correlation. This provides enough
/// uniqueness for operational debugging while keeping formatted output compact.
#[inline]
fn hash_prefix_4(bytes: &[u8]) -> [u8; 4] {
    let hash = blake3::hash(bytes);
    let b = hash.as_bytes();
    [b[0], b[1], b[2], b[3]]
}

/// Shared `Debug`/`Display` formatter for all toxic-byte wrappers.
///
/// Output format: `TypeName(len=N, hash=XXXXXXXX..)` where the hash is the
/// first 4 bytes of the BLAKE3 digest in lowercase hex. Both `Debug` and
/// `Display` intentionally produce identical output so callers cannot
/// accidentally bypass the toxic-byte redaction policy by switching format
/// traits.
#[inline]
fn fmt_toxic_bytes(
    f: &mut fmt::Formatter<'_>,
    type_name: &'static str,
    bytes: &[u8],
) -> fmt::Result {
    let [a, b, c, d] = hash_prefix_4(bytes);
    write!(
        f,
        "{type_name}(len={}, hash={:02x}{:02x}{:02x}{:02x}..)",
        bytes.len(),
        a,
        b,
        c,
        d
    )
}

/// Validates the two shared constructor invariants for toxic-byte wrappers:
///
/// 1. `bytes` must not be empty (rejects zero-length slices).
/// 2. `bytes.len()` must not exceed `max`.
///
/// All wrapper constructors delegate here so the emptiness and size checks are
/// defined in exactly one place.
#[inline]
fn validate_toxic_bytes(
    field: &'static str,
    bytes: &[u8],
    max: usize,
) -> Result<(), ConnectorInputError> {
    if bytes.is_empty() {
        return Err(ConnectorInputError::Empty { field });
    }
    if bytes.len() > max {
        return Err(ConnectorInputError::TooLarge {
            field,
            size: bytes.len(),
            max,
        });
    }
    Ok(())
}

/// Backing storage for toxic-byte wrappers.
///
/// `Owned` is the baseline COLD/WARM representation; `Pooled` is used by
/// HOT-path page emission, where wrappers borrow bytes from a page-local slab.
#[derive(Clone)]
enum ToxicBytesStorage {
    /// Independent heap allocation. Used for isolated values like cursor fields.
    Owned(Box<[u8]>),
    /// Borrowed from a shared page-local slab. Used during high-volume enumeration.
    Pooled(PooledToxicBytes),
}

impl ToxicBytesStorage {
    /// Returns the underlying byte slice regardless of storage mechanism.
    /// Resolves the slot via the shared slab to return the byte slice.
    #[inline]
    fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Owned(bytes) => bytes,
            Self::Pooled(pooled) => pooled.as_bytes(),
        }
    }

    /// Returns `true` if the underlying storage is pooled.
    #[inline]
    fn is_pooled(&self) -> bool {
        matches!(self, Self::Pooled(_))
    }
}

/// Shared page-local slab owner for pooled toxic-byte wrappers.
///
/// Enumeration pages stage bytes through this slab, then wrap it in `Arc` so
/// the pooled handles can be cloned without additional allocations. When the
/// last `Arc<PooledByteSlab>` drops, the slab zeroizes sensitive bytes and
/// clears slot tracking to satisfy `ByteSlab`'s leak assertions.
///
/// Connectors use the two-phase API:
/// 1. **Mutable phase:** call [`allocate`](Self::allocate) to stage byte fields.
/// 2. **Shared phase:** wrap in `Arc` for shared read-only access
///    via pooled toxic-byte wrappers.
///
/// The custom [`Drop`] implementation ensures safe cleanup: [`zeroize_used`]
/// overwrites sensitive toxic-byte residue in the backing buffer, then
/// [`clear`] resets the slab's live slot count to zero, satisfying
/// `ByteSlab`'s debug leak assertion. This cleanup runs on all exit paths,
/// including mid-loop staging failures that return early.
///
/// [`zeroize_used`]: gossip_stdx::ByteSlab::zeroize_used
/// [`clear`]: gossip_stdx::ByteSlab::clear
pub struct PooledByteSlab {
    /// The underlying slab allocation. Shared references to this struct are held
    /// by `PooledToxicBytes` handles emitted from the page.
    slab: ByteSlab,
}

impl PooledByteSlab {
    /// Wrap a page-local slab for staged allocation and later shared read access.
    #[inline]
    #[must_use]
    pub fn new(slab: ByteSlab) -> Self {
        Self { slab }
    }

    /// Stage bytes into the slab during page assembly.
    ///
    /// This is the mutable-phase API: connectors call `allocate` repeatedly
    /// while building a page, then wrap the `PooledByteSlab` in an `Arc` for
    /// shared read access.
    ///
    /// # Errors
    ///
    /// Returns [`SlabFull`] when the remaining slab capacity is insufficient
    /// for the allocation. Callers should pre-size slabs to make staging
    /// failures deterministic overflow signals rather than partial-progress
    /// behavior.
    ///
    /// [`SlabFull`]: gossip_stdx::SlabFull
    #[inline]
    pub fn allocate(&mut self, bytes: &[u8]) -> Result<ByteSlot, gossip_stdx::SlabFull> {
        self.slab.allocate(bytes)
    }

    /// Resolves a previously allocated slot to its underlying byte slice.
    ///
    /// The borrow is tied to `self`, so callers must keep the owning
    /// `Arc<PooledByteSlab>` alive for as long as they hold the slice.
    #[inline]
    fn get(&self, slot: ByteSlot) -> &[u8] {
        self.slab.get(slot)
    }
}

/// Debug format shows only metadata, never raw toxic-byte contents.
///
/// `live_count` is the number of active slots; `live_bytes` is the total
/// size of all live allocations. These metrics help diagnose slab sizing
/// and staging behavior without exposing sensitive payload data.
impl fmt::Debug for PooledByteSlab {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PooledByteSlab")
            .field("live_count", &self.slab.live_count())
            .field("live_bytes", &self.slab.live_bytes())
            .finish()
    }
}

/// Clears sensitive toxic-byte data before the slab is dropped.
///
/// [`zeroize_used`] overwrites all bytes in the used region (`[0, bump)`)
/// with zeros to prevent sensitive residue from lingering in heap memory
/// after the page is freed. [`clear`] then resets the slab to initial state
/// (bump, free-list, live counts, and owner id), satisfying `ByteSlab`'s
/// debug assertion that no live slots remain at drop time and invalidating
/// any stale slot handles. Both operations are required: zeroization
/// protects data, clear maintains all slab invariants.
///
/// [`zeroize_used`]: gossip_stdx::ByteSlab::zeroize_used
/// [`clear`]: gossip_stdx::ByteSlab::clear
/// This cleanup runs when the final `Arc<PooledByteSlab>` is dropped,
/// guaranteeing no pooled handles remain when zeroization starts.
impl Drop for PooledByteSlab {
    fn drop(&mut self) {
        // Safety reasoning: Arc guarantees this runs only when no
        // PooledToxicBytes references remain, so no concurrent reads of slab
        // slots are possible during zeroization or clear.
        self.slab.zeroize_used();
        self.slab.clear();
    }
}

// PooledByteSlab is shared across threads via Arc in connector page emission.
// ByteSlab's backing storage is a plain Vec<u8> with no interior mutability,
// so Send + Sync hold automatically. This assertion guards against future
// field additions that might break thread safety.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<PooledByteSlab>();
};

/// Slab-backed toxic-byte storage handle.
///
/// `slot` indexes bytes inside `slab`; cloning this handle is allocation-free.
/// Slot provenance is enforced by `ByteSlab`: a slot from another slab (or from
/// before a `clear`) panics when resolved.
#[derive(Clone)]
struct PooledToxicBytes {
    /// Opaque handle to the bytes within the slab's allocation.
    slot: ByteSlot,
    /// Reference-counted shared ownership of the underlying slab.
    slab: Arc<PooledByteSlab>,
}

impl PooledToxicBytes {
    /// Constructs a new pooled handle to a slot within the given slab.
    #[inline]
    fn new(slot: ByteSlot, slab: Arc<PooledByteSlab>) -> Self {
        Self { slot, slab }
    }

    /// Resolves the slot via the shared slab to return the byte slice.
    #[inline]
    fn as_bytes(&self) -> &[u8] {
        self.slab.get(self.slot)
    }
}

/// Generates a toxic-byte wrapper struct with validated constructors and
/// redacted formatting.
///
/// Two public arms control whether ordering traits are implemented:
/// - `ordered $name, max = $max` — includes `PartialOrd` + `Ord` (cursor keys).
/// - `$name, max = $max` — unordered (opaque handles and tokens).
///
/// Both arms produce: struct, `try_from_vec`, `try_from_slice`, `as_bytes`,
/// `len`, `AsRef<[u8]>`, `is_pooled`, and identical
/// `Debug`/`Display` (redacted to `TypeName(len=N, hash=XXXXXXXX..)`).
macro_rules! define_toxic_bytes {
    (
        $(#[$meta:meta])*
        ordered $name:ident, max = $max:expr
    ) => {
        define_toxic_bytes!(@base $(#[$meta])* $name, $max);

        impl ::core::cmp::PartialOrd for $name {
            fn partial_cmp(&self, other: &Self) -> Option<::core::cmp::Ordering> {
                Some(self.cmp(other))
            }
        }

        impl ::core::cmp::Ord for $name {
            fn cmp(&self, other: &Self) -> ::core::cmp::Ordering {
                self.as_bytes().cmp(other.as_bytes())
            }
        }
    };
    (
        $(#[$meta:meta])*
        $name:ident, max = $max:expr
    ) => {
        define_toxic_bytes!(@base $(#[$meta])* $name, $max);
    };
    (@base $(#[$meta:meta])* $name:ident, $max:expr) => {
        $(#[$meta])*
        #[derive(Clone)]
        #[allow(clippy::len_without_is_empty)]
        pub struct $name(ToxicBytesStorage);

        impl $name {
            /// Fallible constructor that takes ownership of caller-provided bytes.
            ///
            /// Use this at input boundaries that accept untrusted or external bytes.
            /// Takes ownership of the `Vec` to avoid a copy when validation succeeds.
            ///
            /// # Errors
            ///
            /// Returns [`ConnectorInputError::Empty`] if `bytes` is empty, or
            /// [`ConnectorInputError::TooLarge`] if it exceeds the type's size limit.
            pub fn try_from_vec(bytes: Vec<u8>) -> Result<Self, ConnectorInputError> {
                validate_toxic_bytes(stringify!($name), &bytes, $max)?;
                Ok(Self(ToxicBytesStorage::Owned(bytes.into_boxed_slice())))
            }

            /// Fallible constructor from a borrowed slice.
            ///
            /// Copies `bytes` into a new allocation on success. When the caller
            /// already owns a `Vec`, prefer [`try_from_vec`](Self::try_from_vec)
            /// to avoid the extra copy.
            ///
            /// # Errors
            ///
            /// Returns [`ConnectorInputError::Empty`] if `bytes` is empty, or
            /// [`ConnectorInputError::TooLarge`] if it exceeds the type's size limit.
            pub fn try_from_slice(bytes: &[u8]) -> Result<Self, ConnectorInputError> {
                validate_toxic_bytes(stringify!($name), bytes, $max)?;
                Ok(Self(ToxicBytesStorage::Owned(bytes.to_vec().into_boxed_slice())))
            }

            /// Fallible constructor from a slab slot.
            ///
            /// This is used by HOT enumeration paths that build page-local
            /// slab-backed wrappers to avoid per-item heap allocation.
            ///
            /// # Errors
            ///
            /// Returns [`ConnectorInputError::Empty`] if the slot resolves to empty
            /// bytes, or [`ConnectorInputError::TooLarge`] if it exceeds the type's
            /// size limit.
            ///
            /// # Panics
            ///
            /// Panics if `slot` did not originate from `slab` (or became stale
            /// after that slab was cleared). This indicates an internal page
            /// assembly bug.
            pub fn try_from_slot(
                slot: ByteSlot,
                slab: Arc<PooledByteSlab>,
            ) -> Result<Self, ConnectorInputError> {
                let pooled = PooledToxicBytes::new(slot, slab);
                validate_toxic_bytes(stringify!($name), pooled.as_bytes(), $max)?;
                Ok(Self(ToxicBytesStorage::Pooled(pooled)))
            }

            /// Returns the validated bytes.
            ///
            /// For pooled values, this borrows from the shared page slab with no
            /// additional allocation.
            #[inline]
            #[must_use]
            pub fn as_bytes(&self) -> &[u8] {
                self.0.as_bytes()
            }

            /// Returns the byte length, which is always >= 1 because constructors
            /// reject empty input. `is_empty()` is intentionally absent since it
            /// would unconditionally return `false`.
            #[inline]
            #[must_use]
            pub fn len(&self) -> usize {
                self.as_bytes().len()
            }

            /// Returns `true` if this wrapper is backed by a pooled slab slot.
            ///
            /// Primarily useful for tests/instrumentation that need to assert
            /// HOT-path pooling behavior.
            #[doc(hidden)]
            #[inline]
            #[must_use]
            pub fn is_pooled(&self) -> bool {
                self.0.is_pooled()
            }

        }

        impl AsRef<[u8]> for $name {
            #[inline]
            fn as_ref(&self) -> &[u8] {
                self.as_bytes()
            }
        }

        impl ::core::cmp::PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                self.as_bytes() == other.as_bytes()
            }
        }

        impl ::core::cmp::Eq for $name {}

        impl ::core::hash::Hash for $name {
            fn hash<H: ::core::hash::Hasher>(&self, state: &mut H) {
                ::core::hash::Hash::hash(self.as_bytes(), state);
            }
        }

        impl ::core::fmt::Debug for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                fmt_toxic_bytes(f, stringify!($name), self.as_bytes())
            }
        }

        impl ::core::fmt::Display for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                fmt_toxic_bytes(f, stringify!($name), self.as_bytes())
            }
        }
    };
}

define_toxic_bytes! {
    /// Ordered enumeration key used for sharding, paging, and cursor progression.
    ///
    /// Connectors produce `ItemKey` values to represent ordered positions within a
    /// data source. The coordination layer stores these as cursor `last_key` fields,
    /// so both sides must agree on the size bound ([`MAX_ITEM_KEY_SIZE`]).
    ///
    /// ## Ordering
    ///
    /// `Ord` uses bytewise lexicographic comparison. This matches the cursor
    /// progression contract: advancing means moving to a strictly greater key.
    ///
    /// ## Toxic-byte policy
    ///
    /// `Debug` and `Display` are redacted (length + hash prefix). Raw bytes can
    /// be borrowed through [`as_bytes`](Self::as_bytes) / [`AsRef<[u8]>`](AsRef),
    /// or borrowed via [`AsRef<[u8]>`](AsRef).
    ordered ItemKey, max = MAX_ITEM_KEY_SIZE
}

define_toxic_bytes! {
    /// Opaque, credential-free connector handle for read/open operations.
    ///
    /// A connector returns an `ItemRef` alongside each enumerated item so the
    /// coordinator can later ask the connector to open or read that item without
    /// needing the connector's internal addressing scheme. The bytes are opaque to
    /// the coordination layer -- only the originating connector interprets them.
    ///
    /// ## Differences from [`ItemKey`]
    ///
    /// - **Not ordered.** `ItemRef` does not derive `Ord` because the coordination
    ///   layer never compares or sorts references; they are looked up, not ranged.
    /// - **Independent size limit.** [`MAX_ITEM_REF_SIZE`] is not tied to cursor
    ///   field limits because references never enter cursor state.
    ///
    /// ## Toxic-byte policy
    ///
    /// `Debug` and `Display` are redacted (length + hash prefix). Raw bytes can
    /// be borrowed through [`as_bytes`](Self::as_bytes) / [`AsRef<[u8]>`](AsRef),
    /// or borrowed via [`AsRef<[u8]>`](AsRef).
    ItemRef, max = MAX_ITEM_REF_SIZE
}

define_toxic_bytes! {
    /// Connector-opaque pagination or resume token.
    ///
    /// Connectors emit a `TokenBytes` value when an enumeration page has more
    /// results. The coordinator persists it in the cursor `token` field and hands
    /// it back on the next page request. The coordination layer never interprets
    /// the contents -- only presence and size are validated at this boundary.
    ///
    /// ## Cursor coupling
    ///
    /// [`MAX_TOKEN_SIZE`] is derived from the coordination cursor `token` limit,
    /// so any token that passes validation here is guaranteed to fit in cursor
    /// state. A token only has meaning when paired with an [`ItemKey`] (the
    /// cursor `last_key`).
    ///
    /// ## Toxic-byte policy
    ///
    /// `Debug` and `Display` are redacted (length + hash prefix). Raw bytes can
    /// be borrowed through [`as_bytes`](Self::as_bytes) / [`AsRef<[u8]>`](AsRef),
    /// or borrowed via [`AsRef<[u8]>`](AsRef).
    TokenBytes, max = MAX_TOKEN_SIZE
}

/// Owned cursor used across connector boundaries.
///
/// This bridges to/from the coordination layer's borrowed [`CursorUpdate`]
/// without exposing connector internals to coordination callers.
///
/// ## Invariants
///
/// - `token` is only meaningful when paired with a `last_key`.
/// - Constructors make the invalid `(None, Some(token))` state
///   unrepresentable.
/// - [`try_from_update`](Self::try_from_update) validates external cursor
///   updates and rejects token-without-key states via
///   [`ConnectorInputError::TokenWithoutLastKey`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cursor {
    /// The last fully processed ordered item key, used to bound the next page.
    last_key: Option<ItemKey>,
    /// Connector-opaque token for resuming enumeration at a specific state.
    token: Option<TokenBytes>,
}

impl Cursor {
    /// Initial cursor: no progress key and no resume token.
    ///
    /// This is the neutral state used at scan start and for defensive
    /// normalization when malformed external input is discarded.
    #[inline]
    #[must_use]
    pub fn initial() -> Self {
        Self {
            last_key: None,
            token: None,
        }
    }

    /// Cursor with a `last_key` and no token.
    ///
    /// Use this after processing a page that does not require connector-side
    /// continuation state.
    #[inline]
    #[must_use]
    pub fn with_last_key(last_key: ItemKey) -> Self {
        Self {
            last_key: Some(last_key),
            token: None,
        }
    }

    /// Cursor with both `last_key` and token.
    ///
    /// This represents continuation state for connectors that require an
    /// opaque token in addition to the ordered progress key.
    #[inline]
    #[must_use]
    pub fn with_token(last_key: ItemKey, token: TokenBytes) -> Self {
        Self {
            last_key: Some(last_key),
            token: Some(token),
        }
    }

    /// Returns the last fully processed key, if any.
    #[inline]
    #[must_use]
    pub fn last_key(&self) -> Option<&ItemKey> {
        self.last_key.as_ref()
    }

    /// Returns the connector-opaque resume token, if any.
    ///
    /// `Some` implies [`last_key`](Self::last_key) is also `Some`.
    #[inline]
    #[must_use]
    pub fn token(&self) -> Option<&TokenBytes> {
        self.token.as_ref()
    }

    /// Borrow this owned cursor as a coordination [`CursorUpdate`].
    ///
    /// This projection is allocation-free. The returned update borrows from
    /// `self` and remains valid for the same lifetime.
    ///
    /// The `(None, Some(_))` state is unreachable because all constructors
    /// prevent token-without-key. If reached, this panics to surface the
    /// logic error rather than silently resetting cursor progress.
    ///
    /// # Panics
    ///
    /// Panics if the cursor invariant `(None, Some(_))` is observed, because
    /// that state should never exist outside of an internal bug.
    #[inline]
    #[must_use]
    pub fn as_update(&self) -> CursorUpdate<'_> {
        match (&self.last_key, &self.token) {
            (None, None) => CursorUpdate::initial(),
            (Some(last_key), None) => CursorUpdate::with_last_key(last_key.as_bytes()),
            (Some(last_key), Some(token)) => {
                CursorUpdate::with_token(last_key.as_bytes(), token.as_bytes())
            }
            (None, Some(_)) => unreachable!(
                "Cursor invariant violated: token present without last_key. \
                 All constructors prevent this state."
            ),
        }
    }

    /// Copy from a borrowed coordination cursor update.
    ///
    /// Empty token values normalize to `None` so caller behavior does not
    /// depend on whether a connector emits "no token" as `None` or `Some([])`.
    ///
    /// # Errors
    ///
    /// - Returns [`ConnectorInputError::TokenWithoutLastKey`] if a non-empty
    ///   `token` is present but `last_key` is not.
    /// - Returns [`ConnectorInputError::Empty`] / [`ConnectorInputError::TooLarge`]
    ///   when `last_key` or `token` fail wrapper validation.
    pub fn try_from_update(update: CursorUpdate<'_>) -> Result<Self, ConnectorInputError> {
        let last_key = match update.last_key() {
            None => None,
            Some(last_key) => Some(ItemKey::try_from_slice(last_key)?),
        };
        let token = match update.token() {
            None => None,
            Some([]) => None,
            Some(token) => Some(TokenBytes::try_from_slice(token)?),
        };
        if last_key.is_none() && token.is_some() {
            return Err(ConnectorInputError::TokenWithoutLastKey);
        }
        Ok(Self { last_key, token })
    }
}

impl Default for Cursor {
    fn default() -> Self {
        Self::initial()
    }
}

/// Version claim strength for an item's content identity.
///
/// Connectors often have both a 32-byte derived content identifier and
/// additional semantics about how trustworthy that identifier is as an
/// immutability signal. `VersionId` keeps both pieces together:
///
/// - variant (`Strong` vs `Weak`) communicates confidence semantics;
/// - payload ([`ObjectVersionId`]) keeps the hashing/derivation surface stable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum VersionId {
    /// Strong version identity that should reliably reference immutable content.
    Strong(ObjectVersionId),
    /// Weak version identity where content may change without version changes.
    Weak(ObjectVersionId),
}

impl VersionId {
    /// Returns the wrapped [`ObjectVersionId`] regardless of claim strength.
    ///
    /// This allows downstream code to derive occurrence identities without
    /// branching on strength semantics.
    #[inline]
    #[must_use]
    pub const fn object_version_id(self) -> ObjectVersionId {
        match self {
            Self::Strong(version_id) | Self::Weak(version_id) => version_id,
        }
    }

    /// Returns whether this is a strong version identity.
    ///
    /// Callers can use this to gate trust-sensitive behavior (for example,
    /// deciding whether to treat unchanged version IDs as a strong no-change
    /// signal).
    #[inline]
    #[must_use]
    pub const fn is_strong(self) -> bool {
        matches!(self, Self::Strong(_))
    }
}

/// Optional hints about how to interpret item content.
///
/// These fields are intentionally advisory. The contracts layer enforces only
/// byte-size bounds, not MIME/encoding grammar, so connector implementations
/// can forward source-native metadata without lossy normalization.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ContentHints {
    /// Optional MIME-like media type hint.
    media_type: Option<String>,
    /// Optional transfer or content encoding hint.
    encoding: Option<String>,
}

impl ContentHints {
    /// Construct bounded content hints.
    ///
    /// Empty strings are normalized to `None` so callers cannot observe a
    /// semantic difference between "not provided" and "provided but empty".
    ///
    /// # Errors
    ///
    /// Returns [`ConnectorInputError::TooLarge`] when:
    ///
    /// - `media_type` exceeds `MAX_CONTENT_HINT_MEDIA_TYPE_SIZE`
    /// - `encoding` exceeds `MAX_CONTENT_HINT_ENCODING_SIZE`
    pub fn try_new(
        media_type: Option<String>,
        encoding: Option<String>,
    ) -> Result<Self, ConnectorInputError> {
        // Normalize empty strings to None before validation.
        let media_type = media_type.filter(|s| !s.is_empty());
        let encoding = encoding.filter(|s| !s.is_empty());

        if let Some(media_type) = media_type.as_ref()
            && media_type.len() > MAX_CONTENT_HINT_MEDIA_TYPE_SIZE
        {
            return Err(ConnectorInputError::TooLarge {
                field: "ContentHints.media_type",
                size: media_type.len(),
                max: MAX_CONTENT_HINT_MEDIA_TYPE_SIZE,
            });
        }
        if let Some(encoding) = encoding.as_ref()
            && encoding.len() > MAX_CONTENT_HINT_ENCODING_SIZE
        {
            return Err(ConnectorInputError::TooLarge {
                field: "ContentHints.encoding",
                size: encoding.len(),
                max: MAX_CONTENT_HINT_ENCODING_SIZE,
            });
        }
        Ok(Self {
            media_type,
            encoding,
        })
    }

    /// Returns the MIME-like media type, if known.
    ///
    /// `None` means "unknown" — empty strings are normalized away by the
    /// constructor.
    #[inline]
    #[must_use]
    pub fn media_type(&self) -> Option<&str> {
        self.media_type.as_deref()
    }

    /// Returns the transfer/content encoding name, if known.
    ///
    /// `None` means no encoding hint is available.
    #[inline]
    #[must_use]
    pub fn encoding(&self) -> Option<&str> {
        self.encoding.as_deref()
    }
}

/// Display-safe location metadata for UI/debugging.
///
/// `Location` gives consumers a bounded, human-readable reference they can
/// safely surface in logs and UI without requiring raw connector internals.
/// `url` is optional and size-bounded, but intentionally not parsed or
/// canonicalized at this layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Location {
    /// Required human-readable display string for this location.
    display: String,
    /// Optional deep-link or reference URI. Not canonically parsed.
    url: Option<String>,
}

impl Location {
    /// Construct a bounded display location.
    ///
    /// `display` is required because it is the stable fallback shown when
    /// no `url` is available or safe to render. Empty URL strings are
    /// normalized to `None` so callers cannot observe a semantic difference
    /// between "not provided" and "provided but empty".
    ///
    /// # Errors
    ///
    /// - [`ConnectorInputError::Empty`] when `display` is empty.
    /// - [`ConnectorInputError::TooLarge`] when `display` or `url` exceeds
    ///   the corresponding `MAX_LOCATION_*` limits.
    pub fn try_new(display: String, url: Option<String>) -> Result<Self, ConnectorInputError> {
        let url = url.filter(|u| !u.is_empty());
        if display.is_empty() {
            return Err(ConnectorInputError::Empty {
                field: "Location.display",
            });
        }
        if display.len() > MAX_LOCATION_DISPLAY_SIZE {
            return Err(ConnectorInputError::TooLarge {
                field: "Location.display",
                size: display.len(),
                max: MAX_LOCATION_DISPLAY_SIZE,
            });
        }
        if let Some(url) = url.as_ref()
            && url.len() > MAX_LOCATION_URL_SIZE
        {
            return Err(ConnectorInputError::TooLarge {
                field: "Location.url",
                size: url.len(),
                max: MAX_LOCATION_URL_SIZE,
            });
        }
        Ok(Self { display, url })
    }

    /// Returns the human-readable location string.
    #[inline]
    #[must_use]
    pub fn display(&self) -> &str {
        &self.display
    }

    /// Returns the optional URL-like deep link.
    #[inline]
    #[must_use]
    pub fn url(&self) -> Option<&str> {
        self.url.as_deref()
    }
}

/// Connector-owned item metadata produced by an enumeration pass.
///
/// `ScanItem` keeps core identity fields (`item_key`, `item_ref`,
/// `stable_item_id`, `version`) alongside optional bounded metadata used for
/// presentation and scheduling (`size_hint`, `content_hints`, `location`).
///
/// Optional fields default to `None` and can be set with builder-style methods
/// after constructing the required identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanItem {
    /// Ordered key used for pagination and cursor progression.
    item_key: ItemKey,
    /// Opaque handle used by connectors for subsequent read or open operations.
    item_ref: ItemRef,
    /// Stable, tenant-independent identity of the underlying data.
    stable_item_id: StableItemId,
    /// Strength and payload of the connector's version evidence.
    version: VersionId,
    /// Optional byte-size estimate for the content.
    size_hint: Option<u64>,
    /// Optional hints for parsing or interpreting the content.
    content_hints: Option<ContentHints>,
    /// Optional display-safe metadata for locating the item.
    location: Option<Location>,
}

impl ScanItem {
    /// Construct a scan item with required identity fields.
    ///
    /// Optional metadata fields initialize to `None`.
    #[must_use]
    pub fn new(
        item_key: ItemKey,
        item_ref: ItemRef,
        stable_item_id: StableItemId,
        version: VersionId,
    ) -> Self {
        Self {
            item_key,
            item_ref,
            stable_item_id,
            version,
            size_hint: None,
            content_hints: None,
            location: None,
        }
    }

    /// Set the optional size hint in bytes.
    #[must_use]
    pub fn with_size_hint(self, size_hint: u64) -> Self {
        Self {
            size_hint: Some(size_hint),
            ..self
        }
    }

    /// Set optional content hints.
    #[must_use]
    pub fn with_content_hints(self, content_hints: ContentHints) -> Self {
        Self {
            content_hints: Some(content_hints),
            ..self
        }
    }

    /// Set optional display-safe location metadata.
    #[must_use]
    pub fn with_location(self, location: Location) -> Self {
        Self {
            location: Some(location),
            ..self
        }
    }

    /// Returns the ordered item key used for paging progression.
    #[inline]
    #[must_use]
    pub fn item_key(&self) -> &ItemKey {
        &self.item_key
    }

    /// Returns the connector-opaque item reference used for later reads.
    #[inline]
    #[must_use]
    pub fn item_ref(&self) -> &ItemRef {
        &self.item_ref
    }

    /// Returns the stable tenant-independent item identity.
    #[inline]
    #[must_use]
    pub fn stable_item_id(&self) -> StableItemId {
        self.stable_item_id
    }

    /// Returns connector-provided version semantics for this item.
    #[inline]
    #[must_use]
    pub fn version(&self) -> VersionId {
        self.version
    }

    /// Returns an optional byte-size estimate for this item.
    #[inline]
    #[must_use]
    pub fn size_hint(&self) -> Option<u64> {
        self.size_hint
    }

    /// Returns optional content interpretation hints.
    #[inline]
    #[must_use]
    pub fn content_hints(&self) -> Option<&ContentHints> {
        self.content_hints.as_ref()
    }

    /// Returns optional display-safe location metadata.
    #[inline]
    #[must_use]
    pub fn location(&self) -> Option<&Location> {
        self.location.as_ref()
    }

    /// Consume this scan item, returning its ordered key for cursor advancement.
    #[inline]
    #[must_use]
    pub fn into_item_key(self) -> ItemKey {
        self.item_key
    }

    /// Consume the scan item, returning all fields as owned values.
    ///
    /// Use this when you need owned access to multiple fields without cloning.
    /// The tuple order matches the struct field declaration:
    /// `(item_key, item_ref, stable_item_id, version, size_hint,
    /// content_hints, location)`.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        ItemKey,
        ItemRef,
        StableItemId,
        VersionId,
        Option<u64>,
        Option<ContentHints>,
        Option<Location>,
    ) {
        (
            self.item_key,
            self.item_ref,
            self.stable_item_id,
            self.version,
            self.size_hint,
            self.content_hints,
            self.location,
        )
    }
}

/// Page/scan budget controls used by connector enumeration APIs.
///
/// `Budgets` combines up to three stop conditions:
/// - `max_items`: upper bound on number of returned items.
/// - `max_bytes`: upper bound on cumulative bytes consumed.
/// - `deadline`: optional monotonic deadline (`Instant`).
///
/// `max_items` and `max_bytes` are stored as [`NonZeroUsize`] and
/// [`NonZeroU64`] respectively so that a vacuous zero budget is
/// unrepresentable. Use [`try_new`](Self::try_new) to construct.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Budgets {
    /// Upper bound on the number of returned items.
    max_items: NonZeroUsize,
    /// Upper bound on the cumulative bytes consumed during the scan.
    max_bytes: NonZeroU64,
    /// Optional monotonic deadline for scan termination.
    deadline: Option<Instant>,
}

impl Budgets {
    /// Construct a validated set of scan budgets.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectorInputError::ZeroBudget`] when `max_items` or
    /// `max_bytes` is zero.
    #[inline]
    pub fn try_new(
        max_items: usize,
        max_bytes: u64,
        deadline: Option<Instant>,
    ) -> Result<Self, ConnectorInputError> {
        let max_items = NonZeroUsize::new(max_items).ok_or(ConnectorInputError::ZeroBudget {
            field: "Budgets.max_items",
        })?;
        let max_bytes = NonZeroU64::new(max_bytes).ok_or(ConnectorInputError::ZeroBudget {
            field: "Budgets.max_bytes",
        })?;
        Ok(Self {
            max_items,
            max_bytes,
            deadline,
        })
    }

    /// Returns the maximum number of items allowed for the scan/page.
    #[inline]
    #[must_use]
    pub fn max_items(&self) -> usize {
        self.max_items.get()
    }

    /// Returns the maximum number of bytes allowed for the scan/page.
    #[inline]
    #[must_use]
    pub fn max_bytes(&self) -> u64 {
        self.max_bytes.get()
    }

    /// Returns the optional scan deadline.
    #[inline]
    #[must_use]
    pub fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    /// Returns `true` when the configured deadline has elapsed relative to
    /// `now`. Returns `false` when no deadline is set.
    ///
    /// Accepting the current instant as a parameter keeps this function pure
    /// and deterministic, which is required for simulation testing.
    #[inline]
    #[must_use]
    pub fn is_expired_at(&self, now: Instant) -> bool {
        self.deadline.is_some_and(|deadline| now >= deadline)
    }
}

#[cfg(test)]
#[path = "types_tests.rs"]
mod tests;

## 1) Scope

- **Chunk 1 only**: implement the **connector-facing value types** in `crates/gossip-contracts/src/connector/`
- In scope:
  - `ItemKey`, `ItemRef`, `TokenBytes`
  - `Cursor` (owned) with conversion to/from `coordination::CursorUpdate`
  - `VersionId` (Strong/Weak around `identity::ObjectVersionId`)
  - `ContentHints`, `Location`
  - `ScanItem`, `EnumerationPage`
  - `Budgets`
  - **Hard size caps** + **hash-only/redacted Debug + Display** for toxic byte fields

- Out of scope (Chunk 2+):
  - connector traits (`enumerate_page`, `open`)
  - validator + harness

## 2) Assumptions

- Chunk 0 rename already landed in your branch; I **avoid referencing** the renamed identity key type to keep this chunk orthogonal.
- These types exist (they do in the current upstream code):
  - `crate::coordination::CursorUpdate`
  - `crate::coordination::MAX_KEY_SIZE`
  - `crate::coordination::CursorMaxTokenSize` (alias of MAX_TOKEN_SIZE via `coordination/mod.rs`)
  - `crate::identity::{StableItemId, ObjectVersionId}`

## 3) Decision

### Recommended (do this)

- **Define connector boundary types in `gossip_contracts::connector`** with:
  - strict byte-size limits aligned with coordination cursor/shard spec ceilings
  - **redacted Debug and Display** for `ItemKey`, `ItemRef`, `TokenBytes` (hash prefix only)

Why:

- Forces “no toxic bytes in logs” by default
- Aligns cursor/key caps with the coordination layer’s already-established constraints

### Alternative

- Don’t implement `Display` for toxic types (only `Debug`).
  Tradeoff:
- Safer against accidental `{}` formatting, but you will fight the ecosystem (errors, logs, `thiserror`, etc.).
- Redacted `Display` is a decent compromise: people can format it, but it stays safe.

## 4) Invariants and failure behavior

### Safety invariants

- `ItemKey`, `ItemRef`, `TokenBytes`:
  - MUST be non-empty
  - MUST be <= configured max size
  - MUST NOT reveal raw bytes via `Debug` or `Display`

- `Cursor`:
  - `token` implies `last_key` (no token-only cursor)
  - conversion to `CursorUpdate` must preserve that invariant

### Failure behavior

- Violations return `ConnectorInputError` (or panic for `new_*` constructors explicitly marked as panicking, matching your existing “panic vs try\_\*” constructor style elsewhere in contracts).

## 5) Tests

Stubs are fine for Chunk 1, but I included small unit tests proving:

- redacted formatting doesn’t contain raw substrings
- size caps reject oversized inputs

More serious validator/harness tests are Chunk 3 and Chunk 4.

## 6) Implementation

### Data model summary

- `ItemKey`: ordered bytes for enumeration/sharding (lexicographic)
- `ItemRef`: opaque, credential-free handle for `open()`
- `StableItemId`: required on `ScanItem` (already a safe hashed id)
- `VersionId`: `Strong(ObjectVersionId)` | `Weak(ObjectVersionId)`
- `Cursor`: owned cursor with optional `last_key` and optional `token`
- `Budgets`: `max_items`, `max_bytes`, optional `deadline`

### Perf bounds

- Constructors are O(n) for size checks + single allocation/copy (slice inputs copy, vec inputs move)
- Redacted formatting hashes on demand (Debug/Display only)

---

## 7) Code

### `crates/gossip-contracts/src/connector/mod.rs`

```rust
//! Connector boundary: shared value types and (later) traits for enumeration + reads.
//!
//! This module is the "plug interface" between the distributed runtime and
//! per-source connectors. The main job of Chunk 1 is to lock down **value types**
//! with:
//! - strict size caps (bounded memory + bounded state),
//! - safe-by-default formatting (no raw toxic bytes in Debug/Display),
//! - cursor shapes that align with `gossip_contracts::coordination`.
//!
//! **Toxic bytes policy (non-negotiable):**
//! - `ItemKey`, `ItemRef`, and pagination tokens are treated as toxic.
//! - They must never format as raw bytes.
//! - Debug/Display must be hash-only/redacted.

mod types;

pub use types::{
    Budgets, ConnectorInputError, ContentHints, Cursor, EnumerationPage, ItemKey, ItemRef,
    Location, ScanItem, TokenBytes, VersionId, MAX_ITEM_KEY_SIZE, MAX_ITEM_REF_SIZE,
    MAX_LOCATION_DISPLAY_SIZE, MAX_LOCATION_URL_SIZE,
};
```

### `crates/gossip-contracts/src/connector/types.rs`

```rust
use std::fmt;
use std::time::Instant;

use blake3::Hash;

use crate::coordination::{CursorMaxTokenSize, CursorUpdate, MAX_KEY_SIZE};
use crate::identity::{ObjectVersionId, StableItemId};

/// Maximum size of an `ItemKey` in bytes.
///
/// Must stay aligned with coordination key ceilings because shard specs and
/// cursor last_key fields live in the same lexicographic keyspace.
pub const MAX_ITEM_KEY_SIZE: usize = MAX_KEY_SIZE;

/// Maximum size of an `ItemRef` in bytes.
///
/// Item refs are opaque and connector-defined, but must remain bounded.
/// 16 KiB matches the "opaque metadata / token" ceilings used elsewhere.
pub const MAX_ITEM_REF_SIZE: usize = 16_384;

/// Maximum size of `Location.display` in bytes (UTF-8).
pub const MAX_LOCATION_DISPLAY_SIZE: usize = 4_096;

/// Maximum size of `Location.url` in bytes (UTF-8).
pub const MAX_LOCATION_URL_SIZE: usize = 4_096;

/// Maximum size of a pagination token in bytes.
///
/// Aligned with coordination cursor token ceilings.
pub const MAX_TOKEN_SIZE: usize = CursorMaxTokenSize;

// ============================================================================
// Errors
// ============================================================================

/// Input validation errors for connector boundary value types.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConnectorInputError {
    /// A required field was empty.
    Empty { field: &'static str },
    /// A field exceeded its hard size limit.
    TooLarge {
        field: &'static str,
        size: usize,
        max: usize,
    },
    /// A cursor token was supplied without a last_key.
    TokenWithoutLastKey,
}

impl fmt::Display for ConnectorInputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty { field } => write!(f, "{field} must not be empty"),
            Self::TooLarge { field, size, max } => {
                write!(f, "{field} too large ({size} bytes, max {max})")
            }
            Self::TokenWithoutLastKey => write!(f, "cursor token requires a last_key"),
        }
    }
}

impl std::error::Error for ConnectorInputError {}

// ============================================================================
// Redacted formatting helpers
// ============================================================================

#[inline]
fn hash_prefix_4(bytes: &[u8]) -> [u8; 4] {
    // BLAKE3 is already a dependency of contracts. Debug formatting is not
    // a hot path, so hashing here is acceptable and safer than ever printing bytes.
    let h: Hash = blake3::hash(bytes);
    let b = h.as_bytes();
    [b[0], b[1], b[2], b[3]]
}

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

// ============================================================================
// ItemKey
// ============================================================================

/// Ordered enumeration key used for sharding, paging, and cursor progression.
///
/// Ordering is lexicographic over raw bytes.
///
/// # Safety
/// `ItemKey` is treated as **toxic**: it may contain user-controlled or
/// sensitive strings (paths, object names, etc.). It must never format as raw
/// bytes in logs.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ItemKey(Box<[u8]>);

impl ItemKey {
    /// Panicking constructor for trusted internal call sites.
    ///
    /// # Panics
    /// Panics if empty or larger than [`MAX_ITEM_KEY_SIZE`].
    #[must_use]
    pub fn from_vec(bytes: Vec<u8>) -> Self {
        Self::try_from_vec(bytes).expect("ItemKey must be non-empty and within size limits")
    }

    /// Fallible constructor that takes ownership without copying.
    pub fn try_from_vec(bytes: Vec<u8>) -> Result<Self, ConnectorInputError> {
        if bytes.is_empty() {
            return Err(ConnectorInputError::Empty { field: "ItemKey" });
        }
        if bytes.len() > MAX_ITEM_KEY_SIZE {
            return Err(ConnectorInputError::TooLarge {
                field: "ItemKey",
                size: bytes.len(),
                max: MAX_ITEM_KEY_SIZE,
            });
        }
        Ok(Self(bytes.into_boxed_slice()))
    }

    /// Fallible constructor from a borrowed slice (copies bytes).
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, ConnectorInputError> {
        if bytes.is_empty() {
            return Err(ConnectorInputError::Empty { field: "ItemKey" });
        }
        if bytes.len() > MAX_ITEM_KEY_SIZE {
            return Err(ConnectorInputError::TooLarge {
                field: "ItemKey",
                size: bytes.len(),
                max: MAX_ITEM_KEY_SIZE,
            });
        }
        Ok(Self(bytes.to_vec().into_boxed_slice()))
    }

    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for ItemKey {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl fmt::Debug for ItemKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_toxic_bytes(f, "ItemKey", &self.0)
    }
}

impl fmt::Display for ItemKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_toxic_bytes(f, "ItemKey", &self.0)
    }
}

// ============================================================================
// ItemRef
// ============================================================================

/// Opaque, credential-free handle used to open/read an item.
///
/// # Safety
/// Treated as **toxic**: must not format as raw bytes.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ItemRef(Box<[u8]>);

impl ItemRef {
    /// Panicking constructor for trusted internal call sites.
    ///
    /// # Panics
    /// Panics if empty or larger than [`MAX_ITEM_REF_SIZE`].
    #[must_use]
    pub fn from_vec(bytes: Vec<u8>) -> Self {
        Self::try_from_vec(bytes).expect("ItemRef must be non-empty and within size limits")
    }

    /// Fallible constructor that takes ownership without copying.
    pub fn try_from_vec(bytes: Vec<u8>) -> Result<Self, ConnectorInputError> {
        if bytes.is_empty() {
            return Err(ConnectorInputError::Empty { field: "ItemRef" });
        }
        if bytes.len() > MAX_ITEM_REF_SIZE {
            return Err(ConnectorInputError::TooLarge {
                field: "ItemRef",
                size: bytes.len(),
                max: MAX_ITEM_REF_SIZE,
            });
        }
        Ok(Self(bytes.into_boxed_slice()))
    }

    /// Fallible constructor from a borrowed slice (copies bytes).
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, ConnectorInputError> {
        if bytes.is_empty() {
            return Err(ConnectorInputError::Empty { field: "ItemRef" });
        }
        if bytes.len() > MAX_ITEM_REF_SIZE {
            return Err(ConnectorInputError::TooLarge {
                field: "ItemRef",
                size: bytes.len(),
                max: MAX_ITEM_REF_SIZE,
            });
        }
        Ok(Self(bytes.to_vec().into_boxed_slice()))
    }

    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for ItemRef {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl fmt::Debug for ItemRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_toxic_bytes(f, "ItemRef", &self.0)
    }
}

impl fmt::Display for ItemRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_toxic_bytes(f, "ItemRef", &self.0)
    }
}

// ============================================================================
// TokenBytes
// ============================================================================

/// Connector-opaque pagination / resume token.
///
/// This token is explicitly *not* relied upon for correctness. The durable
/// resumption primitive is `Cursor.last_key`. Tokens are an optimization.
///
/// # Safety
/// Treated as **toxic**: must not format as raw bytes.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct TokenBytes(Box<[u8]>);

impl TokenBytes {
    /// Fallible constructor that takes ownership without copying.
    pub fn try_from_vec(bytes: Vec<u8>) -> Result<Self, ConnectorInputError> {
        if bytes.is_empty() {
            return Err(ConnectorInputError::Empty {
                field: "TokenBytes",
            });
        }
        if bytes.len() > MAX_TOKEN_SIZE {
            return Err(ConnectorInputError::TooLarge {
                field: "TokenBytes",
                size: bytes.len(),
                max: MAX_TOKEN_SIZE,
            });
        }
        Ok(Self(bytes.into_boxed_slice()))
    }

    /// Fallible constructor from a borrowed slice (copies bytes).
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, ConnectorInputError> {
        if bytes.is_empty() {
            return Err(ConnectorInputError::Empty {
                field: "TokenBytes",
            });
        }
        if bytes.len() > MAX_TOKEN_SIZE {
            return Err(ConnectorInputError::TooLarge {
                field: "TokenBytes",
                size: bytes.len(),
                max: MAX_TOKEN_SIZE,
            });
        }
        Ok(Self(bytes.to_vec().into_boxed_slice()))
    }

    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for TokenBytes {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl fmt::Debug for TokenBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_toxic_bytes(f, "TokenBytes", &self.0)
    }
}

impl fmt::Display for TokenBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_toxic_bytes(f, "TokenBytes", &self.0)
    }
}

// ============================================================================
// Cursor (owned)
// ============================================================================

/// Owned cursor used across connector boundaries.
///
/// Internally convertible to/from the coordination layer's borrowed
/// [`CursorUpdate`] type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cursor {
    last_key: Option<ItemKey>,
    token: Option<TokenBytes>,
}

impl Cursor {
    /// Initial cursor: no progress.
    #[inline]
    #[must_use]
    pub fn initial() -> Self {
        Self {
            last_key: None,
            token: None,
        }
    }

    /// Construct a cursor at a known last_key, without a token.
    #[inline]
    #[must_use]
    pub fn with_last_key(last_key: ItemKey) -> Self {
        Self {
            last_key: Some(last_key),
            token: None,
        }
    }

    /// Construct a cursor at last_key with an opaque token.
    #[inline]
    #[must_use]
    pub fn with_token(last_key: ItemKey, token: TokenBytes) -> Self {
        Self {
            last_key: Some(last_key),
            token: Some(token),
        }
    }

    #[inline]
    #[must_use]
    pub fn last_key(&self) -> Option<&ItemKey> {
        self.last_key.as_ref()
    }

    #[inline]
    #[must_use]
    pub fn token(&self) -> Option<&TokenBytes> {
        self.token.as_ref()
    }

    /// Borrow as a coordination-layer cursor update.
    #[inline]
    #[must_use]
    pub fn as_update(&self) -> CursorUpdate<'_> {
        match (&self.last_key, &self.token) {
            (None, None) => CursorUpdate::initial(),
            (Some(k), None) => CursorUpdate::new(k.as_bytes()),
            (Some(k), Some(t)) => CursorUpdate::with_token(k.as_bytes(), t.as_bytes()),
            (None, Some(_)) => {
                // Should be unrepresentable via constructors.
                debug_assert!(false, "Cursor invariant violated: token without last_key");
                CursorUpdate::initial()
            }
        }
    }

    /// Convert from a borrowed coordination cursor update (copies bytes).
    pub fn try_from_update(update: CursorUpdate<'_>) -> Result<Self, ConnectorInputError> {
        let last_key = match update.last_key() {
            None => None,
            Some(k) => Some(ItemKey::try_from_slice(k)?),
        };

        let token = match update.token() {
            None => None,
            Some(t) if t.is_empty() => None, // defensive: normalize empty -> None
            Some(t) => Some(TokenBytes::try_from_slice(t)?),
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

// ============================================================================
// VersionId
// ============================================================================

/// Version claim for an item's content.
///
/// - `Strong`: the connector asserts it can reliably re-open the same version.
/// - `Weak`: best-effort versioning (content may change without version changing).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum VersionId {
    Strong(ObjectVersionId),
    Weak(ObjectVersionId),
}

impl VersionId {
    #[inline]
    #[must_use]
    pub const fn object_version_id(self) -> ObjectVersionId {
        match self {
            Self::Strong(v) => v,
            Self::Weak(v) => v,
        }
    }

    #[inline]
    #[must_use]
    pub const fn is_strong(self) -> bool {
        matches!(self, Self::Strong(_))
    }
}

// ============================================================================
// ContentHints + Location
// ============================================================================

/// Optional hints about how to interpret the item's content.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ContentHints {
    pub media_type: Option<String>,
    pub encoding: Option<String>,
}

impl ContentHints {
    pub fn try_new(
        media_type: Option<String>,
        encoding: Option<String>,
    ) -> Result<Self, ConnectorInputError> {
        if let Some(mt) = media_type.as_ref() {
            if mt.len() > 256 {
                return Err(ConnectorInputError::TooLarge {
                    field: "ContentHints.media_type",
                    size: mt.len(),
                    max: 256,
                });
            }
        }
        if let Some(enc) = encoding.as_ref() {
            if enc.len() > 128 {
                return Err(ConnectorInputError::TooLarge {
                    field: "ContentHints.encoding",
                    size: enc.len(),
                    max: 128,
                });
            }
        }
        Ok(Self { media_type, encoding })
    }
}

/// Display-safe location information for UI/debugging.
///
/// This is not used for correctness. Treat it as optional presentation data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Location {
    pub display: String,
    pub url: Option<String>,
}

impl Location {
    pub fn try_new(display: String, url: Option<String>) -> Result<Self, ConnectorInputError> {
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
        if let Some(u) = url.as_ref() {
            if u.len() > MAX_LOCATION_URL_SIZE {
                return Err(ConnectorInputError::TooLarge {
                    field: "Location.url",
                    size: u.len(),
                    max: MAX_LOCATION_URL_SIZE,
                });
            }
        }

        Ok(Self { display, url })
    }
}

// ============================================================================
// ScanItem + EnumerationPage
// ============================================================================

/// A single enumerated item to be scanned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanItem {
    pub item_key: ItemKey,
    pub item_ref: ItemRef,
    pub stable_item_id: StableItemId,
    pub version: VersionId,
    pub size_hint: Option<u64>,
    pub content_hints: Option<ContentHints>,
    pub location: Option<Location>,
}

impl ScanItem {
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

    #[must_use]
    pub fn with_size_hint(mut self, size_hint: Option<u64>) -> Self {
        self.size_hint = size_hint;
        self
    }

    #[must_use]
    pub fn with_content_hints(mut self, hints: ContentHints) -> Self {
        self.content_hints = Some(hints);
        self
    }

    #[must_use]
    pub fn with_location(mut self, location: Location) -> Self {
        self.location = Some(location);
        self
    }
}

/// Result of a single `enumerate_page` call: items plus the next cursor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnumerationPage {
    pub items: Vec<ScanItem>,
    pub next_cursor: Cursor,
}

impl EnumerationPage {
    #[must_use]
    pub fn new(items: Vec<ScanItem>, next_cursor: Cursor) -> Self {
        Self { items, next_cursor }
    }
}

// ============================================================================
// Budgets
// ============================================================================

/// Resource budgets for connector operations.
#[derive(Clone, Copy, Debug)]
pub struct Budgets {
    pub max_items: usize,
    pub max_bytes: u64,
    pub deadline: Option<Instant>,
}

impl Budgets {
    #[must_use]
    pub fn new(max_items: usize, max_bytes: u64, deadline: Option<Instant>) -> Self {
        Self {
            max_items,
            max_bytes,
            deadline,
        }
    }

    #[inline]
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.deadline.is_some_and(|d| Instant::now() >= d)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn item_key_debug_is_redacted() {
        let key = ItemKey::try_from_slice(b"super-secret-path").unwrap();
        let s = format!("{key:?}");
        assert!(!s.contains("super-secret-path"), "debug leaked raw bytes: {s}");
        assert!(s.contains("len="));
        assert!(s.contains("hash="));
    }

    #[test]
    fn item_ref_debug_is_redacted() {
        let r = ItemRef::try_from_slice(b"Bearer really-bad-idea").unwrap();
        let s = format!("{r:?}");
        assert!(
            !s.contains("Bearer"),
            "debug leaked raw bytes: {s}"
        );
        assert!(s.contains("len="));
        assert!(s.contains("hash="));
    }

    #[test]
    fn token_debug_is_redacted() {
        let t = TokenBytes::try_from_slice(b"page_token=abcdef").unwrap();
        let s = format!("{t:?}");
        assert!(
            !s.contains("page_token"),
            "debug leaked raw bytes: {s}"
        );
        assert!(s.contains("len="));
        assert!(s.contains("hash="));
    }

    #[test]
    fn item_key_size_cap_is_enforced() {
        let too_big = vec![0u8; MAX_ITEM_KEY_SIZE + 1];
        let err = ItemKey::try_from_vec(too_big).unwrap_err();
        assert!(matches!(err, ConnectorInputError::TooLarge { field: "ItemKey", .. }));
    }

    #[test]
    fn item_ref_size_cap_is_enforced() {
        let too_big = vec![0u8; MAX_ITEM_REF_SIZE + 1];
        let err = ItemRef::try_from_vec(too_big).unwrap_err();
        assert!(matches!(err, ConnectorInputError::TooLarge { field: "ItemRef", .. }));
    }
}
```

### Commands to run

```sh
cargo test -p gossip-contracts
cargo check
```

---

This chunk is intentionally “boring but strict”. If these types are leaky or inconsistent now, every connector and every validator later becomes a mess. Next chunk (2) is where we add the traits and capability flags on top of this surface.

//! Scan-object identity: the types that answer "what was scanned" and
//! "which version of it."
//!
//! # Type overview
//!
//! | Type | Width | Construction | Purpose |
//! |------|-------|-------------|---------|
//! | [`ConnectorTag`] | 8 B | `from_ascii` / `from_bytes` | Source-system discriminator |
//! | [`ItemKey`] | variable | `new(connector, path)` | Human-meaningful item identity |
//! | [`ItemKeyRef`] | variable | `new(connector, path)` | Allocation-free borrowed item-key view |
//! | [`ItemKeyScratch`] | const-capacity | `from_path(connector, path)` | Scratch-backed runtime path builder |
//! | [`StableItemId`] | 32 B | derived via `ItemKey::stable_id` | Fixed-width item identity for derivation |
//! | [`ObjectVersionId`] | 32 B | `from_version_bytes` | Version-specific content identity |
//!
//! # Derivation flow
//!
//! ```text
//! ConnectorTag + path ──► ItemKey ──(blake3 derive-key)──► StableItemId
//!                                                              │
//!                                                    enters FindingId derivation
//!
//! version token bytes ──(blake3 derive-key)──► ObjectVersionId
//!                                                    │
//!                                          enters OccurrenceId derivation
//! ```
//!
//! `StableItemId` and `ObjectVersionId` are independent derivations with
//! distinct BLAKE3 domain separators (see [`super::domain`]). Both are
//! consumed downstream by the finding module — `StableItemId` in
//! `FindingId` and `ObjectVersionId` in `OccurrenceId` — but neither
//! depends on the other.

use blake3::Hasher;
use core::fmt;

use super::canonical::CanonicalBytes;
use super::hashing::{ITEM_ID_HASHER, OBJECT_VERSION_HASHER, finalize_32};

// ---------------------------------------------------------------------------
// IdentityInputError — validation errors for identity constructors
// ---------------------------------------------------------------------------

/// Errors from identity type construction.
///
/// These are returned by the `try_*` constructors on [`ConnectorTag`],
/// [`ItemKey`], and [`ObjectVersionId`]. The panicking constructors
/// (`from_ascii`, `new`, `from_version_bytes`) remain available for
/// trusted internal code; only [`ConnectorTag::from_ascii`] is `const`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityInputError {
    /// Connector tag is empty.
    EmptyTag,
    /// Connector tag exceeds 8 bytes.
    TagTooLong(usize),
    /// Connector tag contains a non-ASCII-graphic byte at the given index.
    NonGraphicByte {
        /// Byte index within the tag.
        index: usize,
        /// The invalid byte value.
        byte: u8,
    },
    /// Item path is empty.
    EmptyPath,
    /// Version bytes are empty.
    EmptyVersionBytes,
}

impl fmt::Display for IdentityInputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyTag => write!(f, "ConnectorTag must not be empty"),
            Self::TagTooLong(len) => {
                write!(f, "ConnectorTag must be at most 8 bytes, got {len}")
            }
            Self::NonGraphicByte { index, byte } => {
                write!(
                    f,
                    "ConnectorTag byte at index {index} is not ASCII graphic: 0x{byte:02X}"
                )
            }
            Self::EmptyPath => write!(f, "ItemKey path must not be empty"),
            Self::EmptyVersionBytes => write!(f, "version bytes must not be empty"),
        }
    }
}

impl std::error::Error for IdentityInputError {}

// ---------------------------------------------------------------------------
// ConnectorTag — source discriminator
// ---------------------------------------------------------------------------

/// Fixed-width tag identifying the connector (source system) that produced
/// an [`ItemKey`].
///
/// Prevents cross-source collisions: a GitHub file at `org/repo/path.txt`
/// and a GitLab file at `org/repo/path.txt` hash to different
/// [`StableItemId`] values because their `ConnectorTag` differs.
///
/// # Conventions
///
/// Tags SHOULD be short ASCII identifiers, null-padded on the right:
///
/// ```text
/// b"github\0\0"     — GitHub connector
/// b"gitlab\0\0"     — GitLab connector
/// b"s3\0\0\0\0\0\0" — S3 connector
/// b"azblob\0\0"     — Azure Blob connector
/// ```
///
/// The contracts crate does NOT enumerate valid tags. Connectors are
/// responsible for choosing a stable, unique tag. Tags are compared
/// byte-for-byte — `b"github\0\0"` and `b"GITHUB\0\0"` are different.
///
/// # Invariants
///
/// **Safety (uniqueness)**: Two distinct connectors MUST use distinct tags.
/// This is enforced by convention and integration tests, not by the type.
///
/// **Safety (stability)**: A connector MUST NOT change its tag across
/// versions. Changing the tag changes all derived [`StableItemId`] values,
/// invalidating all finding records for items from that connector.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConnectorTag([u8; 8]);

impl fmt::Debug for ConnectorTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Three branches:
        // 1. Properly null-padded + all-ASCII-graphic prefix → quoted ASCII
        // 2. No NUL (all 8 bytes filled) + all-ASCII-graphic → quoted ASCII
        // 3. Everything else → hex
        let first_nul = self.0.iter().position(|&b| b == 0);
        let (prefix, tail_clean) = match first_nul {
            Some(pos) => (&self.0[..pos], self.0[pos..].iter().all(|&b| b == 0)),
            None => (&self.0[..], true),
        };

        if tail_clean && !prefix.is_empty() && prefix.iter().all(|b| b.is_ascii_graphic()) {
            let s = core::str::from_utf8(prefix).unwrap_or("???");
            write!(f, "ConnectorTag({s:?})")
        } else {
            write!(
                f,
                "ConnectorTag({:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x})",
                self.0[0],
                self.0[1],
                self.0[2],
                self.0[3],
                self.0[4],
                self.0[5],
                self.0[6],
                self.0[7],
            )
        }
    }
}

impl ConnectorTag {
    /// Create a tag from a byte string. Pads with zeros if shorter than 8.
    ///
    /// This is `const`, so connector tags can be defined as module-level
    /// constants with zero runtime cost.
    ///
    /// # Examples
    ///
    /// ```
    /// use gossip_contracts::identity::ConnectorTag;
    ///
    /// const GITHUB: ConnectorTag = ConnectorTag::from_ascii(b"github");
    /// assert_eq!(GITHUB.as_bytes(), b"github\0\0");
    ///
    /// const S3: ConnectorTag = ConnectorTag::from_ascii(b"s3");
    /// assert_eq!(S3.as_bytes(), b"s3\0\0\0\0\0\0");
    /// ```
    ///
    /// # Panics
    ///
    /// Panics if `tag` is longer than 8 bytes, empty, or contains
    /// non-ASCII-graphic bytes (anything outside `!`..`~`, i.e. 0x21..=0x7E).
    pub const fn from_ascii(tag: &[u8]) -> Self {
        assert!(!tag.is_empty(), "ConnectorTag must not be empty");
        assert!(tag.len() <= 8, "ConnectorTag must be at most 8 bytes");

        let mut buf = [0u8; 8];
        let mut i = 0;
        while i < tag.len() {
            // const-compatible equivalent of `tag[i].is_ascii_graphic()`.
            assert!(
                tag[i] >= 0x21 && tag[i] <= 0x7E,
                "ConnectorTag bytes must be ASCII graphic (0x21..=0x7E)"
            );
            buf[i] = tag[i];
            i += 1;
        }
        Self(buf)
    }

    /// Fallible version of [`from_ascii`](Self::from_ascii).
    ///
    /// Returns an error instead of panicking when the input is invalid.
    /// Use this at system boundaries where the tag comes from external input.
    pub fn try_from_ascii(tag: &[u8]) -> Result<Self, IdentityInputError> {
        if tag.is_empty() {
            return Err(IdentityInputError::EmptyTag);
        }
        if tag.len() > 8 {
            return Err(IdentityInputError::TagTooLong(tag.len()));
        }
        let mut buf = [0u8; 8];
        for (i, &b) in tag.iter().enumerate() {
            if !(0x21..=0x7E).contains(&b) {
                return Err(IdentityInputError::NonGraphicByte { index: i, byte: b });
            }
            buf[i] = b;
        }
        Ok(Self(buf))
    }

    /// Create a tag from a raw 8-byte array **without validation**.
    ///
    /// Unlike [`from_ascii`](Self::from_ascii), this constructor does not
    /// enforce ASCII-graphic content, null-padding, or non-emptiness.
    /// Prefer `from_ascii` for standard connectors; `from_bytes` exists as
    /// an escape hatch for deserialization and foreign-format tags that may
    /// not satisfy the ASCII-graphic invariant.
    #[inline]
    pub const fn from_bytes(bytes: [u8; 8]) -> Self {
        Self(bytes)
    }

    /// Borrow the inner 8-byte array.
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; 8] {
        &self.0
    }
}

impl CanonicalBytes for ConnectorTag {
    #[inline]
    fn write_canonical(&self, h: &mut Hasher) {
        // Fixed-width: no length prefix.
        h.update(&self.0);
    }
}

// ---------------------------------------------------------------------------
// ItemKey — variable-length scannable-item identity
// ---------------------------------------------------------------------------

/// Logical identity of a scannable item: a file, page, object, etc.
///
/// `ItemKey` is the full, human-meaningful identity. It carries enough
/// information to uniquely locate an item across all connectors. The
/// fixed-width [`StableItemId`] is derived from it for use in finding
/// derivation.
///
/// # Structure
///
/// ```text
/// ┌──────────────┬───────────────────────────────────┐
/// │ ConnectorTag  │ path (connector-defined bytes)     │
/// │   [u8; 8]     │ Box<[u8]>                          │
/// └──────────────┴───────────────────────────────────┘
/// ```
///
/// The `path` field is opaque to the contracts crate. Connectors define
/// its encoding:
///
/// - GitHub: `"{owner}/{repo}\0{file_path}"` (UTF-8, null-separated)
/// - S3: `"{bucket}\0{object_key}"` (UTF-8, null-separated)
/// - Generic: any deterministic byte sequence
///
/// # Invariants
///
/// **Safety (determinism)**: The same logical item MUST always produce
/// the same `ItemKey` bytes. Connectors MUST normalize before construction
/// (e.g., path canonicalization, case folding if the source is
/// case-insensitive).
///
/// **Safety (collision-freedom)**: Two distinct items from the same
/// connector MUST produce distinct `path` bytes. Two items from different
/// connectors are automatically distinct due to `ConnectorTag`.
///
/// # `CanonicalBytes` encoding
///
/// `ConnectorTag` (8 bytes, fixed) + `path` (length-prefixed).
/// The length prefix is a `u32` LE (max path length: ~4 GiB, far more
/// than needed).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ItemKey {
    connector: ConnectorTag,
    path: Box<[u8]>,
}

impl ItemKey {
    /// Construct an `ItemKey` from a connector tag and path bytes.
    ///
    /// The `path` encoding is connector-defined. A common convention is
    /// null-separated segments (`b"org/repo\0src/main.rs"`), but any
    /// deterministic byte sequence works.
    ///
    /// # Examples
    ///
    /// ```
    /// use gossip_contracts::identity::{ConnectorTag, ItemKey};
    ///
    /// let github = ConnectorTag::from_ascii(b"github");
    /// let key = ItemKey::new(github, b"org/repo\0src/main.rs");
    ///
    /// assert_eq!(key.connector(), github);
    /// assert_eq!(key.path(), b"org/repo\0src/main.rs");
    /// ```
    ///
    /// # Panics
    ///
    /// Panics if `path` is empty.  An empty path is a programming error in
    /// the connector — every scannable item has a non-empty location.  This
    /// is not a user-input validation boundary; connectors are trusted
    /// internal code, so a panic (rather than `Result`) is appropriate.
    pub fn new(connector: ConnectorTag, path: impl AsRef<[u8]>) -> Self {
        let path = path.as_ref();
        assert!(!path.is_empty(), "ItemKey path must not be empty");
        Self {
            connector,
            path: path.into(),
        }
    }

    /// Fallible version of [`new`](Self::new).
    ///
    /// Returns an error instead of panicking when the path is empty.
    /// Use this at system boundaries where the path comes from external input.
    pub fn try_new(
        connector: ConnectorTag,
        path: impl AsRef<[u8]>,
    ) -> Result<Self, IdentityInputError> {
        let path = path.as_ref();
        if path.is_empty() {
            return Err(IdentityInputError::EmptyPath);
        }
        Ok(Self {
            connector,
            path: path.into(),
        })
    }

    /// The connector tag for this item.
    #[inline]
    pub fn connector(&self) -> ConnectorTag {
        self.connector
    }

    /// The opaque path bytes for this item.
    #[inline]
    pub fn path(&self) -> &[u8] {
        &self.path
    }

    /// Borrow this key as an allocation-free [`ItemKeyRef`] view.
    #[inline]
    pub fn as_ref(&self) -> ItemKeyRef<'_> {
        ItemKeyRef::new(self.connector, &self.path)
    }

    /// Allocate a new owned key from a borrowed view.
    #[inline]
    pub fn from_ref(key: ItemKeyRef<'_>) -> Self {
        Self {
            connector: key.connector(),
            path: key.path().into(),
        }
    }

    /// Derive the fixed-width [`StableItemId`] for this key.
    ///
    /// This is a pure, infallible function: same `ItemKey` always produces
    /// the same `StableItemId`.
    pub fn stable_id(&self) -> StableItemId {
        self.as_ref().stable_id()
    }
}

impl CanonicalBytes for ItemKey {
    #[inline]
    fn write_canonical(&self, h: &mut Hasher) {
        self.as_ref().write_canonical(h);
    }
}

impl<'a> From<&'a ItemKey> for ItemKeyRef<'a> {
    #[inline]
    fn from(value: &'a ItemKey) -> Self {
        value.as_ref()
    }
}

impl<'a> From<ItemKeyRef<'a>> for ItemKey {
    #[inline]
    fn from(value: ItemKeyRef<'a>) -> Self {
        value.to_owned()
    }
}

impl<'a> PartialEq<ItemKeyRef<'a>> for ItemKey {
    #[inline]
    fn eq(&self, other: &ItemKeyRef<'a>) -> bool {
        self.connector == other.connector() && self.path() == other.path()
    }
}

impl<'a> PartialEq<ItemKey> for ItemKeyRef<'a> {
    #[inline]
    fn eq(&self, other: &ItemKey) -> bool {
        other == self
    }
}

// ---------------------------------------------------------------------------
// ItemKeyRef — borrowed item-key view for allocation-free hot paths
// ---------------------------------------------------------------------------

/// Borrowed item identity view.
///
/// `ItemKeyRef` is the allocation-free companion to [`ItemKey`]. It borrows
/// path bytes from caller-owned storage (or from an existing [`ItemKey`]) and
/// can derive [`StableItemId`] without materializing owned path memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ItemKeyRef<'a> {
    connector: ConnectorTag,
    path: &'a [u8],
}

impl<'a> ItemKeyRef<'a> {
    /// Construct a borrowed key view from connector and path bytes.
    ///
    /// # Panics
    ///
    /// Panics if `path` is empty.
    #[inline]
    pub fn new(connector: ConnectorTag, path: &'a [u8]) -> Self {
        assert!(!path.is_empty(), "ItemKey path must not be empty");
        Self { connector, path }
    }

    /// Fallible constructor for borrowed key views.
    #[inline]
    pub fn try_new(connector: ConnectorTag, path: &'a [u8]) -> Result<Self, IdentityInputError> {
        if path.is_empty() {
            return Err(IdentityInputError::EmptyPath);
        }
        Ok(Self { connector, path })
    }

    /// Borrow from an owned [`ItemKey`].
    #[inline]
    pub fn from_item_key(key: &'a ItemKey) -> Self {
        key.as_ref()
    }

    /// The connector tag for this item.
    #[inline]
    pub fn connector(self) -> ConnectorTag {
        self.connector
    }

    /// The opaque connector-defined path bytes.
    #[inline]
    pub fn path(self) -> &'a [u8] {
        self.path
    }

    /// Convert into an owned [`ItemKey`], allocating path storage once.
    #[inline]
    pub fn to_owned(self) -> ItemKey {
        ItemKey::from_ref(self)
    }

    /// Derive the fixed-width [`StableItemId`] from this borrowed key.
    pub fn stable_id(self) -> StableItemId {
        let mut h = ITEM_ID_HASHER.clone();
        self.write_canonical(&mut h);
        StableItemId::from_bytes(finalize_32(&h))
    }
}

impl CanonicalBytes for ItemKeyRef<'_> {
    #[inline]
    fn write_canonical(&self, h: &mut Hasher) {
        self.connector.write_canonical(h);
        // Path is variable-length → length-prefixed.
        self.path.write_canonical(h);
    }
}

// ---------------------------------------------------------------------------
// ItemKeyScratch — fixed-capacity scratch for runtime path reuse
// ---------------------------------------------------------------------------

/// Errors from [`ItemKeyScratch`] path staging.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ItemKeyScratchError {
    /// Provided path was empty.
    EmptyPath,
    /// Provided path exceeded this scratch's fixed capacity.
    PathTooLong {
        /// Input path length.
        len: usize,
        /// Scratch capacity.
        capacity: usize,
    },
}

impl fmt::Display for ItemKeyScratchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPath => write!(f, "ItemKey path must not be empty"),
            Self::PathTooLong { len, capacity } => {
                write!(
                    f,
                    "ItemKey path length {len} exceeds scratch capacity {capacity}"
                )
            }
        }
    }
}

impl std::error::Error for ItemKeyScratchError {}

/// Reusable fixed-capacity scratch buffer for runtime item paths.
///
/// This is intended for hot loops where paths are generated repeatedly and a
/// borrowed key view is sufficient. `ItemKeyScratch` stores path bytes in a
/// caller-owned array and returns an [`ItemKeyRef`] borrowing that array.
///
/// Any subsequent write invalidates previously returned `ItemKeyRef` values.
#[derive(Clone)]
pub struct ItemKeyScratch<const CAP: usize> {
    buf: [u8; CAP],
    len: usize,
}

impl<const CAP: usize> ItemKeyScratch<CAP> {
    /// Maximum number of path bytes this scratch can hold.
    pub const CAPACITY: usize = CAP;

    /// Create an empty scratch buffer.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            buf: [0u8; CAP],
            len: 0,
        }
    }

    /// Active path bytes currently staged in this scratch.
    #[inline]
    pub fn path(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// Number of active path bytes.
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` when no path is currently staged.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Clear the staged path without touching backing storage.
    #[inline]
    pub fn clear(&mut self) {
        self.len = 0;
    }

    /// Copy path bytes into this scratch and return a borrowed key view.
    ///
    /// The returned [`ItemKeyRef`] borrows this scratch and stays valid until
    /// the next mutation of the same scratch value.
    pub fn from_path<'a>(
        &'a mut self,
        connector: ConnectorTag,
        path: &[u8],
    ) -> Result<ItemKeyRef<'a>, ItemKeyScratchError> {
        if path.is_empty() {
            return Err(ItemKeyScratchError::EmptyPath);
        }
        if path.len() > CAP {
            return Err(ItemKeyScratchError::PathTooLong {
                len: path.len(),
                capacity: CAP,
            });
        }
        self.buf[..path.len()].copy_from_slice(path);
        self.len = path.len();
        Ok(ItemKeyRef::new(connector, self.path()))
    }

    /// View the currently staged path as an [`ItemKeyRef`].
    ///
    /// Returns [`IdentityInputError::EmptyPath`] if scratch is empty.
    pub fn try_view(&self, connector: ConnectorTag) -> Result<ItemKeyRef<'_>, IdentityInputError> {
        ItemKeyRef::try_new(connector, self.path())
    }
}

impl<const CAP: usize> Default for ItemKeyScratch<CAP> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const CAP: usize> fmt::Debug for ItemKeyScratch<CAP> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ItemKeyScratch")
            .field("capacity", &CAP)
            .field("len", &self.len)
            .field("path", &self.path())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// StableItemId — fixed-width item identity for derivation
// ---------------------------------------------------------------------------

crate::define_id_32! {
    /// Content-addressed identity of a scannable item.
    ///
    /// Derived as `blake3("gossip/item-id/v1", canonical_bytes(item_key))`.
    ///
    /// This is the identifier that enters `FindingId` derivation. It is
    /// **tenant-independent**: the same file has the same `StableItemId`
    /// regardless of which tenant is scanning it. Tenant scoping is
    /// applied at `FindingId` derivation.
    ///
    /// # Invariants
    ///
    /// **Safety**: `StableItemId` MUST be a pure function of `ItemKey`.
    /// Given the same `ItemKey`, the output is always the same.
    ///
    /// **Safety**: Distinct `ItemKey` values MUST produce distinct
    /// `StableItemId` values (with cryptographic collision resistance).
    StableItemId
}

// ---------------------------------------------------------------------------
// ObjectVersionId — version-specific content identity
// ---------------------------------------------------------------------------

crate::define_id_32! {
    /// Identity of a specific version of a scannable item's content.
    ///
    /// Examples of what connectors normalize into this:
    ///
    /// - Git: `blake3(commit_sha ++ tree_sha_for_path)` — pinpoints the
    ///   exact content of a file at a specific commit.
    /// - S3: `blake3(etag_bytes)` or `blake3(version_id_bytes)`.
    /// - Content-hash: `blake3(raw_content)` for sources without native
    ///   versioning.
    ///
    /// Connectors MUST produce this via a deterministic function of the
    /// version token. The contracts crate provides a helper for the common
    /// case.
    ///
    /// # Invariants
    ///
    /// **Safety**: The same version of the same content MUST always produce
    /// the same `ObjectVersionId`.
    ///
    /// **Safety**: Different versions of the same item SHOULD produce
    /// different `ObjectVersionId` values. (If a version token doesn't
    /// change when content changes — e.g., a mutable S3 object without
    /// versioning — the connector should fall back to content hashing.)
    ///
    /// # Role in finding model
    ///
    /// `ObjectVersionId` enters `OccurrenceId` derivation but NOT
    /// `FindingId`. This means a finding is stable across versions:
    /// "rule R found secret S in item I" is the same finding regardless
    /// of which version it was first detected in.
    ObjectVersionId
}

impl ObjectVersionId {
    /// Derive an `ObjectVersionId` from arbitrary version token bytes.
    ///
    /// This is a convenience for connectors that have a variable-length
    /// version identifier (e.g., a Git commit SHA as a hex string, an
    /// S3 ETag). It normalizes to 32 bytes via BLAKE3.
    ///
    /// Connectors with richer version semantics (e.g., needing to combine
    /// commit SHA + tree SHA) should build a [`domain_hasher`](super::domain_hasher)
    /// manually and feed structured fields via [`CanonicalBytes`].
    ///
    /// # Examples
    ///
    /// ```
    /// use gossip_contracts::identity::ObjectVersionId;
    ///
    /// // Git connector: version from commit SHA hex.
    /// let v1 = ObjectVersionId::from_version_bytes(b"abc123def456");
    ///
    /// // S3 connector: version from ETag.
    /// let v2 = ObjectVersionId::from_version_bytes(b"\"d41d8cd98f00b204e9800998ecf8427e\"");
    ///
    /// assert_ne!(v1, v2);
    /// ```
    ///
    /// # Panics
    ///
    /// Panics if `version_bytes` is empty.  An empty version token is a
    /// programming error in the connector — every versioned object has a
    /// non-empty version identifier.  Connectors are trusted internal code,
    /// so a panic (rather than `Result`) is appropriate.
    pub fn from_version_bytes(version_bytes: &[u8]) -> Self {
        assert!(!version_bytes.is_empty(), "version bytes must not be empty");
        let mut h = OBJECT_VERSION_HASHER.clone();
        version_bytes.write_canonical(&mut h);
        Self::from_bytes(finalize_32(&h))
    }

    /// Fallible version of [`from_version_bytes`](Self::from_version_bytes).
    ///
    /// Returns an error instead of panicking when `version_bytes` is empty.
    /// Use this at system boundaries where the version token comes from
    /// external input.
    pub fn try_from_version_bytes(version_bytes: &[u8]) -> Result<Self, IdentityInputError> {
        if version_bytes.is_empty() {
            return Err(IdentityInputError::EmptyVersionBytes);
        }
        let mut h = OBJECT_VERSION_HASHER.clone();
        version_bytes.write_canonical(&mut h);
        Ok(Self::from_bytes(finalize_32(&h)))
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::hash::{Hash, Hasher as StdHasher};

    // -- ConnectorTag --

    #[test]
    #[should_panic(expected = "must not be empty")]
    fn connector_tag_empty_panics() {
        ConnectorTag::from_ascii(b"");
    }

    #[test]
    #[should_panic(expected = "at most 8 bytes")]
    fn connector_tag_too_long_panics() {
        ConnectorTag::from_ascii(b"toolongname");
    }

    #[test]
    fn connector_tag_debug_ascii() {
        let tag = ConnectorTag::from_ascii(b"github");
        let dbg = format!("{tag:?}");
        assert!(dbg.contains("github"), "got: {dbg}");
    }

    #[test]
    fn connector_tag_debug_binary() {
        let tag = ConnectorTag::from_bytes([0xFF; 8]);
        let dbg = format!("{tag:?}");
        // Non-ASCII → hex output.
        assert!(dbg.contains("ffffffff"), "got: {dbg}");
    }

    #[test]
    fn connector_tag_debug_nonzero_after_nul() {
        // Tag with non-zero byte after first NUL must print as hex, not ASCII.
        let tag = ConnectorTag::from_bytes(*b"github\0\x42");
        let dbg = format!("{tag:?}");
        assert!(
            !dbg.contains("\"github\""),
            "non-zero trailing byte must not be hidden: {dbg}"
        );
        assert!(dbg.starts_with("ConnectorTag("), "got: {dbg}");
        // Should be hex output.
        assert!(dbg.contains("676974687562"), "got: {dbg}");
    }

    #[test]
    fn connector_tag_debug_full_ascii_no_nul() {
        // All 8 bytes are ASCII graphic, no NUL → prints as ASCII.
        let tag = ConnectorTag::from_bytes(*b"githubXY");
        let dbg = format!("{tag:?}");
        assert!(dbg.contains("githubXY"), "got: {dbg}");
    }

    // -- ItemKey --

    #[test]
    #[should_panic(expected = "must not be empty")]
    fn item_key_empty_path_panics() {
        ItemKey::new(ConnectorTag::from_ascii(b"github"), vec![]);
    }

    #[test]
    #[should_panic(expected = "must not be empty")]
    fn item_key_ref_empty_path_panics() {
        let _ = ItemKeyRef::new(ConnectorTag::from_ascii(b"github"), b"");
    }

    #[test]
    fn item_key_ref_try_new_rejects_empty_path() {
        let err = ItemKeyRef::try_new(ConnectorTag::from_ascii(b"github"), b"")
            .expect_err("empty path should fail");
        assert_eq!(err, IdentityInputError::EmptyPath);
    }

    #[test]
    fn item_key_ref_matches_owned_semantics() {
        let connector = ConnectorTag::from_ascii(b"github");
        let owned = ItemKey::new(connector, b"org/repo\0src/main.rs");
        let borrowed = owned.as_ref();

        assert_eq!(borrowed.connector(), connector);
        assert_eq!(borrowed.path(), owned.path());
        assert_eq!(borrowed.stable_id(), owned.stable_id());
        assert_eq!(borrowed.to_owned(), owned);
        assert_eq!(borrowed, owned);
        assert_eq!(owned, borrowed);
    }

    #[test]
    fn item_key_ref_hash_matches_owned() {
        let connector = ConnectorTag::from_ascii(b"github");
        let owned = ItemKey::new(connector, b"org/repo\0src/main.rs");
        let borrowed = owned.as_ref();

        let mut owned_hasher = std::collections::hash_map::DefaultHasher::new();
        let mut borrowed_hasher = std::collections::hash_map::DefaultHasher::new();
        owned.hash(&mut owned_hasher);
        borrowed.hash(&mut borrowed_hasher);
        assert_eq!(owned_hasher.finish(), borrowed_hasher.finish());
    }

    #[test]
    fn item_key_canonical_bytes_match_borrowed_view() {
        let connector = ConnectorTag::from_ascii(b"github");
        let owned = ItemKey::new(connector, b"org/repo\0src/main.rs");
        let borrowed = owned.as_ref();
        let mut owned_hasher = Hasher::new();
        let mut borrowed_hasher = Hasher::new();
        owned.write_canonical(&mut owned_hasher);
        borrowed.write_canonical(&mut borrowed_hasher);
        assert_eq!(owned_hasher.finalize(), borrowed_hasher.finalize());
    }

    #[test]
    fn item_key_scratch_from_path_builds_borrowed_view() {
        let connector = ConnectorTag::from_ascii(b"github");
        let mut scratch = ItemKeyScratch::<64>::new();
        let key = scratch
            .from_path(connector, b"org/repo\0src/main.rs")
            .expect("path should fit scratch");
        let owned = ItemKey::new(connector, b"org/repo\0src/main.rs");
        assert_eq!(key.path(), b"org/repo\0src/main.rs");
        assert_eq!(key.stable_id(), owned.stable_id());
    }

    #[test]
    fn item_key_scratch_try_view_uses_staged_path() {
        let connector = ConnectorTag::from_ascii(b"github");
        let mut scratch = ItemKeyScratch::<16>::new();
        scratch
            .from_path(connector, b"abc")
            .expect("staging path should succeed");
        let view = scratch
            .try_view(connector)
            .expect("existing path should produce a view");
        assert_eq!(view.path(), b"abc");
    }

    #[test]
    fn item_key_scratch_rejects_empty_path() {
        let connector = ConnectorTag::from_ascii(b"github");
        let mut scratch = ItemKeyScratch::<16>::new();
        let err = scratch
            .from_path(connector, b"")
            .expect_err("empty path should be rejected");
        assert_eq!(err, ItemKeyScratchError::EmptyPath);
    }

    #[test]
    fn item_key_scratch_rejects_oversized_path() {
        let connector = ConnectorTag::from_ascii(b"github");
        let mut scratch = ItemKeyScratch::<4>::new();
        let err = scratch
            .from_path(connector, b"12345")
            .expect_err("oversized path should fail");
        assert_eq!(
            err,
            ItemKeyScratchError::PathTooLong {
                len: 5,
                capacity: 4
            }
        );
    }

    #[test]
    fn item_key_scratch_try_view_rejects_empty_state() {
        let scratch = ItemKeyScratch::<8>::new();
        let err = scratch
            .try_view(ConnectorTag::from_ascii(b"github"))
            .expect_err("empty scratch should not produce a key");
        assert_eq!(err, IdentityInputError::EmptyPath);
    }

    #[test]
    fn item_key_scratch_can_be_reused_across_iterations() {
        let connector = ConnectorTag::from_ascii(b"github");
        let mut scratch = ItemKeyScratch::<32>::new();

        for path in [
            b"first/path".as_slice(),
            b"second/path".as_slice(),
            b"third/path".as_slice(),
        ] {
            let key = scratch
                .from_path(connector, path)
                .expect("path should fit scratch");
            let owned = ItemKey::new(connector, path);
            assert_eq!(key.stable_id(), owned.stable_id());
        }
    }

    // -- ItemKey CanonicalBytes --

    #[test]
    fn item_key_canonical_bytes_unambiguous() {
        // Connector tag + path must not collide with different splits.
        // ConnectorTag is fixed-width and path is length-prefixed,
        // so this is structurally impossible. Verify anyway:
        let a = ItemKey::new(ConnectorTag::from_bytes(*b"ab\0\0\0\0\0\0"), b"cd");
        let b = ItemKey::new(ConnectorTag::from_bytes(*b"abcd\0\0\0\0"), b"ef");
        let mut ha = Hasher::new();
        let mut hb = Hasher::new();
        a.write_canonical(&mut ha);
        b.write_canonical(&mut hb);
        assert_ne!(ha.finalize(), hb.finalize());
    }

    // -- ObjectVersionId --

    #[test]
    #[should_panic(expected = "must not be empty")]
    fn object_version_id_empty_panics() {
        ObjectVersionId::from_version_bytes(b"");
    }

    #[test]
    fn object_version_id_debug_is_safe() {
        let v = ObjectVersionId::from_version_bytes(b"commit-sha");
        let dbg = format!("{v:?}");
        assert!(dbg.starts_with("ObjectVersionId("));
        assert!(dbg.len() < 80);
    }

    // -- StableItemId --

    #[test]
    fn stable_item_id_debug_is_safe() {
        let id = StableItemId::from_bytes([0xCA; 32]);
        let dbg = format!("{id:?}");
        assert!(dbg.starts_with("StableItemId("));
        assert!(dbg.contains("cacacaca"));
        assert!(dbg.len() < 80);
    }

    // -- Property-based --

    proptest::proptest! {
        #![proptest_config(crate::test_util::miri_proptest_config())]

        #[test]
        fn item_key_stable_id_is_pure(
            tag_bytes in proptest::array::uniform8(proptest::num::u8::ANY),
            path in proptest::collection::vec(proptest::num::u8::ANY, 1..256),
        ) {
            let key = ItemKey::new(ConnectorTag::from_bytes(tag_bytes), path);
            let id1 = key.stable_id();
            let id2 = key.stable_id();
            proptest::prop_assert_eq!(id1, id2);
        }

        #[test]
        fn item_key_ref_stable_id_matches_owned(
            tag_bytes in proptest::array::uniform8(proptest::num::u8::ANY),
            path in proptest::collection::vec(proptest::num::u8::ANY, 1..256),
        ) {
            let connector = ConnectorTag::from_bytes(tag_bytes);
            let owned = ItemKey::new(connector, path.clone());
            let borrowed = ItemKeyRef::new(connector, &path);
            proptest::prop_assert_eq!(owned.stable_id(), borrowed.stable_id());
        }

        #[test]
        fn object_version_id_is_pure(
            bytes in proptest::collection::vec(proptest::num::u8::ANY, 1..256),
        ) {
            let v1 = ObjectVersionId::from_version_bytes(&bytes);
            let v2 = ObjectVersionId::from_version_bytes(&bytes);
            proptest::prop_assert_eq!(v1, v2);
        }

        #[test]
        fn item_key_canonical_bytes_stable(
            tag_bytes in proptest::array::uniform8(proptest::num::u8::ANY),
            path in proptest::collection::vec(proptest::num::u8::ANY, 1..128),
        ) {
            let key = ItemKey::new(ConnectorTag::from_bytes(tag_bytes), path);
            let mut h1 = Hasher::new();
            let mut h2 = Hasher::new();
            key.write_canonical(&mut h1);
            key.write_canonical(&mut h2);
            proptest::prop_assert_eq!(h1.finalize(), h2.finalize());
        }

        #[test]
        fn connector_tag_from_ascii_pads_correctly(
            raw in proptest::collection::vec(0x21u8..0x7Fu8, 1..=8),
        ) {
            let tag = ConnectorTag::from_ascii(&raw);
            let mut expected = [0u8; 8];
            expected[..raw.len()].copy_from_slice(&raw);
            proptest::prop_assert_eq!(*tag.as_bytes(), expected);
        }

        #[test]
        fn from_ascii_rejects_non_graphic(
            // Generate 1-8 bytes with at least one non-graphic byte.
            len in 1usize..=8,
            bad_pos in 0usize..8,
            bad_byte in proptest::prop_oneof![
                0u8..=0x20u8,   // NUL, control chars, space
                0x7Fu8..=0xFFu8 // DEL and high bytes
            ],
            fill_byte in 0x21u8..0x7Fu8,
        ) {
            let len = len.min(8);
            let bad_pos = bad_pos % len;
            let mut buf = vec![fill_byte; len];
            buf[bad_pos] = bad_byte;

            let result = std::panic::catch_unwind(|| ConnectorTag::from_ascii(&buf));
            proptest::prop_assert!(result.is_err(), "expected panic for input {buf:?}");
        }

        #[test]
        fn item_key_stable_id_collision_free(
            tag_a in proptest::array::uniform8(proptest::num::u8::ANY),
            tag_b in proptest::array::uniform8(proptest::num::u8::ANY),
            path_a in proptest::collection::vec(proptest::num::u8::ANY, 1..128),
            path_b in proptest::collection::vec(proptest::num::u8::ANY, 1..128),
        ) {
            proptest::prop_assume!(tag_a != tag_b || path_a != path_b);
            let a = ItemKey::new(ConnectorTag::from_bytes(tag_a), path_a);
            let b = ItemKey::new(ConnectorTag::from_bytes(tag_b), path_b);
            proptest::prop_assert_ne!(a.stable_id(), b.stable_id());
        }

        #[test]
        fn item_key_accessors_roundtrip(
            tag_bytes in proptest::array::uniform8(proptest::num::u8::ANY),
            path in proptest::collection::vec(proptest::num::u8::ANY, 1..256),
        ) {
            let connector = ConnectorTag::from_bytes(tag_bytes);
            let key = ItemKey::new(connector, path.clone());
            proptest::prop_assert_eq!(key.connector(), connector);
            proptest::prop_assert_eq!(key.path(), path.as_slice());
        }

        #[test]
        fn object_version_id_collision_free(
            a in proptest::collection::vec(proptest::num::u8::ANY, 1..128),
            b in proptest::collection::vec(proptest::num::u8::ANY, 1..128),
        ) {
            proptest::prop_assume!(a != b);
            proptest::prop_assert_ne!(
                ObjectVersionId::from_version_bytes(&a),
                ObjectVersionId::from_version_bytes(&b),
            );
        }
    }
}

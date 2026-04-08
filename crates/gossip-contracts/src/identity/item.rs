//! Scan-object identity: the types that answer "what was scanned" and
//! "which version of it."
//!
//! # Type overview
//!
//! | Type | Width | Construction | Purpose |
//! |------|-------|-------------|---------|
//! | [`ConnectorTag`] | 8 B | `from_ascii` / `from_bytes` | Source-system discriminator |
//! | [`ConnectorInstanceIdHash`] | 32 B | `from_instance_id_bytes` | Stable connector-instance scope |
//! | [`ItemIdentityKey`] | variable | `new(connector, connector_instance, locator)` | Human-meaningful item identity |
//! | [`StableItemId`] | 32 B | derived via `ItemIdentityKey::stable_id` | Fixed-width item identity for derivation |
//! | [`ObjectVersionId`] | 32 B | `from_version_bytes` | Version-specific content identity |
//!
//! # Derivation flow
//!
//! ```text
//! connector-instance bytes ──(blake3 derive-key)──► ConnectorInstanceIdHash
//!
//! ConnectorTag + ConnectorInstanceIdHash + locator ──► ItemIdentityKey ──(blake3 derive-key)──► StableItemId
//!                                                                         │
//!                                                               enters FindingId derivation
//!
//! version token bytes ──(blake3 derive-key)──► ObjectVersionId
//!                                                    │
//!                                          enters OccurrenceId derivation
//! ```
//!
//! `StableItemId` and `ObjectVersionId` are independent derivations with
//! distinct BLAKE3 domain separators (see [`domain`](crate::identity::domain)). Both are
//! consumed downstream by the finding module — `StableItemId` in
//! `FindingId` and `ObjectVersionId` in `OccurrenceId` — but neither
//! depends on the other.

use blake3::Hasher;
use core::fmt;

use super::canonical::CanonicalBytes;
use super::hashing::{
    CONNECTOR_INSTANCE_HASHER, ITEM_ID_HASHER, OBJECT_VERSION_HASHER, finalize_32,
};

// ---------------------------------------------------------------------------
// IdentityInputError — validation errors for identity constructors
// ---------------------------------------------------------------------------

/// Errors from identity type construction.
///
/// These are returned by the `try_*` constructors on [`ConnectorTag`],
/// [`ItemIdentityKey`], and [`ObjectVersionId`]. The panicking constructors
/// (`from_ascii`, `new`, `from_version_bytes`) remain available for
/// trusted internal code; only [`ConnectorTag::from_ascii`] is `const`.
///
/// All variants carry enough context to produce a useful error message
/// without re-inspecting the original input.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IdentityInputError {
    /// Connector tag is empty.
    #[error("ConnectorTag must not be empty")]
    EmptyTag,
    /// Connector tag exceeds 8 bytes.
    #[error("ConnectorTag must be at most 8 bytes, got {0}")]
    TagTooLong(usize),
    /// Connector tag contains a non-ASCII-graphic byte at the given index.
    #[error("ConnectorTag byte at index {index} is not ASCII graphic: 0x{byte:02X}")]
    NonGraphicByte {
        /// Byte index within the tag.
        index: usize,
        /// The invalid byte value.
        byte: u8,
    },
    /// Connector instance ID bytes are empty.
    #[error("connector instance ID bytes must not be empty")]
    EmptyConnectorInstanceId,
    /// Item locator is empty.
    #[error("ItemIdentityKey locator must not be empty")]
    EmptyLocator,
    /// Version bytes are empty.
    #[error("version bytes must not be empty")]
    EmptyVersionBytes,
}

// ---------------------------------------------------------------------------
// ConnectorTag — source discriminator
// ---------------------------------------------------------------------------

/// Fixed-width tag identifying the connector (source system) that produced
/// an [`ItemIdentityKey`].
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
    ///
    /// # Errors
    ///
    /// - [`IdentityInputError::EmptyTag`] if `tag` is empty.
    /// - [`IdentityInputError::TagTooLong`] if `tag` exceeds 8 bytes.
    /// - [`IdentityInputError::NonGraphicByte`] if any byte is outside
    ///   the ASCII graphic range (`0x21..=0x7E`).
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

    /// Borrow the inner 8-byte array, including any null padding.
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; 8] {
        &self.0
    }
}

impl CanonicalBytes for ConnectorTag {
    /// Writes the full 8-byte array (including null padding) with no length
    /// prefix. Fixed-width encoding ensures unambiguous framing when
    /// concatenated with subsequent fields in composite types like [`ItemIdentityKey`].
    #[inline]
    fn write_canonical(&self, h: &mut Hasher) {
        h.update(&self.0);
    }
}

// ---------------------------------------------------------------------------
// ConnectorInstanceIdHash — fixed-width connector-instance scope
// ---------------------------------------------------------------------------

crate::define_id_32! {
    /// Stable hash of a connector instance identifier.
    ///
    /// Connector instance IDs often arrive as variable-length strings or byte
    /// sequences from coordination/runtime code. Hashing them once into a
    /// fixed-width value keeps [`ItemIdentityKey`] framing simple and prevents
    /// identity collisions when two instances scan the same locator under the
    /// same connector tag.
    ConnectorInstanceIdHash
}

impl ConnectorInstanceIdHash {
    /// Derive a connector-instance hash from arbitrary instance ID bytes.
    ///
    /// # Panics
    ///
    /// Panics if `instance_id` is empty.
    pub fn from_instance_id_bytes(instance_id: &[u8]) -> Self {
        assert!(
            !instance_id.is_empty(),
            "connector instance ID bytes must not be empty"
        );
        let mut hasher = CONNECTOR_INSTANCE_HASHER.clone();
        instance_id.write_canonical(&mut hasher);
        Self::from_bytes(finalize_32(&hasher))
    }

    /// Fallible version of [`from_instance_id_bytes`](Self::from_instance_id_bytes).
    ///
    /// # Errors
    ///
    /// Returns [`IdentityInputError::EmptyConnectorInstanceId`] if
    /// `instance_id` is empty.
    pub fn try_from_instance_id_bytes(instance_id: &[u8]) -> Result<Self, IdentityInputError> {
        if instance_id.is_empty() {
            return Err(IdentityInputError::EmptyConnectorInstanceId);
        }
        let mut hasher = CONNECTOR_INSTANCE_HASHER.clone();
        instance_id.write_canonical(&mut hasher);
        Ok(Self::from_bytes(finalize_32(&hasher)))
    }
}

// ---------------------------------------------------------------------------
// ItemIdentityKey — variable-length scannable-item identity
// ---------------------------------------------------------------------------

/// Logical identity of a scannable item: a file, page, object, etc.
///
/// `ItemIdentityKey` is the full, human-meaningful identity. It carries
/// enough information to uniquely locate an item across all connectors.
/// The fixed-width [`StableItemId`] is derived from it for use in finding
/// derivation.
///
/// # Structure
///
/// ```text
/// ┌──────────────┬──────────────────────────┬───────────────────────────────────┐
/// │ ConnectorTag │ ConnectorInstanceIdHash │ locator (connector-defined bytes) │
/// │   [u8; 8]    │        [u8; 32]         │ Box<[u8]>                         │
/// └──────────────┴──────────────────────────┴───────────────────────────────────┘
/// ```
///
/// The `locator` field is opaque to the contracts crate. Connectors define
/// its encoding:
///
/// - GitHub: `"{owner}/{repo}\0{file_path}"` (UTF-8, null-separated)
/// - S3: `"{bucket}\0{object_key}"` (UTF-8, null-separated)
/// - Jira: `"{project}\0{issue_key}"` (UTF-8, null-separated)
/// - Generic: any deterministic byte sequence
///
/// # Invariants
///
/// **Safety (determinism)**: The same logical item MUST always produce
/// the same `ItemIdentityKey` bytes. Connectors MUST normalize before
/// construction (e.g., locator canonicalization, case folding if the
/// source is case-insensitive).
///
/// **Safety (collision-freedom)**: Two distinct items from the same
/// connector MUST produce distinct `locator` bytes. Two items from
/// different connectors are automatically distinct due to `ConnectorTag`.
///
/// # `CanonicalBytes` encoding
///
/// `ConnectorTag` (8 bytes, fixed) + `ConnectorInstanceIdHash` (32 bytes,
/// fixed) + `locator` (length-prefixed). The length prefix is a `u32` LE
/// (max locator length: ~4 GiB, far more than needed).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ItemIdentityKey {
    connector: ConnectorTag,
    connector_instance: ConnectorInstanceIdHash,
    locator: Box<[u8]>,
}

impl ItemIdentityKey {
    /// Construct an `ItemIdentityKey` from a connector tag, connector-instance
    /// hash, and locator bytes.
    ///
    /// The `locator` encoding is connector-defined. A common convention is
    /// null-separated segments (`b"org/repo\0src/main.rs"`), but any
    /// deterministic byte sequence works.
    ///
    /// # Examples
    ///
    /// ```
    /// use gossip_contracts::identity::{
    ///     ConnectorInstanceIdHash, ConnectorTag, ItemIdentityKey,
    /// };
    ///
    /// let github = ConnectorTag::from_ascii(b"github");
    /// let instance = ConnectorInstanceIdHash::from_instance_id_bytes(b"github-installation-1");
    /// let key = ItemIdentityKey::new(github, instance, b"org/repo\0src/main.rs");
    ///
    /// assert_eq!(key.connector(), github);
    /// assert_eq!(key.connector_instance(), instance);
    /// assert_eq!(key.locator(), b"org/repo\0src/main.rs");
    /// ```
    ///
    /// # Panics
    ///
    /// Panics if `locator` is empty.  An empty locator is a programming
    /// error in the connector — every scannable item has a non-empty
    /// location.  This is not a user-input validation boundary; connectors
    /// are trusted internal code, so a panic (rather than `Result`) is
    /// appropriate.
    pub fn new(
        connector: ConnectorTag,
        connector_instance: ConnectorInstanceIdHash,
        locator: impl AsRef<[u8]>,
    ) -> Self {
        let locator = locator.as_ref();
        assert!(
            !locator.is_empty(),
            "ItemIdentityKey locator must not be empty"
        );
        Self {
            connector,
            connector_instance,
            locator: locator.into(),
        }
    }

    /// Fallible version of [`new`](Self::new).
    ///
    /// Returns an error instead of panicking when the locator is empty.
    /// Use this at system boundaries where the locator comes from external
    /// input.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityInputError::EmptyLocator`] if the locator is empty.
    pub fn try_new(
        connector: ConnectorTag,
        connector_instance: ConnectorInstanceIdHash,
        locator: impl AsRef<[u8]>,
    ) -> Result<Self, IdentityInputError> {
        let locator = locator.as_ref();
        if locator.is_empty() {
            return Err(IdentityInputError::EmptyLocator);
        }
        Ok(Self {
            connector,
            connector_instance,
            locator: locator.into(),
        })
    }

    /// The connector tag for this item (e.g., `b"github\0\0"`).
    #[inline]
    pub fn connector(&self) -> ConnectorTag {
        self.connector
    }

    /// The connector-instance hash for this item.
    #[inline]
    pub fn connector_instance(&self) -> ConnectorInstanceIdHash {
        self.connector_instance
    }

    /// The opaque, connector-defined locator bytes for this item.
    ///
    /// The encoding is connector-specific; see [`ItemIdentityKey`] struct
    /// docs for examples. The returned slice never includes the connector
    /// tag.
    #[inline]
    pub fn locator(&self) -> &[u8] {
        &self.locator
    }

    /// Derive the fixed-width [`StableItemId`] for this key.
    ///
    /// Uses BLAKE3 derive-key mode with [`domain::ITEM_ID_V1`](super::domain::ITEM_ID_V1)
    /// via a cached hasher clone. This is a pure, infallible function: same
    /// `ItemIdentityKey` always produces the same `StableItemId`.
    pub fn stable_id(&self) -> StableItemId {
        let mut h = ITEM_ID_HASHER.clone();
        self.write_canonical(&mut h);
        StableItemId::from_bytes(finalize_32(&h))
    }
}

impl CanonicalBytes for ItemIdentityKey {
    /// Writes `ConnectorTag` (8 bytes, fixed-width) followed by
    /// `ConnectorInstanceIdHash` (32 bytes, fixed-width) followed by
    /// `locator` (4-byte LE length prefix + variable-length body). The
    /// length prefix on the locator prevents concatenation ambiguity.
    #[inline]
    fn write_canonical(&self, h: &mut Hasher) {
        self.connector.write_canonical(h);
        self.connector_instance.write_canonical(h);
        self.locator.write_canonical(h);
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
    /// **Safety**: `StableItemId` MUST be a pure function of `ItemIdentityKey`.
    /// Given the same `ItemIdentityKey`, the output is always the same.
    ///
    /// **Safety**: Distinct `ItemIdentityKey` values MUST produce distinct
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
    ///
    /// # Errors
    ///
    /// Returns [`IdentityInputError::EmptyVersionBytes`] if `version_bytes`
    /// is empty.
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

    // -- ItemIdentityKey --

    #[test]
    #[should_panic(expected = "must not be empty")]
    fn item_identity_key_empty_locator_panics() {
        ItemIdentityKey::new(
            ConnectorTag::from_ascii(b"github"),
            ConnectorInstanceIdHash::from_instance_id_bytes(b"github-installation-1"),
            vec![],
        );
    }

    // -- ItemIdentityKey CanonicalBytes --

    #[test]
    fn item_identity_key_canonical_bytes_unambiguous() {
        // ConnectorTag and ConnectorInstanceIdHash are fixed-width and locator
        // is length-prefixed, so this is structurally impossible. Verify
        // anyway:
        let a = ItemIdentityKey::new(
            ConnectorTag::from_bytes(*b"ab\0\0\0\0\0\0"),
            ConnectorInstanceIdHash::from_bytes([0x10; 32]),
            b"cd",
        );
        let b = ItemIdentityKey::new(
            ConnectorTag::from_bytes(*b"abcd\0\0\0\0"),
            ConnectorInstanceIdHash::from_bytes([0x20; 32]),
            b"ef",
        );
        let mut ha = Hasher::new();
        let mut hb = Hasher::new();
        a.write_canonical(&mut ha);
        b.write_canonical(&mut hb);
        assert_ne!(ha.finalize(), hb.finalize());
    }

    #[test]
    #[should_panic(expected = "must not be empty")]
    fn connector_instance_id_hash_empty_panics() {
        let _ = ConnectorInstanceIdHash::from_instance_id_bytes(b"");
    }

    #[test]
    fn connector_instance_id_hash_debug_is_safe() {
        let hash = ConnectorInstanceIdHash::from_bytes([0xA5; 32]);
        let dbg = format!("{hash:?}");
        assert!(dbg.starts_with("ConnectorInstanceIdHash("));
        assert!(dbg.contains("a5a5a5a5"));
        assert!(dbg.len() < 96);
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
        fn connector_instance_id_hash_is_pure(
            instance_bytes in proptest::collection::vec(proptest::num::u8::ANY, 1..256),
        ) {
            let a = ConnectorInstanceIdHash::from_instance_id_bytes(&instance_bytes);
            let b = ConnectorInstanceIdHash::from_instance_id_bytes(&instance_bytes);
            proptest::prop_assert_eq!(a, b);
        }

        #[test]
        fn connector_instance_id_hash_is_distinct(
            instance_a in proptest::collection::vec(proptest::num::u8::ANY, 1..128),
            instance_b in proptest::collection::vec(proptest::num::u8::ANY, 1..128),
        ) {
            proptest::prop_assume!(instance_a != instance_b);
            proptest::prop_assert_ne!(
                ConnectorInstanceIdHash::from_instance_id_bytes(&instance_a),
                ConnectorInstanceIdHash::from_instance_id_bytes(&instance_b),
            );
        }

        #[test]
        fn item_identity_key_stable_id_is_pure(
            tag_bytes in proptest::array::uniform8(proptest::num::u8::ANY),
            connector_instance in proptest::array::uniform32(proptest::num::u8::ANY),
            locator in proptest::collection::vec(proptest::num::u8::ANY, 1..256),
        ) {
            let key = ItemIdentityKey::new(
                ConnectorTag::from_bytes(tag_bytes),
                ConnectorInstanceIdHash::from_bytes(connector_instance),
                locator,
            );
            let id1 = key.stable_id();
            let id2 = key.stable_id();
            proptest::prop_assert_eq!(id1, id2);
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
        fn item_identity_key_canonical_bytes_stable(
            tag_bytes in proptest::array::uniform8(proptest::num::u8::ANY),
            connector_instance in proptest::array::uniform32(proptest::num::u8::ANY),
            locator in proptest::collection::vec(proptest::num::u8::ANY, 1..128),
        ) {
            let key = ItemIdentityKey::new(
                ConnectorTag::from_bytes(tag_bytes),
                ConnectorInstanceIdHash::from_bytes(connector_instance),
                locator,
            );
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
        fn item_identity_key_stable_id_collision_free(
            tag_a in proptest::array::uniform8(proptest::num::u8::ANY),
            tag_b in proptest::array::uniform8(proptest::num::u8::ANY),
            instance_a in proptest::array::uniform32(proptest::num::u8::ANY),
            instance_b in proptest::array::uniform32(proptest::num::u8::ANY),
            locator_a in proptest::collection::vec(proptest::num::u8::ANY, 1..128),
            locator_b in proptest::collection::vec(proptest::num::u8::ANY, 1..128),
        ) {
            proptest::prop_assume!(
                tag_a != tag_b
                    || instance_a != instance_b
                    || locator_a != locator_b
            );
            let a = ItemIdentityKey::new(
                ConnectorTag::from_bytes(tag_a),
                ConnectorInstanceIdHash::from_bytes(instance_a),
                locator_a,
            );
            let b = ItemIdentityKey::new(
                ConnectorTag::from_bytes(tag_b),
                ConnectorInstanceIdHash::from_bytes(instance_b),
                locator_b,
            );
            proptest::prop_assert_ne!(a.stable_id(), b.stable_id());
        }

        #[test]
        fn item_identity_key_accessors_roundtrip(
            tag_bytes in proptest::array::uniform8(proptest::num::u8::ANY),
            connector_instance in proptest::array::uniform32(proptest::num::u8::ANY),
            locator in proptest::collection::vec(proptest::num::u8::ANY, 1..256),
        ) {
            let connector = ConnectorTag::from_bytes(tag_bytes);
            let connector_instance = ConnectorInstanceIdHash::from_bytes(connector_instance);
            let key = ItemIdentityKey::new(connector, connector_instance, locator.clone());
            proptest::prop_assert_eq!(key.connector(), connector);
            proptest::prop_assert_eq!(key.connector_instance(), connector_instance);
            proptest::prop_assert_eq!(key.locator(), locator.as_slice());
        }

        #[test]
        fn different_instance_same_key_different_stable_id(
            tag_bytes in proptest::array::uniform8(proptest::num::u8::ANY),
            instance_a in proptest::array::uniform32(proptest::num::u8::ANY),
            instance_b in proptest::array::uniform32(proptest::num::u8::ANY),
            locator in proptest::collection::vec(proptest::num::u8::ANY, 1..256),
        ) {
            proptest::prop_assume!(instance_a != instance_b);
            let connector = ConnectorTag::from_bytes(tag_bytes);
            let a = ItemIdentityKey::new(
                connector,
                ConnectorInstanceIdHash::from_bytes(instance_a),
                locator.clone(),
            );
            let b = ItemIdentityKey::new(
                connector,
                ConnectorInstanceIdHash::from_bytes(instance_b),
                locator,
            );
            proptest::prop_assert_ne!(a.stable_id(), b.stable_id());
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

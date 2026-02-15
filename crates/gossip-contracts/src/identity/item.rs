//! Scan-object identity: the types that answer "what was scanned" and
//! "which version of it."
//!
//! # Type overview
//!
//! | Type | Width | Construction | Purpose |
//! |------|-------|-------------|---------|
//! | [`ConnectorTag`] | 8 B | `from_ascii` / `from_bytes` | Source-system discriminator |
//! | [`ItemKey`] | variable | `new(connector, path)` | Human-meaningful item identity |
//! | [`StableItemId`] | 32 B | derived via `ItemKey::stable_id` | Fixed-width item identity for derivation |
//! | [`ObjectVersionId`] | 32 B | `from_version_bytes` | Version-specific content identity |

use blake3::Hasher;
use core::fmt;

use super::canonical::CanonicalBytes;
use super::domain;
use super::hashing::{domain_hasher, finalize_32};

// ---------------------------------------------------------------------------
// § ConnectorTag — source discriminator
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
    /// non-ASCII-graphic bytes (anything outside `!`..`~`, i.e. 0x21..0x7E).
    pub const fn from_ascii(tag: &[u8]) -> Self {
        assert!(!tag.is_empty(), "ConnectorTag must not be empty");
        assert!(tag.len() <= 8, "ConnectorTag must be at most 8 bytes");

        let mut buf = [0u8; 8];
        let mut i = 0;
        while i < tag.len() {
            // const-compatible equivalent of `tag[i].is_ascii_graphic()`.
            assert!(
                tag[i] > 0x20 && tag[i] < 0x7F,
                "ConnectorTag bytes must be ASCII graphic (0x21..0x7E)"
            );
            buf[i] = tag[i];
            i += 1;
        }
        Self(buf)
    }

    /// Create a tag from a raw 8-byte array.
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
// § ItemKey — variable-length scannable-item identity
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
    /// let key = ItemKey::new(github, b"org/repo\0src/main.rs".to_vec());
    ///
    /// assert_eq!(key.connector(), github);
    /// assert_eq!(key.path(), b"org/repo\0src/main.rs");
    /// ```
    ///
    /// # Panics
    ///
    /// Panics if `path` is empty (an item must have a non-empty path).
    pub fn new(connector: ConnectorTag, path: Vec<u8>) -> Self {
        assert!(!path.is_empty(), "ItemKey path must not be empty");
        Self {
            connector,
            path: path.into_boxed_slice(),
        }
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

    /// Derive the fixed-width [`StableItemId`] for this key.
    ///
    /// This is a pure, infallible function: same `ItemKey` always produces
    /// the same `StableItemId`.
    pub fn stable_id(&self) -> StableItemId {
        let mut h = domain_hasher(domain::ITEM_ID_V1);
        self.write_canonical(&mut h);
        StableItemId::from_bytes(finalize_32(&h))
    }
}

impl CanonicalBytes for ItemKey {
    #[inline]
    fn write_canonical(&self, h: &mut Hasher) {
        self.connector.write_canonical(h);
        // Path is variable-length → length-prefixed.
        self.path.as_ref().write_canonical(h);
    }
}

// ---------------------------------------------------------------------------
// § StableItemId — fixed-width item identity for derivation
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
// § ObjectVersionId — version-specific content identity
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
    /// commit SHA + tree SHA) should build a [`domain_hasher`] manually and
    /// feed structured fields via [`CanonicalBytes`].
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
    /// Panics if `version_bytes` is empty.
    pub fn from_version_bytes(version_bytes: &[u8]) -> Self {
        assert!(!version_bytes.is_empty(), "version bytes must not be empty");
        let mut h = domain_hasher(domain::OBJECT_VERSION_V1);
        version_bytes.write_canonical(&mut h);
        Self::from_bytes(finalize_32(&h))
    }
}

// ============================================================================
// § Tests
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

    // -- ItemKey --

    #[test]
    #[should_panic(expected = "must not be empty")]
    fn item_key_empty_path_panics() {
        ItemKey::new(ConnectorTag::from_ascii(b"github"), vec![]);
    }

    // -- ItemKey CanonicalBytes --

    #[test]
    fn item_key_canonical_bytes_unambiguous() {
        // Connector tag + path must not collide with different splits.
        // ConnectorTag is fixed-width and path is length-prefixed,
        // so this is structurally impossible. Verify anyway:
        let a = ItemKey::new(ConnectorTag::from_bytes(*b"ab\0\0\0\0\0\0"), b"cd".to_vec());
        let b = ItemKey::new(ConnectorTag::from_bytes(*b"abcd\0\0\0\0"), b"ef".to_vec());
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

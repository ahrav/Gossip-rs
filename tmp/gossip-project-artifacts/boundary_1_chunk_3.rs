//! Boundary â‘  â€” Identity Spine: Chunk 3 (DRAFT)
//!
//! Scan-Object Identity: the types that answer "what was scanned" and
//! "which version of it."
//!
//! This file is additive to chunks 1+2. It uses the `CanonicalBytes` trait,
//! `define_id_32!` macro, `domain_hasher`, and `finalize_32` from chunk 1.
//!
//! ## Design Decisions (locked)
//!
//! D3a: ItemKey is source-prefixed with an opaque ConnectorTag to prevent
//!      cross-source collisions. Connectors self-identify; contracts crate
//!      does not enumerate connector types.
//!
//! D3b: ObjectVersionId is fixed [u8; 32]. Connectors normalize their
//!      version tokens via blake3 before constructing.
//!
//! D3c: ConnectorTag is [u8; 8] â€” readable ASCII tags, null-padded.
//!
//! D3d: StableItemId is tenant-independent. Tenant scoping enters at
//!      FindingId derivation (chunk 4).

// Assumes these are in scope from chunks 1+2:
// use crate::{CanonicalBytes, define_id_32, domain_hasher, finalize_32, Hasher};

// ============================================================================
// Â§ Chunk 3: Scan-Object Identity
// ============================================================================

// ---------------------------------------------------------------------------
// Â§3.1 ConnectorTag â€” source discriminator
// ---------------------------------------------------------------------------

/// Fixed-width tag identifying the connector (source system) that produced
/// an `ItemKey`.
///
/// Prevents cross-source collisions: a GitHub file at `org/repo/path.txt`
/// and a GitLab file at `org/repo/path.txt` hash to different
/// `StableItemId` values because their `ConnectorTag` differs.
///
/// ## Conventions
///
/// Tags SHOULD be short ASCII identifiers, null-padded on the right:
///
/// ```text
/// b"github\0\0"   â€” GitHub connector
/// b"gitlab\0\0"   â€” GitLab connector
/// b"s3\0\0\0\0\0\0" â€” S3 connector
/// b"azblob\0\0"   â€” Azure Blob connector
/// ```
///
/// The contracts crate does NOT enumerate valid tags. Connectors are
/// responsible for choosing a stable, unique tag. Tags are compared
/// byte-for-byte â€” `b"github\0\0"` and `b"GITHUB\0\0"` are different.
///
/// ## Invariants
///
/// **Safety (uniqueness)**: Two distinct connectors MUST use distinct tags.
/// This is enforced by convention and integration tests, not by the type.
///
/// **Safety (stability)**: A connector MUST NOT change its tag across
/// versions. Changing the tag changes all derived `StableItemId` values,
/// invalidating all finding records for items from that connector.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConnectorTag(pub [u8; 8]);

impl fmt::Debug for ConnectorTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Print as ASCII if all bytes are printable or null, else hex.
        let end = self.0.iter().position(|&b| b == 0).unwrap_or(8);
        let ascii = &self.0[..end];
        if ascii.iter().all(|b| b.is_ascii_graphic()) {
            // Safety: we just checked all bytes are ASCII graphic.
            let s = core::str::from_utf8(ascii).unwrap_or("???");
            write!(f, "ConnectorTag({s:?})")
        } else {
            write!(
                f,
                "ConnectorTag({:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x})",
                self.0[0], self.0[1], self.0[2], self.0[3],
                self.0[4], self.0[5], self.0[6], self.0[7],
            )
        }
    }
}

impl ConnectorTag {
    /// Create a tag from a byte string. Pads with zeros if shorter than 8.
    ///
    /// # Panics
    ///
    /// Panics if `tag` is longer than 8 bytes or empty.
    pub const fn from_ascii(tag: &[u8]) -> Self {
        assert!(!tag.is_empty(), "ConnectorTag must not be empty");
        assert!(tag.len() <= 8, "ConnectorTag must be at most 8 bytes");

        let mut buf = [0u8; 8];
        let mut i = 0;
        while i < tag.len() {
            buf[i] = tag[i];
            i += 1;
        }
        Self(buf)
    }

    #[inline]
    pub const fn from_bytes(bytes: [u8; 8]) -> Self {
        Self(bytes)
    }

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
// Â§3.2 ItemKey â€” variable-length scannable-item identity
// ---------------------------------------------------------------------------

/// Logical identity of a scannable item: a file, page, object, etc.
///
/// `ItemKey` is the full, human-meaningful identity. It carries enough
/// information to uniquely locate an item across all connectors. The
/// fixed-width `StableItemId` is derived from it for use in finding
/// derivation.
///
/// ## Structure
///
/// ```text
/// â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
/// â”‚ ConnectorTag  â”‚ path (connector-defined bytes)     â”‚
/// â”‚   [u8; 8]     â”‚ Box<[u8]>                          â”‚
/// â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
/// ```
///
/// The `path` field is opaque to the contracts crate. Connectors define
/// its encoding:
///
/// - GitHub: `"{owner}/{repo}\0{file_path}"` (UTF-8, null-separated)
/// - S3: `"{bucket}\0{object_key}"` (UTF-8, null-separated)
/// - Generic: any deterministic byte sequence
///
/// ## Invariants
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
/// ## CanonicalBytes Encoding
///
/// `ConnectorTag` (8 bytes, fixed) + `path` (length-prefixed).
/// The length prefix is a `u32` LE (max path length: ~4 GiB, far more
/// than needed).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ItemKey {
    pub connector: ConnectorTag,
    pub path: Box<[u8]>,
}

impl ItemKey {
    /// Construct an `ItemKey` from a connector tag and path bytes.
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

    /// Derive the fixed-width `StableItemId` for this key.
    ///
    /// This is a pure function: same `ItemKey` always produces the same
    /// `StableItemId`.
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
        // Path is variable-length â†’ length-prefixed.
        self.path.as_ref().write_canonical(h);
    }
}

// ---------------------------------------------------------------------------
// Â§3.3 StableItemId â€” fixed-width item identity for derivation
// ---------------------------------------------------------------------------

define_id_32! {
    /// Content-addressed identity of a scannable item.
    ///
    /// Derived as `blake3("gossip/item-id/v1", canonical_bytes(item_key))`.
    ///
    /// This is the identifier that enters `FindingId` derivation. It is
    /// **tenant-independent**: the same file has the same `StableItemId`
    /// regardless of which tenant is scanning it. Tenant scoping is
    /// applied at `FindingId` derivation (chunk 4).
    ///
    /// ## Invariants
    ///
    /// **Safety**: `StableItemId` MUST be a pure function of `ItemKey`.
    /// Given the same `ItemKey`, the output is always the same.
    ///
    /// **Safety**: Distinct `ItemKey` values MUST produce distinct
    /// `StableItemId` values (with cryptographic collision resistance).
    StableItemId
}

// ---------------------------------------------------------------------------
// Â§3.4 ObjectVersionId â€” version-specific content identity
// ---------------------------------------------------------------------------

define_id_32! {
    /// Identity of a specific version of a scannable item's content.
    ///
    /// Examples of what connectors normalize into this:
    ///
    /// - Git: `blake3(commit_sha ++ tree_sha_for_path)` â€” pinpoints the
    ///   exact content of a file at a specific commit.
    /// - S3: `blake3(etag_bytes)` or `blake3(version_id_bytes)`.
    /// - Content-hash: `blake3(raw_content)` for sources without native
    ///   versioning.
    ///
    /// Connectors MUST produce this via a deterministic function of the
    /// version token. The contracts crate provides a helper for the common
    /// case.
    ///
    /// ## Invariants
    ///
    /// **Safety**: The same version of the same content MUST always produce
    /// the same `ObjectVersionId`.
    ///
    /// **Safety**: Different versions of the same item SHOULD produce
    /// different `ObjectVersionId` values. (If a version token doesn't
    /// change when content changes â€” e.g., a mutable S3 object without
    /// versioning â€” the connector should fall back to content hashing.)
    ///
    /// ## Role in Finding Model
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
    /// commit SHA + tree SHA) should build a `domain_hasher` manually and
    /// feed structured fields via `CanonicalBytes`.
    pub fn from_version_bytes(version_bytes: &[u8]) -> Self {
        assert!(!version_bytes.is_empty(), "version bytes must not be empty");

        let mut h = domain_hasher(domain::OBJECT_VERSION_V1);
        version_bytes.write_canonical(&mut h);
        Self::from_bytes(finalize_32(&h))
    }
}

// ---------------------------------------------------------------------------
// Â§3.5 Domain constant additions
// ---------------------------------------------------------------------------

// Add to the `domain` module from chunk 1:
pub mod domain {
    // ... existing constants from chunk 1 ...

    /// StableItemId derivation from ItemKey.
    pub const ITEM_ID_V1: &[u8] = b"gossip/item-id/v1";

    /// ObjectVersionId derivation from version bytes.
    pub const OBJECT_VERSION_V1: &[u8] = b"gossip/object-version/v1";
}

// ============================================================================
// Â§ Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- ConnectorTag --

    #[test]
    fn connector_tag_from_ascii_pads() {
        let tag = ConnectorTag::from_ascii(b"github");
        assert_eq!(tag.0, *b"github\0\0");
    }

    #[test]
    fn connector_tag_from_ascii_exact_8() {
        let tag = ConnectorTag::from_ascii(b"conflunc");
        assert_eq!(tag.0, *b"conflunc");
    }

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
        let dbg = format!("{:?}", tag);
        assert!(dbg.contains("github"), "got: {dbg}");
    }

    #[test]
    fn connector_tag_debug_binary() {
        let tag = ConnectorTag::from_bytes([0xFF; 8]);
        let dbg = format!("{:?}", tag);
        // Non-ASCII â†’ hex output.
        assert!(dbg.contains("ffffffff"), "got: {dbg}");
    }

    // -- ItemKey --

    #[test]
    fn item_key_stable_id_deterministic() {
        let key = ItemKey::new(
            ConnectorTag::from_ascii(b"github"),
            b"org/repo\0src/main.rs".to_vec(),
        );
        let id1 = key.stable_id();
        let id2 = key.stable_id();
        assert_eq!(id1, id2);
    }

    #[test]
    fn item_key_different_connector_different_id() {
        let path = b"org/repo\0src/main.rs".to_vec();
        let github = ItemKey::new(
            ConnectorTag::from_ascii(b"github"),
            path.clone(),
        );
        let gitlab = ItemKey::new(
            ConnectorTag::from_ascii(b"gitlab"),
            path,
        );
        assert_ne!(github.stable_id(), gitlab.stable_id());
    }

    #[test]
    fn item_key_different_path_different_id() {
        let connector = ConnectorTag::from_ascii(b"github");
        let a = ItemKey::new(connector, b"org/repo\0a.rs".to_vec());
        let b = ItemKey::new(connector, b"org/repo\0b.rs".to_vec());
        assert_ne!(a.stable_id(), b.stable_id());
    }

    #[test]
    #[should_panic(expected = "must not be empty")]
    fn item_key_empty_path_panics() {
        ItemKey::new(ConnectorTag::from_ascii(b"github"), vec![]);
    }

    // -- ItemKey CanonicalBytes --

    #[test]
    fn item_key_canonical_bytes_deterministic() {
        let key = ItemKey::new(
            ConnectorTag::from_ascii(b"s3"),
            b"bucket\0path/to/object".to_vec(),
        );
        let mut h1 = Hasher::new();
        let mut h2 = Hasher::new();
        key.write_canonical(&mut h1);
        key.write_canonical(&mut h2);
        assert_eq!(h1.finalize(), h2.finalize());
    }

    #[test]
    fn item_key_canonical_bytes_unambiguous() {
        // Connector tag + path must not collide with different splits.
        // E.g., tag "ab" + path "cd" vs tag "abcd" + path "" â€” but
        // we prevent empty paths, and ConnectorTag is fixed-width,
        // so this is structurally impossible. Verify anyway:
        let a = ItemKey::new(
            ConnectorTag::from_bytes(*b"ab\0\0\0\0\0\0"),
            b"cd".to_vec(),
        );
        let b = ItemKey::new(
            ConnectorTag::from_bytes(*b"abcd\0\0\0\0"),
            b"ef".to_vec(),
        );
        let mut ha = Hasher::new();
        let mut hb = Hasher::new();
        a.write_canonical(&mut ha);
        b.write_canonical(&mut hb);
        assert_ne!(ha.finalize(), hb.finalize());
    }

    // -- ObjectVersionId --

    #[test]
    fn object_version_id_from_bytes_deterministic() {
        let v1 = ObjectVersionId::from_version_bytes(b"abc123");
        let v2 = ObjectVersionId::from_version_bytes(b"abc123");
        assert_eq!(v1, v2);
    }

    #[test]
    fn object_version_id_different_input_different_id() {
        let v1 = ObjectVersionId::from_version_bytes(b"abc123");
        let v2 = ObjectVersionId::from_version_bytes(b"def456");
        assert_ne!(v1, v2);
    }

    #[test]
    #[should_panic(expected = "must not be empty")]
    fn object_version_id_empty_panics() {
        ObjectVersionId::from_version_bytes(b"");
    }

    #[test]
    fn object_version_id_debug_is_safe() {
        let v = ObjectVersionId::from_version_bytes(b"commit-sha");
        let dbg = format!("{:?}", v);
        assert!(dbg.starts_with("ObjectVersionId("));
        assert!(dbg.len() < 80);
    }

    // -- StableItemId --

    #[test]
    fn stable_item_id_debug_is_safe() {
        let id = StableItemId::from_bytes([0xCA; 32]);
        let dbg = format!("{:?}", id);
        assert!(dbg.starts_with("StableItemId("));
        assert!(dbg.contains("cacacaca"));
        assert!(dbg.len() < 80);
    }

    // -- Property-based --

    proptest::proptest! {
        #[test]
        fn item_key_stable_id_is_pure(
            tag_bytes in proptest::array::uniform8(proptest::num::u8::ANY),
            path in proptest::collection::vec(proptest::num::u8::ANY, 1..256)
        ) {
            let key = ItemKey::new(
                ConnectorTag::from_bytes(tag_bytes),
                path,
            );
            let id1 = key.stable_id();
            let id2 = key.stable_id();
            prop_assert_eq!(id1, id2);
        }

        #[test]
        fn object_version_id_is_pure(
            bytes in proptest::collection::vec(proptest::num::u8::ANY, 1..256)
        ) {
            let v1 = ObjectVersionId::from_version_bytes(&bytes);
            let v2 = ObjectVersionId::from_version_bytes(&bytes);
            prop_assert_eq!(v1, v2);
        }

        #[test]
        fn item_key_canonical_bytes_stable(
            tag_bytes in proptest::array::uniform8(proptest::num::u8::ANY),
            path in proptest::collection::vec(proptest::num::u8::ANY, 1..128)
        ) {
            let key = ItemKey::new(
                ConnectorTag::from_bytes(tag_bytes),
                path,
            );
            let mut h1 = Hasher::new();
            let mut h2 = Hasher::new();
            key.write_canonical(&mut h1);
            key.write_canonical(&mut h2);
            prop_assert_eq!(h1.finalize(), h2.finalize());
        }
    }
}

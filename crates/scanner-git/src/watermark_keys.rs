//! Key building for watermark batch queries.
//!
//! The watermark store is queried with a MultiGet of composite keys:
//! `(repo_id, policy_hash, start_set_id, ref_name)`.
//!
//! This module provides `KeyArena`, a contiguous buffer that builds
//! all keys without per-key heap allocation. Keys are accessed by `KeyRef`
//! handles (offset + length into the arena). The arena pre-allocates
//! capacity based on caller estimates; if exceeded, the underlying `Vec`
//! grows normally (no silent failure, no panic).
//!
//! # Key Format
//!
//! ```text
//! ref_watermark key:
//!   "rw" (2B) || repo_id_be (8B) || policy_hash (32B) || start_set_id (32B) || ref_name || 0x00
//! ```
//!
//! Big-endian repo_id ensures lexicographic key ordering groups by repo.
//! Trailing null byte terminates the variable-length ref_name unambiguously
//! (Git ref names cannot contain NUL bytes per `git-check-ref-format`).

use super::object_id::OidBytes;
use super::start_set::StartSetId;

/// Key namespace prefix for ref watermarks (2 bytes).
///
/// Keeps the ref watermark keyspace disjoint from any future key types
/// in the same backing store.
pub const NS_REF_WATERMARK: [u8; 2] = *b"rw";

/// Fixed byte overhead per ref_watermark key (excluding ref_name).
///
/// `2 (ns) + 8 (repo_id) + 32 (policy_hash) + 32 (start_set_id) + 1 (null) = 75`
const RW_KEY_FIXED_OVERHEAD: usize = 2 + 8 + 32 + 32 + 1;

/// A reference to a key within a `KeyArena`.
///
/// Lightweight handle (8 bytes) that does not own any data. Handles are only
/// meaningful for the `KeyArena` that produced them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyRef {
    /// Byte offset into the arena.
    pub(crate) off: u32,
    /// Byte length of the key.
    pub(crate) len: u32,
}

impl KeyRef {
    /// Returns the byte offset into the arena.
    #[inline]
    #[must_use]
    pub fn off(&self) -> u32 {
        self.off
    }

    /// Returns the byte length of the key.
    #[inline]
    #[must_use]
    pub fn len(&self) -> u32 {
        self.len
    }

    /// Returns true if the key has zero length.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// In-memory key arena to batch-build many keys without per-key heap work.
///
/// # Invariants
///
/// - `refs.len()` equals the number of keys pushed
/// - `get(kr)` returns the exact bytes for key `kr`
/// - Arena is append-only; `clear()` resets both bytes and refs
/// - Total arena size must not exceed `u32::MAX` bytes (enforced by assert)
#[derive(Debug)]
pub struct KeyArena {
    bytes: Vec<u8>,
    refs: Vec<KeyRef>,
}

impl KeyArena {
    /// Creates a new arena with pre-allocated capacity.
    ///
    /// # Arguments
    ///
    /// * `cap_bytes` - Expected total bytes across all keys
    /// * `cap_keys` - Expected number of keys
    pub fn new(cap_bytes: usize, cap_keys: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(cap_bytes),
            refs: Vec::with_capacity(cap_keys),
        }
    }

    /// Resets the arena for reuse without deallocating.
    #[inline]
    pub fn clear(&mut self) {
        self.bytes.clear();
        self.refs.clear();
    }

    /// Returns the key bytes for a given reference.
    ///
    /// # Panics
    ///
    /// Panics if `k` is out of bounds (indicates a bug; `KeyRef` values
    /// should only come from this arena's `push_*` methods).
    #[inline]
    pub fn get(&self, k: KeyRef) -> &[u8] {
        let off = k.off as usize;
        let len = k.len as usize;

        let end = off.checked_add(len).expect("KeyRef off + len overflow");

        debug_assert!(
            end <= self.bytes.len(),
            "KeyRef out of bounds: off={off}, len={len}, arena_len={}",
            self.bytes.len()
        );

        &self.bytes[off..end]
    }

    /// Returns all key references in push order.
    #[inline]
    pub fn refs(&self) -> &[KeyRef] {
        &self.refs
    }

    /// Returns the number of keys in the arena.
    #[inline]
    pub fn key_count(&self) -> usize {
        self.refs.len()
    }

    /// Returns the total bytes used in the arena.
    #[inline]
    pub fn bytes_used(&self) -> usize {
        self.bytes.len()
    }

    /// Builds and appends a ref_watermark key.
    ///
    /// Key format:
    /// ```text
    /// "rw" (2B) || repo_id_be (8B) || policy_hash (32B) || start_set_id (32B) || ref_name || 0x00
    /// ```
    ///
    /// Fixed overhead: 75 bytes + ref_name.len()
    ///
    /// # Requirements
    ///
    /// - `ref_name` must be fully-qualified (e.g., `refs/heads/main`)
    /// - `ref_name` must not contain NUL bytes
    ///
    /// # Panics
    ///
    /// Panics if the arena would exceed `u32::MAX` bytes after this key.
    /// With `RepoOpenLimits::max_refs_in_start_set` at 1M and
    /// `max_refname_bytes` at 1024, worst case is about 1.02 GB and still
    /// within `u32::MAX`. This assert catches sizing bugs.
    ///
    /// # Returns
    ///
    /// The `KeyRef` handle for the appended key.
    pub fn push_ref_watermark_key(
        &mut self,
        repo_id: u64,
        policy_hash: &[u8; 32],
        start_set_id: &StartSetId,
        ref_name: &[u8],
    ) -> KeyRef {
        debug_assert!(
            !ref_name.contains(&0),
            "ref_name must not contain null bytes (violates key format)"
        );

        let key_len = RW_KEY_FIXED_OVERHEAD + ref_name.len();
        let start = self.bytes.len();

        assert!(
            start
                .checked_add(key_len)
                .is_some_and(|end| end <= u32::MAX as usize),
            "KeyArena overflow: arena would exceed u32::MAX bytes \
             (start={start}, key_len={key_len})"
        );

        self.bytes.reserve(key_len);

        self.bytes.extend_from_slice(&NS_REF_WATERMARK);
        self.bytes.extend_from_slice(&repo_id.to_be_bytes());
        self.bytes.extend_from_slice(policy_hash);
        self.bytes.extend_from_slice(start_set_id);
        self.bytes.extend_from_slice(ref_name);
        self.bytes.push(0);

        debug_assert_eq!(
            self.bytes.len() - start,
            key_len,
            "key_len calculation mismatch"
        );

        let kr = KeyRef {
            off: start as u32,
            len: key_len as u32,
        };
        self.refs.push(kr);

        kr
    }
}

/// Encodes a ref watermark value (OID) into a fixed buffer.
///
/// Value format: `oid_len (u8) + oid bytes (20 or 32)`
///
/// Returns `(buffer, used_len)` where `buffer[..used_len]` is the encoded value.
/// Maximum `used_len` is 33 (1 + 32 for SHA-256).
pub fn encode_ref_watermark_value(oid: &OidBytes) -> ([u8; 33], usize) {
    let mut out = [0u8; 33];
    let n = oid.len() as usize;

    debug_assert!(n == 20 || n == 32, "OID len must be 20 or 32, got {n}");

    out[0] = oid.len();
    out[1..1 + n].copy_from_slice(oid.as_slice());
    (out, 1 + n)
}

/// Decodes a ref watermark value back to an `OidBytes`.
///
/// The input slice must be exactly the encoded value (no trailing bytes).
/// This matches the semantics of KV store point lookups (MultiGet), where
/// each returned value is a complete, standalone buffer.
///
/// Returns `None` if the value is malformed:
/// - Empty input
/// - OID length is not 20 or 32
/// - Actual byte count does not match declared length
pub fn decode_ref_watermark_value(bytes: &[u8]) -> Option<OidBytes> {
    if bytes.is_empty() {
        return None;
    }
    let oid_len = bytes[0] as usize;
    if oid_len != 20 && oid_len != 32 {
        return None;
    }
    if bytes.len() != 1 + oid_len {
        return None;
    }
    OidBytes::try_from_slice(&bytes[1..])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_oid_sha1(val: u8) -> OidBytes {
        OidBytes::sha1([val; 20])
    }

    fn test_oid_sha256(val: u8) -> OidBytes {
        OidBytes::sha256([val; 32])
    }

    #[test]
    fn key_ref_accessors() {
        let kr = KeyRef { off: 10, len: 75 };
        assert_eq!(kr.off(), 10);
        assert_eq!(kr.len(), 75);
        assert!(!kr.is_empty());

        let empty = KeyRef { off: 0, len: 0 };
        assert!(empty.is_empty());
    }

    #[test]
    fn key_arena_basic_roundtrip() {
        let mut arena = KeyArena::new(512, 4);

        let repo_id = 42u64;
        let policy_hash = [0xaa; 32];
        let start_set_id = [0xbb; 32];

        let kr1 =
            arena.push_ref_watermark_key(repo_id, &policy_hash, &start_set_id, b"refs/heads/main");
        let kr2 =
            arena.push_ref_watermark_key(repo_id, &policy_hash, &start_set_id, b"refs/heads/dev");

        assert_eq!(arena.key_count(), 2);
        assert_eq!(arena.refs().len(), 2);

        let k1 = arena.get(kr1);
        let k2 = arena.get(kr2);
        assert!(k1.starts_with(b"rw"));
        assert!(k2.starts_with(b"rw"));
        assert_ne!(k1, k2);
        assert!(k1.ends_with(b"refs/heads/main\0"));
        assert!(k2.ends_with(b"refs/heads/dev\0"));
    }

    #[test]
    fn key_arena_clear_resets() {
        let mut arena = KeyArena::new(256, 2);
        arena.push_ref_watermark_key(1, &[0; 32], &[0; 32], b"refs/heads/main");
        assert_eq!(arena.key_count(), 1);
        assert!(arena.bytes_used() > 0);

        arena.clear();
        assert_eq!(arena.key_count(), 0);
        assert_eq!(arena.bytes_used(), 0);
    }

    #[test]
    fn key_fixed_overhead_is_75_plus_ref_name() {
        let mut arena = KeyArena::new(256, 1);
        let ref_name = b"refs/heads/main";
        let kr = arena.push_ref_watermark_key(1, &[0; 32], &[0; 32], ref_name);

        let expected = RW_KEY_FIXED_OVERHEAD + ref_name.len();
        assert_eq!(kr.len() as usize, expected);
        assert_eq!(RW_KEY_FIXED_OVERHEAD, 75);
    }

    #[test]
    fn key_layout_field_offsets() {
        let mut arena = KeyArena::new(256, 1);
        let repo_id = 0x0102_0304_0506_0708u64;
        let policy_hash = [0xaa; 32];
        let start_set_id = [0xbb; 32];
        let ref_name = b"refs/heads/main";

        let kr = arena.push_ref_watermark_key(repo_id, &policy_hash, &start_set_id, ref_name);
        let key = arena.get(kr);

        assert_eq!(&key[0..2], b"rw");
        assert_eq!(&key[2..10], &repo_id.to_be_bytes());
        assert_eq!(&key[10..42], &policy_hash);
        assert_eq!(&key[42..74], &start_set_id);
        assert_eq!(&key[74..74 + ref_name.len()], ref_name);
        assert_eq!(key[74 + ref_name.len()], 0x00);
        assert_eq!(key.len(), 75 + ref_name.len());
    }

    #[test]
    fn big_endian_repo_id_preserves_numeric_ordering() {
        let mut arena = KeyArena::new(512, 3);
        let policy = [0; 32];
        let ssid = [0; 32];
        let ref_name = b"r";

        let kr1 = arena.push_ref_watermark_key(1, &policy, &ssid, ref_name);
        let kr2 = arena.push_ref_watermark_key(256, &policy, &ssid, ref_name);
        let kr3 = arena.push_ref_watermark_key(u64::MAX, &policy, &ssid, ref_name);

        let k1 = arena.get(kr1);
        let k2 = arena.get(kr2);
        let k3 = arena.get(kr3);

        assert!(k1 < k2, "repo_id 1 should sort before 256");
        assert!(k2 < k3, "repo_id 256 should sort before MAX");
    }

    #[test]
    fn encode_decode_roundtrip_sha1() {
        let oid = test_oid_sha1(0xab);
        let (buf, len) = encode_ref_watermark_value(&oid);

        assert_eq!(len, 21);
        assert_eq!(buf[0], 20);

        let decoded = decode_ref_watermark_value(&buf[..len]).unwrap();
        assert_eq!(decoded, oid);
    }

    #[test]
    fn encode_decode_roundtrip_sha256() {
        let oid = test_oid_sha256(0xcd);
        let (buf, len) = encode_ref_watermark_value(&oid);

        assert_eq!(len, 33);
        assert_eq!(buf[0], 32);

        let decoded = decode_ref_watermark_value(&buf[..len]).unwrap();
        assert_eq!(decoded, oid);
    }

    #[test]
    fn decode_rejects_empty() {
        assert!(decode_ref_watermark_value(&[]).is_none());
    }

    #[test]
    fn decode_rejects_invalid_oid_len() {
        let mut buf = [0u8; 11];
        buf[0] = 10;
        assert!(decode_ref_watermark_value(&buf).is_none());
    }

    #[test]
    fn decode_rejects_truncated() {
        let mut buf = [0u8; 11];
        buf[0] = 20;
        assert!(decode_ref_watermark_value(&buf).is_none());
    }

    #[test]
    fn decode_rejects_oversized() {
        let mut buf = [0u8; 33];
        buf[0] = 20;
        assert!(decode_ref_watermark_value(&buf).is_none());
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        let oid = test_oid_sha1(0xab);
        let (buf, len) = encode_ref_watermark_value(&oid);

        assert!(decode_ref_watermark_value(&buf[..len]).is_some());

        let mut extended = [0u8; 34];
        extended[..len].copy_from_slice(&buf[..len]);
        assert!(decode_ref_watermark_value(&extended[..len + 1]).is_none());
    }
}

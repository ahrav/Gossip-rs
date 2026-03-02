//! Deduplicating byte interner for identity strings.
//!
//! Stores unique identity strings (names, emails) in a compact [`ByteArena`]
//! with hash-based deduplication. Each unique string gets a `u32` intern ID;
//! repeated insertions return the existing ID.
//!
//! # Design
//! - Uses `ahash::AHashMap` (already a dependency) for O(1) dedup lookups.
//! - Dedup key is `u64` hash-as-key: amortized O(1) allocation (map/vec
//!   growth), acceptable collision probability (~2.7e-10 birthday bound at
//!   100K entries) for display-only data.
//! - Arena stores raw bytes; non-UTF-8 is preserved and handled at
//!   serialization (JSONL uses `\u00XX` escaping).
//! - [`SENTINEL_ID`] (`u32::MAX`) signals parse failure; never maps to a
//!   valid entry.

use ahash::AHashMap;

use super::byte_arena::{ByteArena, ByteRef};

/// Sentinel ID returned when identity parsing fails.
///
/// Never maps to a valid interned entry. Callers must check for this
/// value before resolving via [`IdentityInterner::get`].
pub const SENTINEL_ID: u32 = u32::MAX;

/// Per-commit identity ID tuple.
///
/// Stores intern IDs for author name, author email, committer name,
/// committer email. Each ID indexes into an [`IdentityInterner`].
/// [`SENTINEL_ID`] indicates a parse failure for that field.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommitIdentityIds {
    pub author_name: u32,
    pub author_email: u32,
    pub committer_name: u32,
    pub committer_email: u32,
}

impl Default for CommitIdentityIds {
    /// All fields default to [`SENTINEL_ID`] (unset/parse-failure).
    ///
    /// This prevents confusion with intern ID 0, which is a valid entry.
    fn default() -> Self {
        Self {
            author_name: SENTINEL_ID,
            author_email: SENTINEL_ID,
            committer_name: SENTINEL_ID,
            committer_email: SENTINEL_ID,
        }
    }
}

// Compile-time layout assertions.
const _: () = {
    assert!(std::mem::size_of::<CommitIdentityIds>() == 16);
    assert!(std::mem::align_of::<CommitIdentityIds>() == 4);
};

/// Deduplicating byte interner backed by a [`ByteArena`].
///
/// Each unique byte sequence gets a monotonically increasing `u32` ID.
/// Deduplication uses the 64-bit hash of the bytes as the map key.
///
/// # Thread safety
///
/// Intended for single-threaded population during commit graph traversal,
/// after which the interner is shared immutably (via `&self` on
/// [`get`](Self::get) and [`iter`](Self::iter)).
///
/// # Hash-collision trade-off
///
/// Two distinct byte sequences that hash to the same `u64` will silently
/// alias to the same intern ID. At 100K unique entries, the birthday-bound
/// collision probability is ~2.7 × 10⁻¹⁰ — acceptable because identity
/// strings are display-only metadata, not security-critical join keys.
pub struct IdentityInterner {
    arena: ByteArena,
    /// hash(bytes) → intern_id.
    dedup: AHashMap<u64, u32>,
    /// intern_id → ByteRef into arena.
    refs: Vec<ByteRef>,
}

impl IdentityInterner {
    /// Creates a new interner with pre-allocated capacity.
    ///
    /// # Arguments
    /// * `arena_bytes` - Maximum byte capacity for the arena.
    /// * `estimated_unique` - Estimated number of unique strings (for map sizing).
    #[must_use]
    pub fn with_capacity(arena_bytes: u32, estimated_unique: usize) -> Self {
        Self {
            arena: ByteArena::with_capacity(arena_bytes),
            dedup: AHashMap::with_capacity(estimated_unique),
            refs: Vec::with_capacity(estimated_unique),
        }
    }

    /// Interns a byte slice, returning its ID.
    ///
    /// Returns the existing ID on dedup hit. Returns `None` if the arena
    /// is full, the slice exceeds `ByteRef::MAX_LEN`, or the intern table
    /// has reached `u32::MAX` entries (which would collide with
    /// [`SENTINEL_ID`]).
    pub fn intern(&mut self, bytes: &[u8]) -> Option<u32> {
        let hash = self.hash_bytes(bytes);

        if let Some(&id) = self.dedup.get(&hash) {
            return Some(id);
        }

        let byte_ref = self.arena.intern(bytes)?;
        let id = self.refs.len() as u32;
        if id == SENTINEL_ID {
            // Would collide with sentinel. This requires 4 billion unique entries,
            // which is not realistic, but guard against it.
            return None;
        }
        self.refs.push(byte_ref);
        self.dedup.insert(hash, id);
        Some(id)
    }

    /// Interns a byte slice, returning [`SENTINEL_ID`] on failure.
    #[inline]
    pub fn intern_or_sentinel(&mut self, bytes: &[u8]) -> u32 {
        self.intern(bytes).unwrap_or(SENTINEL_ID)
    }

    /// Resolves an intern ID to its byte slice.
    ///
    /// # Panics
    /// Panics if `id` is [`SENTINEL_ID`] or out of range.
    #[inline]
    pub fn get(&self, id: u32) -> &[u8] {
        assert!(
            id != SENTINEL_ID,
            "attempted to resolve SENTINEL_ID in IdentityInterner"
        );
        self.arena.get(self.refs[id as usize])
    }

    /// Returns the number of unique interned entries.
    #[inline]
    #[must_use]
    pub fn len(&self) -> u32 {
        self.refs.len() as u32
    }

    /// Returns `true` if no entries have been interned.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.refs.is_empty()
    }

    /// Iterates over all interned entries as `(id, bytes)` pairs in
    /// insertion order (monotonically increasing IDs, `0..len()`).
    pub fn iter(&self) -> impl Iterator<Item = (u32, &[u8])> {
        self.refs
            .iter()
            .enumerate()
            .map(move |(id, byte_ref)| (id as u32, self.arena.get(*byte_ref)))
    }

    /// Compute the `ahash` of a byte slice using the map's own hasher.
    ///
    /// Reuses the `AHashMap`'s `RandomState` so the hash values are
    /// consistent with the dedup map — a standalone hasher would use a
    /// different random seed and produce incompatible keys.
    #[inline]
    fn hash_bytes(&self, bytes: &[u8]) -> u64 {
        self.dedup.hasher().hash_one(bytes)
    }
}

impl std::fmt::Debug for IdentityInterner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityInterner")
            .field("entries", &self.refs.len())
            .field("arena_used", &self.arena.len())
            .field("arena_capacity", &self.arena.capacity())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedup_correctness() {
        let mut interner = IdentityInterner::with_capacity(4096, 16);

        let id1 = interner.intern(b"alice").unwrap();
        let id2 = interner.intern(b"bob").unwrap();
        let id3 = interner.intern(b"alice").unwrap();

        assert_eq!(id1, id3, "duplicate should return same ID");
        assert_ne!(id1, id2, "distinct strings should get different IDs");
    }

    #[test]
    fn distinct_ids() {
        let mut interner = IdentityInterner::with_capacity(4096, 16);

        let ids: Vec<u32> = (0..100)
            .map(|i| interner.intern(format!("user{i}").as_bytes()).unwrap())
            .collect();

        // All IDs should be unique.
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(ids.len(), sorted.len());
    }

    #[test]
    fn arena_overflow_returns_sentinel() {
        let mut interner = IdentityInterner::with_capacity(10, 16);

        let _id1 = interner.intern(b"hello").unwrap(); // 5 bytes
        let _id2 = interner.intern(b"world").unwrap(); // 5 bytes, arena full

        // Arena is full — next intern should fail.
        let id3 = interner.intern(b"overflow");
        assert!(id3.is_none());
        assert_eq!(interner.intern_or_sentinel(b"overflow"), SENTINEL_ID);
    }

    #[test]
    fn empty_bytes() {
        let mut interner = IdentityInterner::with_capacity(4096, 16);

        let id = interner.intern(b"").unwrap();
        assert_eq!(interner.get(id), b"");
    }

    #[test]
    fn get_roundtrip() {
        let mut interner = IdentityInterner::with_capacity(4096, 16);

        let id = interner.intern(b"torvalds@linux-foundation.org").unwrap();
        assert_eq!(interner.get(id), b"torvalds@linux-foundation.org");
    }

    #[test]
    fn iter_roundtrip() {
        let mut interner = IdentityInterner::with_capacity(4096, 16);

        interner.intern(b"alice").unwrap();
        interner.intern(b"bob").unwrap();
        interner.intern(b"alice").unwrap(); // dedup

        let entries: Vec<(u32, &[u8])> = interner.iter().collect();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0], (0, b"alice" as &[u8]));
        assert_eq!(entries[1], (1, b"bob" as &[u8]));
    }

    #[test]
    fn len_tracking() {
        let mut interner = IdentityInterner::with_capacity(4096, 16);
        assert!(interner.is_empty());
        assert_eq!(interner.len(), 0);

        interner.intern(b"a").unwrap();
        assert!(!interner.is_empty());
        assert_eq!(interner.len(), 1);

        interner.intern(b"a").unwrap(); // dedup
        assert_eq!(interner.len(), 1);

        interner.intern(b"b").unwrap();
        assert_eq!(interner.len(), 2);
    }

    #[test]
    #[should_panic(expected = "SENTINEL_ID")]
    fn get_sentinel_panics() {
        let interner = IdentityInterner::with_capacity(4096, 16);
        let _ = interner.get(SENTINEL_ID);
    }

    #[test]
    fn commit_identity_ids_default_uses_sentinel() {
        let ids = CommitIdentityIds::default();
        assert_eq!(ids.author_name, SENTINEL_ID);
        assert_eq!(ids.author_email, SENTINEL_ID);
        assert_eq!(ids.committer_name, SENTINEL_ID);
        assert_eq!(ids.committer_email, SENTINEL_ID);
    }

    #[test]
    fn non_utf8_preserved() {
        let mut interner = IdentityInterner::with_capacity(4096, 16);
        let raw = &[0xff, 0xfe, 0xfd, 0x00, 0x80];
        let id = interner.intern(raw).unwrap();
        assert_eq!(interner.get(id), raw);
    }
}

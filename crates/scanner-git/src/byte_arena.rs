//! Byte arena for Git scanning.
//!
//! Provides compact storage for variable-length byte sequences with
//! stable `ByteRef` handles. Primarily used to intern file paths
//! discovered during blob introduction so that `PackCandidate` and
//! `LooseCandidate` records can reference paths without per-candidate
//! heap allocation.
//!
//! # Design
//! - Append-only during normal use: bytes are not selectively removed, so
//!   references remain valid until an explicit reset (see
//!   [`ByteArena::clear_keep_capacity`]).
//! - References are offsets, not pointers, so `Vec` reallocation does not
//!   invalidate them.
//! - No deduplication is performed; repeated inserts store repeated bytes.
//! - Capacity is a hard `u32` limit (max ~4 GiB), bounded at creation.
//!   Pre-allocation is capped at 1 MiB to avoid large upfront reservations
//!   on small repos.
//!
//! # Complexity
//! - `intern` is `O(n)` in the inserted length (memcpy).
//! - `get` is `O(1)` (slice index).

/// Reference to bytes stored in a `ByteArena`.
///
/// This is a small, copyable handle. It does not track lifetimes, so the
/// caller must ensure it is only used with the arena it was created from.
/// A zero-length reference (`off=0,len=0`) is commonly used as an empty-path
/// sentinel, but is still tied to the owning arena.
///
/// # Invariants
/// - `off + len` must not overflow `u32` (enforced by `end()`)
/// - The referenced range must be valid in the owning arena
/// - `len` is at most `MAX_LEN` (fits in `u16`)
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ByteRef {
    /// Offset into the arena.
    pub off: u32,
    /// Length in bytes (max 65535).
    pub len: u16,
}

impl ByteRef {
    /// Maximum length for a byte reference.
    pub const MAX_LEN: u16 = u16::MAX;

    /// Creates a new byte reference.
    ///
    /// This does not validate the range. Use only with trusted inputs.
    #[inline]
    #[must_use]
    pub const fn new(off: u32, len: u16) -> Self {
        Self { off, len }
    }

    /// Returns the offset.
    #[inline]
    #[must_use]
    pub const fn off(&self) -> u32 {
        self.off
    }

    /// Returns the length.
    #[inline]
    #[must_use]
    pub const fn length(&self) -> u16 {
        self.len
    }

    /// Returns the end offset (exclusive).
    ///
    /// # Panics
    ///
    /// Panics if `off + len` overflows `u32`.
    #[inline]
    #[must_use]
    pub const fn end(&self) -> u32 {
        match self.off.checked_add(self.len as u32) {
            Some(v) => v,
            None => panic!("ByteRef::end overflow"),
        }
    }

    /// Returns the end offset, or `None` if overflow would occur.
    #[inline]
    #[must_use]
    pub const fn checked_end(&self) -> Option<u32> {
        self.off.checked_add(self.len as u32)
    }
}

/// Bump allocator for variable-length byte sequences.
///
/// This arena stores bytes contiguously and returns offset-based references.
/// The `capacity` is a hard limit; the internal `Vec` may reserve less to
/// avoid large upfront allocations.
///
/// # Invariants
/// - Total bytes never exceeds `capacity`
/// - All returned `ByteRef` values remain valid until [`clear_keep_capacity`](Self::clear_keep_capacity) is called
/// - All returned `ByteRef` values have `off + len <= capacity`
#[derive(Clone, Debug)]
pub struct ByteArena {
    bytes: Vec<u8>,
    capacity: u32,
}

impl ByteArena {
    /// Maximum pre-allocation size (1 MiB).
    const PREALLOC_MAX_BYTES: u32 = 1024 * 1024;

    /// Creates a new arena with the specified maximum capacity.
    ///
    /// The internal pre-allocation is capped to avoid large eager allocations.
    #[must_use]
    pub fn with_capacity(capacity: u32) -> Self {
        Self {
            bytes: Vec::with_capacity(capacity.min(Self::PREALLOC_MAX_BYTES) as usize),
            capacity,
        }
    }

    /// Pushes a byte slice into the arena, returning a reference.
    ///
    /// This is an append-only operation; previously returned references
    /// remain valid after insertion.
    ///
    /// Returns `None` if the slice is too long or exceeds capacity.
    pub fn intern(&mut self, data: &[u8]) -> Option<ByteRef> {
        if data.len() > ByteRef::MAX_LEN as usize {
            return None;
        }
        let len = data.len() as u16;

        let off = self.bytes.len() as u32;
        let end = off.checked_add(len as u32)?;
        if end > self.capacity {
            return None;
        }

        debug_assert!(end <= self.capacity);

        self.bytes.extend_from_slice(data);
        Some(ByteRef::new(off, len))
    }

    /// Retrieves the bytes for a reference.
    ///
    /// # Panics
    ///
    /// Panics if `r` is invalid (overflow in `end()` or out-of-bounds range).
    #[inline]
    #[must_use]
    pub fn get(&self, r: ByteRef) -> &[u8] {
        let start = r.off as usize;
        let end = r.end() as usize;

        debug_assert!(
            start <= self.bytes.len(),
            "ByteRef start out of bounds: {} > {}",
            start,
            self.bytes.len()
        );
        debug_assert!(
            end <= self.bytes.len(),
            "ByteRef end out of bounds: {} > {}",
            end,
            self.bytes.len()
        );

        &self.bytes[start..end]
    }

    /// Returns current usage in bytes.
    #[inline]
    #[must_use]
    pub fn len(&self) -> u32 {
        self.bytes.len() as u32
    }

    /// Returns true if the arena is empty.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Returns remaining capacity in bytes.
    ///
    /// Saturates at 0 if the arena is at or above capacity.
    #[inline]
    #[must_use]
    pub fn remaining(&self) -> u32 {
        self.capacity.saturating_sub(self.bytes.len() as u32)
    }

    /// Returns the maximum capacity.
    #[inline]
    #[must_use]
    pub fn capacity(&self) -> u32 {
        self.capacity
    }

    /// Returns the backing bytes as a slice.
    #[inline]
    #[must_use]
    pub fn backing_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Appends all bytes from `other` into this arena.
    ///
    /// Returns the base offset that was used for the appended region.
    /// Callers must rebase `ByteRef` values from `other` by adding
    /// this base to their `off` field (using `checked_add` to detect
    /// overflow).
    ///
    /// Returns `None` if the combined size would exceed this arena's
    /// capacity or overflow `u32`.
    pub fn append_arena(&mut self, other: &ByteArena) -> Option<u32> {
        let base = self.bytes.len() as u32;
        let other_len = other.bytes.len() as u32;
        let new_total = base.checked_add(other_len)?;
        if new_total > self.capacity {
            return None;
        }
        self.bytes.extend_from_slice(&other.bytes);
        Some(base)
    }

    /// Clears all stored bytes while preserving allocated capacity.
    ///
    /// All previously returned `ByteRef` values become invalid after this call.
    pub fn clear_keep_capacity(&mut self) {
        self.bytes.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const _: () = {
        assert!(std::mem::size_of::<ByteRef>() == 8);
        assert!(std::mem::align_of::<ByteRef>() == 4);
    };

    #[test]
    fn byte_arena_basic() {
        let mut arena = ByteArena::with_capacity(1024);

        let r1 = arena.intern(b"refs/heads/main").unwrap();
        let r2 = arena.intern(b"refs/heads/develop").unwrap();

        assert_eq!(arena.get(r1), b"refs/heads/main");
        assert_eq!(arena.get(r2), b"refs/heads/develop");
    }

    #[test]
    fn byte_arena_capacity_limit() {
        let mut arena = ByteArena::with_capacity(10);

        let r1 = arena.intern(b"hello");
        assert!(r1.is_some());

        let r2 = arena.intern(b"world!");
        assert!(r2.is_none());

        let r3 = arena.intern(b"hi");
        assert!(r3.is_some());
    }

    #[test]
    fn byte_arena_max_len() {
        let mut arena = ByteArena::with_capacity(u32::MAX);

        let long_data = vec![0u8; ByteRef::MAX_LEN as usize + 1];
        let result = arena.intern(&long_data);
        assert!(result.is_none());
    }

    #[test]
    fn byte_ref_end_valid() {
        let r = ByteRef::new(100, 50);
        assert_eq!(r.end(), 150);
        assert_eq!(r.checked_end(), Some(150));
    }

    #[test]
    #[should_panic(expected = "ByteRef::end overflow")]
    fn byte_ref_end_overflow_panics() {
        let r = ByteRef::new(u32::MAX - 10, 100);
        let _ = r.end();
    }

    #[test]
    fn byte_ref_checked_end_overflow() {
        let r = ByteRef::new(u32::MAX - 10, 100);
        assert!(r.checked_end().is_none());
    }

    #[test]
    fn append_arena_rebases_correctly() {
        let mut dst = ByteArena::with_capacity(1024);
        let r1 = dst.intern(b"hello").unwrap();

        let mut src = ByteArena::with_capacity(1024);
        let r2 = src.intern(b"world").unwrap();

        let base = dst.append_arena(&src).unwrap();
        assert_eq!(base, 5);

        // Original ref still valid.
        assert_eq!(dst.get(r1), b"hello");

        // Rebased ref from src.
        let rebased = ByteRef::new(r2.off.checked_add(base).unwrap(), r2.len);
        assert_eq!(dst.get(rebased), b"world");
    }

    #[test]
    fn append_arena_capacity_exceeded() {
        let mut dst = ByteArena::with_capacity(8);
        dst.intern(b"hello").unwrap();

        let mut src = ByteArena::with_capacity(1024);
        src.intern(b"world").unwrap();

        // 5 + 5 = 10 > 8: should fail.
        assert!(dst.append_arena(&src).is_none());
    }

    #[test]
    fn backing_bytes_returns_content() {
        let mut arena = ByteArena::with_capacity(1024);
        arena.intern(b"abc").unwrap();
        assert_eq!(arena.backing_bytes(), b"abc");
    }
}

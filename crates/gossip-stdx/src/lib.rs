//! Shared low-level data structures for gossip-rs.
//!
//! # Motivation
//!
//! The gossip coordination layer needs allocation-silent hot paths: per-shard
//! mutations (checkpoint, complete, cursor updates) run millions of times per
//! session, and heap allocation in those loops is the dominant cost. This crate
//! provides three data structures that eliminate those allocations by keeping
//! storage stack-resident or pre-allocated.
//!
//! It exists as a separate crate from `gossip-contracts` because that crate
//! uses `#![forbid(unsafe_code)]`, and two of the three types here
//! (`InlineVec`, `RingBuffer`) require `unsafe` for `MaybeUninit`-based
//! storage. Key types are re-exported by `gossip-coordination`.
//!
//! # Provided types
//!
//! | Type | Purpose |
//! |------|---------|
//! | [`ByteSlab`] / [`ByteSlot`] | Pre-allocated contiguous byte pool with hybrid bump + free-list allocator; replaces per-field `Box<[u8]>` heap allocations for shard byte fields |
//! | [`InlineVec`] | Stack-first small vector; stores up to N elements inline, one-way spill to heap beyond N; replaces `Vec<T>` for small collections (e.g., spawned children per shard) |
//! | [`RingBuffer`] | Fixed-capacity circular buffer with power-of-2 bitwise indexing; zero heap allocation; used for bounded event/history queues |
//!
//! All three share a common design philosophy: the hot-path representation
//! uses contiguous, pre-sized storage, and the hot-path operations
//! (`allocate`/`deallocate`, `push` while inline, `push_back`) perform no
//! heap allocation.
//!
//! # Safety and verification
//!
//! Every `unsafe` block in this crate carries a `// SAFETY:` comment
//! explaining why the preconditions hold. Correctness is verified through
//! three complementary techniques:
//!
//! - **Miri** (runtime): detects undefined behavior, use-after-free, and
//!   uninitialized reads under the stacked-borrows model.
//! - **Kani** (formal): symbolic verification of `InlineVec` unsafe
//!   operations (9 proofs covering 8 of 9 unsafe blocks — bounds, spill
//!   preservation, and drop correctness).
//! - **Fuzz testing** (coverage): `cargo-fuzz` targets exercise randomized
//!   operation sequences for all three types (see `fuzz/fuzz_targets/`).
//!
//! # Crate-level lints
//!
//! - `deny(unsafe_op_in_unsafe_fn)` — forces every `unsafe` operation inside
//!   an `unsafe fn` to be wrapped in an explicit `unsafe` block with a safety
//!   comment, preventing "inherited unsafety" from hiding under-documented
//!   operations.
//! - `deny(clippy::undocumented_unsafe_blocks)` — requires a `// SAFETY:`
//!   comment on every `unsafe` block.
//!
//! # Miri testing
//!
//! All tests in this crate should be run under Miri to verify memory safety:
//! ```sh
//! cargo +nightly miri test -p gossip-stdx
//! ```
//!
//! # scanner-rs Compatibility Mapping
//!
//! During scanner-rs consolidation we intentionally avoid duplicate container
//! implementations:
//! - `scanner-rs::stdx::fixed_vec::FixedVec<T, N>` -> [`InlineVec<T, N>`]
//! - `scanner-rs::stdx::ring_buffer::RingBuffer<T, N>` -> [`RingBuffer<T, N>`]
//!
//! New scanner-facing stdx modules are exposed both as root re-exports and via
//! module paths to minimize migration churn.

#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]

use std::fmt;

/// Provides a lock-free atomic bitset with test-and-set for concurrent dedup.
pub mod atomic_bitset;
/// Provides composite concurrent dedup tracker for git object traversal.
pub mod atomic_seen_sets;
/// Provides a heap-allocated dynamic bitset for runtime-determined sizes.
pub mod bitset;
/// Implements a byte ring buffer keyed by absolute stream offsets.
pub mod byte_ring;
mod byte_slab;
/// Implements fast range reduction via multiply-high (no division).
pub mod fastrange;
/// Provides fixed-capacity dedupe sets with O(1) reset via generation counters.
pub mod fixed_set;
/// Provides FNV-1a 64-bit hashing helpers for deterministic fingerprinting.
pub mod fnv;
mod inline_vec;
/// Provides small arithmetic helpers for scan-time performance counters.
pub mod perf_stats;
mod ring_buffer;
pub mod spsc;
/// Implements a hashed timing wheel with FIFO buckets and bitmap occupancy.
pub mod timing_wheel;

/// Shared proptest configuration helpers for consistent test case counts.
#[cfg(any(test, feature = "stdx-proptest"))]
pub mod test_support;

pub use atomic_bitset::AtomicBitSet;
pub use atomic_seen_sets::AtomicSeenSets;
pub use bitset::{DynamicBitSet, DynamicBitSetIterator, words_for_bits};
pub use byte_ring::ByteRing;
/// Pre-allocated contiguous byte pool with hybrid bump + free-list allocator.
///
/// - [`ByteSlab`]: the pool itself — allocate, deallocate, and read byte regions.
/// - [`ByteSlot`]: a 16-byte handle (offset + length + alloc size + owner id)
///   returned by [`ByteSlab::allocate`]; acts as coordinates into the pool.
/// - [`SlabFull`]: error returned when neither the free list nor the bump
///   region can satisfy an allocation request.
///
/// See [`ByteSlab`] type-level docs for design details, memory layout
/// diagrams, and invariants.
pub use byte_slab::{ByteSlab, ByteSlot, MIN_BLOCK, SlabFull};

/// FNV-1a 64-bit hashing helpers for deterministic fingerprinting.
///
/// Re-exported from [`fnv`] for convenience. These are the shared primitives
/// used across `gossip-engine` and `gossip-worker` for page signatures and
/// finding fingerprints.
pub use fnv::{FNV_OFFSET, FNV_PRIME, fnv_mix_byte, fnv_mix_bytes, fnv_mix_opt_bytes, fnv_mix_u64};

/// Stack-first small vector backed by `[MaybeUninit<T>; N]`.
///
/// Stores up to `N` elements inline with zero heap allocation. On the
/// `N+1`th push, all elements spill one-way to a heap `Vec<T>`.
/// Typical use: `InlineVec<ShardId, N>` for spawned-children lists where
/// most shards have few children and the inline path avoids allocation.
pub use inline_vec::InlineVec;

pub use fastrange::fast_range;
pub use fixed_set::FixedSet128;
/// Fixed-capacity ring buffer with stack-allocated storage and power-of-2
/// bitwise indexing.
///
/// - [`RingBuffer`]: the buffer itself — `push_back`, `pop_front`,
///   `push_back_overwrite` (evict oldest on overflow).
/// - [`Iter`]: borrowing iterator with [`DoubleEndedIterator`] support
///   (forward and reverse traversal).
/// - [`IntoIter`]: consuming iterator that yields owned elements in FIFO
///   order; remaining elements are dropped when the iterator is dropped.
pub use ring_buffer::{IntoIter, Iter, RingBuffer};
pub use spsc::{OwnedSpscConsumer, OwnedSpscProducer, spsc_channel};
pub use timing_wheel::{Bitset2, PushError, PushOutcome, TimingWheel};

/// Encode a byte slice as a lowercase hexadecimal string.
///
/// Uses a constant lookup table for branchless nibble conversion.
#[must_use]
pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Lookup table shared by hex encoding functions.
const HEX_LUT: &[u8; 16] = b"0123456789abcdef";

/// Encode a byte slice as lowercase hex into a caller-provided buffer.
///
/// Returns the number of bytes written (`bytes.len() * 2`). The caller must
/// ensure `buf` has at least `bytes.len() * 2` bytes available starting at
/// `offset`. Panics otherwise.
#[inline]
pub fn hex_encode_into(bytes: &[u8], buf: &mut [u8], offset: usize) -> usize {
    let hex_len = bytes.len() * 2;
    assert!(
        buf.len() >= offset + hex_len,
        "hex_encode_into: buffer too small ({} < {})",
        buf.len(),
        offset + hex_len,
    );
    let dest = &mut buf[offset..offset + hex_len];
    for (i, &byte) in bytes.iter().enumerate() {
        dest[i * 2] = HEX_LUT[(byte >> 4) as usize];
        dest[i * 2 + 1] = HEX_LUT[(byte & 0x0f) as usize];
    }
    hex_len
}

/// Stack-allocated lowercase hex representation of a Git object ID.
///
/// Git OIDs are 20 bytes (SHA-1) or 32 bytes (SHA-256), producing hex
/// strings of 40 or 64 characters respectively. `HexOid` stores the hex
/// in a fixed `[u8; 64]` buffer with a length discriminant, avoiding heap
/// allocation entirely.
///
/// Implements `Display`, `Debug`, `AsRef<str>`, and `Deref<Target = str>`
/// so it can be used anywhere a `&str` is expected.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct HexOid {
    buf: [u8; Self::MAX_HEX_LEN],
    len: u8,
}

impl HexOid {
    /// Maximum hex output length: SHA-256 OID = 32 bytes = 64 hex chars.
    pub const MAX_HEX_LEN: usize = 64;

    /// Encode raw OID bytes into a stack-resident hex string.
    ///
    /// # Panics
    ///
    /// Panics if `oid_bytes.len() > 32` (i.e. hex output would exceed 64).
    #[must_use]
    pub fn from_oid_bytes(oid_bytes: &[u8]) -> Self {
        let hex_len = oid_bytes.len() * 2;
        assert!(
            hex_len <= Self::MAX_HEX_LEN,
            "OID too large for HexOid: {} bytes",
            oid_bytes.len(),
        );
        let mut buf = [0u8; Self::MAX_HEX_LEN];
        hex_encode_into(oid_bytes, &mut buf, 0);
        Self {
            buf,
            len: hex_len as u8,
        }
    }

    /// View the hex content as a `&str`.
    #[inline]
    #[must_use]
    pub fn as_str(&self) -> &str {
        // SAFETY: hex_encode_into only writes ASCII hex digits (0-9, a-f),
        // which are valid UTF-8.
        unsafe { std::str::from_utf8_unchecked(&self.buf[..self.len as usize]) }
    }
}

impl std::ops::Deref for HexOid {
    type Target = str;

    #[inline]
    fn deref(&self) -> &str {
        self.as_str()
    }
}

impl AsRef<str> for HexOid {
    #[inline]
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for HexOid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Debug for HexOid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HexOid(\"{}\")", self.as_str())
    }
}

impl PartialEq<str> for HexOid {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl PartialEq<&str> for HexOid {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_oid_sha1_20_bytes() {
        let oid = HexOid::from_oid_bytes(&[0u8; 20]);
        assert_eq!(oid.as_str().len(), 40);
        assert_eq!(oid.as_str(), "0000000000000000000000000000000000000000");
    }

    #[test]
    fn hex_oid_sha256_32_bytes() {
        let oid = HexOid::from_oid_bytes(&[0xffu8; 32]);
        assert_eq!(oid.as_str().len(), 64);
        assert_eq!(
            oid.as_str(),
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        );
    }

    #[test]
    fn hex_oid_empty_input() {
        let oid = HexOid::from_oid_bytes(&[]);
        assert_eq!(oid.as_str(), "");
        assert_eq!(oid.as_str().len(), 0);
    }

    #[test]
    fn hex_oid_known_value() {
        let oid = HexOid::from_oid_bytes(&[0xCA, 0xFE]);
        assert_eq!(oid.as_str(), "cafe");
    }

    #[test]
    fn hex_oid_display_and_debug() {
        let oid = HexOid::from_oid_bytes(&[0xAB, 0xCD]);
        assert_eq!(format!("{oid}"), "abcd");
        assert_eq!(format!("{oid:?}"), "HexOid(\"abcd\")");
    }

    #[test]
    fn hex_oid_partial_eq_str() {
        let oid = HexOid::from_oid_bytes(&[0xCA, 0xFE]);
        assert_eq!(oid, *"cafe");
        assert_eq!(oid, "cafe");
    }

    #[test]
    fn hex_oid_deref_to_str() {
        let oid = HexOid::from_oid_bytes(&[0xDE, 0xAD]);
        let s: &str = &oid;
        assert_eq!(s, "dead");
    }

    #[test]
    #[should_panic(expected = "OID too large")]
    fn hex_oid_oversized_panics() {
        let _ = HexOid::from_oid_bytes(&[0u8; 33]);
    }

    #[test]
    fn hex_encode_into_correctness() {
        let mut buf = [0u8; 8];
        let written = hex_encode_into(&[0xAB, 0xCD, 0xEF, 0x01], &mut buf, 0);
        assert_eq!(written, 8);
        assert_eq!(&buf, b"abcdef01");
    }

    #[test]
    #[should_panic(expected = "buffer too small")]
    fn hex_encode_into_buffer_too_small_panics() {
        let mut buf = [0u8; 3];
        hex_encode_into(&[0xAB, 0xCD], &mut buf, 0);
    }
}

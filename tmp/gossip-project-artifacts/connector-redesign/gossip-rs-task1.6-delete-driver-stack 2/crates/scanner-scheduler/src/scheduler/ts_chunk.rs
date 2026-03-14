//! Sendable Chunk Wrapper
//!
//! # Purpose
//!
//! Pairs a buffer handle with chunk metadata using scanner naming conventions:
//! - `base_offset`: Absolute offset of `data()[0]` (includes overlap prefix)
//! - `prefix_len`: Overlap bytes at the front from previous chunk
//! - `buf_offset`: Offset into underlying buffer where chunk data starts
//!
//! # Thread Safety
//!
//! `TsChunk` is both `Send` and `Sync` (all fields are `Send + Sync`).
//! It can be moved across threads (e.g., from I/O completion to worker)
//! and shared via `&` references. The typical usage pattern is exclusive
//! ownership per worker, but the type does not restrict shared access.
//!
//! # Memory Layout
//!
//! ```text
//! Buffer: [padding...][prefix][payload]
//!         ^           ^       ^
//!         |           |       +-- new_bytes_start()
//!         |           +---------- data() starts here (base_offset)
//!         +---------------------- buf.as_slice() starts here
//!
//! buf_offset = offset from buffer start to data()[0]
//! prefix_len = overlap bytes from previous chunk
//! len = total bytes in data() (prefix + payload)
//! ```
//!
//! # Size
//!
//! ```text
//! TsChunk<u64> layout (64-bit):
//!   id:          8 bytes (u64)
//!   base_offset: 8 bytes (u64)
//!   len:         4 bytes (u32)
//!   prefix_len:  4 bytes (u32)
//!   buf_offset:  4 bytes (u32)
//!   [padding]:   4 bytes
//!   buf:        24 bytes (TsBufferHandle)
//!   ─────────────────────
//!   Total:      56 bytes (fits in one cache line)
//! ```
//!
//! All metadata + buffer pointer fetched in one memory access.
//!
//! # Scanner Contract Compatibility
//!
//! - `data()` returns the full slice including overlap prefix
//! - `payload()` returns only the new bytes (excludes prefix)
//! - `new_bytes_start()` returns absolute offset of first new byte
//!
//! # Fail-Fast Construction
//!
//! All invariants are validated at construction time via `TsChunk::new()`.
//! This ensures bugs are caught at the producer (I/O stage), not the consumer
//! (scanner), making debugging significantly easier.
//!
//! # Ownership
//!
//! `TsChunk` owns the `TsBufferHandle`. When the chunk is dropped,
//! the buffer is automatically returned to the pool.

use crate::scheduler::ts_buffer_pool::TsBufferHandle;

// ============================================================================
// TsChunk
// ============================================================================

/// Chunk with buffer ownership.
///
/// # Type Parameters
///
/// - `Id`: Object identifier type (e.g., `u64`, `ObjectId`). Must be `Copy`.
///
/// # Construction
///
/// Use `TsChunk::new()` which validates all invariants immediately.
/// Invalid parameters cause an immediate panic at the construction site,
/// not later when `data()` or `payload()` is called.
///
/// # Invariants (checked at construction)
///
/// - `prefix_len <= len`
/// - `buf_offset + len <= buf.len()`
/// - `base_offset + len` does not overflow `u64`
///
/// The first two checks use `assert!` and fire in all builds; the overflow
/// check uses `debug_assert!` and is elided in release builds.
pub struct TsChunk<Id: Copy> {
    /// Object identifier this chunk belongs to.
    id: Id,

    /// Absolute offset of `data()[0]` within the source object.
    ///
    /// This includes the overlap prefix, so:
    /// - First chunk of object starting at 0: `base_offset = 0`
    /// - Subsequent chunks: `base_offset = prev_end - overlap`
    /// - Partial/range scans: `base_offset` may be non-zero even for first chunk
    base_offset: u64,

    /// Total length of data in this chunk (prefix + payload).
    len: u32,

    /// Overlap prefix length (bytes from previous chunk).
    ///
    /// For the first chunk of an object (no prior context), this is 0.
    prefix_len: u32,

    /// Offset into buffer where chunk data starts.
    ///
    /// Typically 0 unless the buffer has leading padding (e.g., for SIMD alignment).
    buf_offset: u32,

    /// Owned buffer handle.
    buf: TsBufferHandle,
}

impl<Id: Copy> TsChunk<Id> {
    /// Construct a new chunk with immediate invariant validation.
    ///
    /// # Panics
    ///
    /// Panics immediately if any invariant is violated:
    /// - `prefix_len > len`: Prefix cannot exceed total length
    /// - `buf_offset + len > buf.len()`: Data would exceed buffer bounds
    /// - `base_offset + len` overflows: Would corrupt offset calculations
    ///
    /// # Why Fail-Fast?
    ///
    /// Validating at construction ensures bugs are caught at the producer
    /// (I/O stage) with a clear stack trace, not 50ms later at the consumer
    /// (scanner) where the root cause is obscured.
    pub fn new(
        id: Id,
        base_offset: u64,
        len: u32,
        prefix_len: u32,
        buf_offset: u32,
        buf: TsBufferHandle,
    ) -> Self {
        // Invariant 1: Prefix fits within data
        assert!(
            prefix_len <= len,
            "TsChunk: prefix_len ({}) > len ({})",
            prefix_len,
            len
        );

        // Invariant 2: Data fits within buffer
        let data_end = buf_offset as usize + len as usize;
        assert!(
            data_end <= buf.len(),
            "TsChunk: buf_offset ({}) + len ({}) = {} exceeds buffer length ({})",
            buf_offset,
            len,
            data_end,
            buf.len()
        );

        // Invariant 3: Offset calculations won't overflow
        // In practice, objects are never close to u64::MAX, but check anyway.
        debug_assert!(
            base_offset.checked_add(len as u64).is_some(),
            "TsChunk: base_offset + len would overflow u64"
        );

        Self {
            id,
            base_offset,
            len,
            prefix_len,
            buf_offset,
            buf,
        }
    }

    /// Object identifier this chunk belongs to.
    #[inline]
    pub fn id(&self) -> Id {
        self.id
    }

    /// Absolute offset of `data()[0]` within the source object.
    #[inline]
    pub fn base_offset(&self) -> u64 {
        self.base_offset
    }

    /// Total length of data in this chunk (prefix + payload).
    #[inline]
    pub fn len(&self) -> u32 {
        self.len
    }

    /// Returns true if this chunk has no data.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Overlap prefix length (bytes from previous chunk).
    #[inline]
    pub fn prefix_len(&self) -> u32 {
        self.prefix_len
    }

    /// Offset into buffer where chunk data starts.
    #[inline]
    pub fn buf_offset(&self) -> u32 {
        self.buf_offset
    }

    /// Full chunk data including overlap prefix.
    ///
    /// ```text
    /// |<------- data() ------->|
    /// [prefix][payload]
    /// ```
    ///
    /// # Performance
    ///
    /// Single slice operation; bounds are safe because invariants are checked at construction.
    #[inline]
    pub fn data(&self) -> &[u8] {
        let start = self.buf_offset as usize;
        let end = start + self.len as usize;
        // Safety: Bounds verified in constructor
        &self.buf.as_slice()[start..end]
    }

    /// Payload only (excludes overlap prefix).
    ///
    /// ```text
    /// [prefix][payload]
    ///         |<----->|  <- payload()
    /// ```
    ///
    /// This is the portion containing new bytes not seen in previous chunks.
    #[inline]
    pub fn payload(&self) -> &[u8] {
        let start = self.buf_offset as usize + self.prefix_len as usize;
        let end = self.buf_offset as usize + self.len as usize;
        // Safety: prefix_len <= len verified in constructor
        &self.buf.as_slice()[start..end]
    }

    /// Absolute offset of first new byte (after overlap prefix).
    ///
    /// This is where bytes from this chunk should be attributed in results.
    #[inline]
    pub fn new_bytes_start(&self) -> u64 {
        self.base_offset + self.prefix_len as u64
    }

    /// Absolute offset of last byte + 1.
    ///
    /// Useful for calculating next chunk's base_offset with overlap.
    #[inline]
    pub fn end_offset(&self) -> u64 {
        self.base_offset + self.len as u64
    }

    /// Length of payload (new bytes) in this chunk.
    ///
    /// # Invariant
    ///
    /// Always returns `len - prefix_len`. Since `prefix_len <= len` is
    /// enforced at construction, this never underflows.
    #[inline]
    pub fn payload_len(&self) -> u32 {
        // No saturating_sub: invariant enforced at construction
        self.len - self.prefix_len
    }

    /// Check if this is the first chunk of an object (no overlap prefix).
    ///
    /// # Semantics
    ///
    /// "First" means "no prior chunk context needed for scanning", not "starts at
    /// byte 0". This distinction matters for:
    ///
    /// - **Full object scan**: `is_first() == true` and `base_offset() == 0`
    /// - **Partial/range scan**: `is_first() == true` but `base_offset() > 0`
    /// - **Continuation chunk**: `is_first() == false` (has overlap prefix)
    #[inline]
    pub fn is_first(&self) -> bool {
        self.prefix_len == 0
    }

    /// Check if a byte index within `data()` falls in the new bytes region.
    ///
    /// Useful for deduplication: only report matches whose start is in new bytes.
    ///
    /// # Arguments
    ///
    /// - `index_in_data`: Index relative to `data()[0]` (not buffer or absolute offset)
    ///
    /// # Returns
    ///
    /// `true` if `index_in_data >= prefix_len` (i.e., the byte is in payload).
    #[inline]
    pub fn is_new_byte(&self, index_in_data: usize) -> bool {
        index_in_data >= self.prefix_len as usize
    }

    /// Range of new bytes within `data()`.
    ///
    /// Returns `prefix_len..len` as a range suitable for iteration or slicing.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let new_bytes = &chunk.data()[chunk.new_range_in_data()];
    /// assert_eq!(new_bytes, chunk.payload());
    /// ```
    #[inline]
    pub fn new_range_in_data(&self) -> std::ops::Range<usize> {
        self.prefix_len as usize..self.len as usize
    }

    /// Convert a match offset within `data()` to an absolute file offset.
    ///
    /// # Arguments
    ///
    /// - `index_in_data`: Index relative to `data()[0]`
    ///
    /// # Returns
    ///
    /// Absolute offset within the source object: `base_offset + index_in_data`
    #[inline]
    pub fn to_absolute_offset(&self, index_in_data: usize) -> u64 {
        self.base_offset + index_in_data as u64
    }

    /// Consume the chunk and return the underlying buffer handle.
    ///
    /// Use this when you need to reuse the buffer for another chunk
    /// without returning it to the pool.
    #[inline]
    pub fn into_buffer(self) -> TsBufferHandle {
        self.buf
    }

    /// Borrow the underlying buffer handle.
    #[inline]
    pub fn buffer(&self) -> &TsBufferHandle {
        &self.buf
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheduler::ts_buffer_pool::{TsBufferPool, TsBufferPoolConfig};

    fn test_pool() -> TsBufferPool {
        TsBufferPool::new(TsBufferPoolConfig {
            buffer_len: 1024,
            total_buffers: 4,
            workers: 1,
            local_queue_cap: 4,
        })
    }

    #[test]
    fn first_chunk_no_prefix() {
        let pool = test_pool();
        let mut buf = pool.acquire();

        // Write test data
        buf.as_mut_slice()[..10].copy_from_slice(b"0123456789");

        let chunk = TsChunk::new(42u64, 0, 10, 0, 0, buf);

        assert_eq!(chunk.id(), 42);
        assert_eq!(chunk.data(), b"0123456789");
        assert_eq!(chunk.payload(), b"0123456789");
        assert_eq!(chunk.new_bytes_start(), 0);
        assert_eq!(chunk.end_offset(), 10);
        assert_eq!(chunk.payload_len(), 10);
        assert!(chunk.is_first());
    }

    #[test]
    fn chunk_with_overlap_prefix() {
        let pool = test_pool();
        let mut buf = pool.acquire();

        // Simulate: "abc" is overlap from previous chunk, "defgh" is new
        buf.as_mut_slice()[..8].copy_from_slice(b"abcdefgh");

        let chunk = TsChunk::new(
            42u64, 97, // Previous chunk ended at 100, overlap=3
            8,  // len
            3,  // prefix_len
            0,  // buf_offset
            buf,
        );

        assert_eq!(chunk.data(), b"abcdefgh");
        assert_eq!(chunk.payload(), b"defgh");
        assert_eq!(chunk.new_bytes_start(), 100);
        assert_eq!(chunk.end_offset(), 105);
        assert_eq!(chunk.payload_len(), 5);
        assert!(!chunk.is_first());
    }

    #[test]
    fn chunk_with_buffer_offset() {
        let pool = test_pool();
        let mut buf = pool.acquire();

        // Data starts at offset 16 in buffer (e.g., for alignment padding)
        let data_start = 16usize;
        buf.as_mut_slice()[data_start..data_start + 6].copy_from_slice(b"HELLO!");

        let chunk = TsChunk::new(1u64, 0, 6, 0, 16, buf);

        assert_eq!(chunk.data(), b"HELLO!");
        assert_eq!(chunk.payload(), b"HELLO!");
        assert_eq!(chunk.buf_offset(), 16);
    }

    #[test]
    fn chunk_returns_buffer_on_drop() {
        let pool = test_pool();

        {
            let buf = pool.acquire();
            let _chunk = TsChunk::new(1u64, 0, 0, 0, 0, buf);
            // _chunk dropped here
        }

        // Buffer should be back in pool - we can acquire 4 buffers
        let _a = pool.acquire();
        let _b = pool.acquire();
        let _c = pool.acquire();
        let _d = pool.acquire();
    }

    #[test]
    fn generic_id_types() {
        let pool = test_pool();

        // u64 id
        let buf1 = pool.acquire();
        let c1 = TsChunk::new(123u64, 0, 0, 0, 0, buf1);
        assert_eq!(c1.id(), 123u64);

        // Custom id type
        #[derive(Clone, Copy, Debug, PartialEq)]
        struct ObjectId(u32, u16);

        let buf2 = pool.acquire();
        let c2 = TsChunk::new(ObjectId(1, 2), 0, 0, 0, 0, buf2);
        assert_eq!(c2.id(), ObjectId(1, 2));
    }

    #[test]
    fn is_new_byte_classification() {
        let pool = test_pool();
        let mut buf = pool.acquire();
        buf.as_mut_slice()[..10].copy_from_slice(b"0123456789");

        let chunk = TsChunk::new(0u64, 0, 10, 3, 0, buf);

        // Indices 0, 1, 2 are in prefix (old bytes)
        assert!(!chunk.is_new_byte(0));
        assert!(!chunk.is_new_byte(1));
        assert!(!chunk.is_new_byte(2));

        // Indices 3+ are in payload (new bytes)
        assert!(chunk.is_new_byte(3));
        assert!(chunk.is_new_byte(9));
    }

    #[test]
    fn new_range_in_data() {
        let pool = test_pool();
        let mut buf = pool.acquire();
        buf.as_mut_slice()[..10].copy_from_slice(b"0123456789");

        let chunk = TsChunk::new(0u64, 0, 10, 3, 0, buf);

        let range = chunk.new_range_in_data();
        assert_eq!(range, 3..10);
        assert_eq!(&chunk.data()[range], chunk.payload());
    }

    #[test]
    fn to_absolute_offset() {
        let pool = test_pool();
        let buf = pool.acquire();

        let chunk = TsChunk::new(0u64, 1000, 100, 10, 0, buf);

        // Index 0 in data() -> absolute 1000
        assert_eq!(chunk.to_absolute_offset(0), 1000);
        // Index 50 in data() -> absolute 1050
        assert_eq!(chunk.to_absolute_offset(50), 1050);
    }

    #[test]
    fn into_buffer_transfers_ownership() {
        let pool = test_pool();
        let buf = pool.acquire();
        let ptr = buf.ptr_usize();

        let chunk = TsChunk::new(0u64, 0, 0, 0, 0, buf);
        let recovered = chunk.into_buffer();

        // Same underlying buffer
        assert_eq!(recovered.ptr_usize(), ptr);
    }

    #[test]
    fn partial_scan_first_chunk_nonzero_base() {
        // Simulating a range scan starting at offset 5000
        let pool = test_pool();
        let buf = pool.acquire();

        let chunk = TsChunk::new(
            0u64, 5000, // Non-zero base offset (partial scan)
            100, 0, // No prefix (first chunk of this range)
            0, buf,
        );

        // Should be "first" because no prefix, even though base_offset != 0
        assert!(chunk.is_first());
        assert_eq!(chunk.base_offset(), 5000);
        assert_eq!(chunk.new_bytes_start(), 5000);
    }

    // ========================================================================
    // Fail-fast construction tests
    // ========================================================================

    #[test]
    #[should_panic(expected = "prefix_len (10) > len (5)")]
    fn construction_rejects_prefix_exceeds_len() {
        let pool = test_pool();
        let buf = pool.acquire();

        // This should panic immediately, not later when payload() is called
        let _chunk = TsChunk::new(0u64, 0, 5, 10, 0, buf);
    }

    #[test]
    #[should_panic(expected = "exceeds buffer length")]
    fn construction_rejects_data_exceeds_buffer() {
        let pool = test_pool();
        let buf = pool.acquire(); // 1024 bytes

        // buf_offset=1000, len=100 -> end=1100 > 1024
        let _chunk = TsChunk::new(0u64, 0, 100, 0, 1000, buf);
    }

    #[test]
    #[should_panic(expected = "exceeds buffer length")]
    fn construction_rejects_buf_offset_at_end() {
        let pool = test_pool();
        let buf = pool.acquire(); // 1024 bytes

        // buf_offset=1024 (at end), len=1 -> exceeds
        let _chunk = TsChunk::new(0u64, 0, 1, 0, 1024, buf);
    }

    #[test]
    fn construction_accepts_zero_length() {
        let pool = test_pool();
        let buf = pool.acquire();

        // Zero-length chunk is valid (e.g., empty file)
        let chunk = TsChunk::new(0u64, 0, 0, 0, 0, buf);
        assert_eq!(chunk.data().len(), 0);
        assert_eq!(chunk.payload().len(), 0);
    }

    #[test]
    fn construction_accepts_exact_fit() {
        let pool = test_pool();
        let buf = pool.acquire(); // 1024 bytes

        // Exactly fills buffer
        let chunk = TsChunk::new(0u64, 0, 1024, 0, 0, buf);
        assert_eq!(chunk.data().len(), 1024);
    }
}

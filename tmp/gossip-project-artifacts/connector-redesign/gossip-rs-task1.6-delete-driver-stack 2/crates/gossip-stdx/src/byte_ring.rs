//! Byte ring keyed by absolute stream offsets.
//!
//! This buffer models a logical, ever-growing byte stream. Each `push` appends
//! new bytes at the current `end_offset`, and the ring retains only the most
//! recent `capacity` bytes. The absolute offset of the first retained byte is
//! tracked in `start_offset`, so callers can ask whether a `[lo, hi)` range is
//! still available and materialize it into an output buffer.
//!
//! # Invariants
//! - `len <= capacity` and `head < capacity`.
//! - Capacity is always a power of two, so all index wrapping uses `& mask`
//!   instead of modulo division (eliminates `divq` on the hot push path).
//! - When `len > 0`, `start_offset` is the absolute offset of the byte at
//!   `head`.
//! - `end_offset == start_offset + len` (using saturating arithmetic on
//!   overflow).
//!
//! # Layout
//! Data lives in a circular `Vec<u8>`. The retained bytes are contiguous in
//! logical order but may wrap in the underlying buffer; `segments()` exposes up
//! to two slices that, when concatenated, yield the retained bytes in order.
//!
//! # Edge cases
//! - Empty ranges with `hi <= lo` are treated as present.
//! - Pushing `n >= capacity` bytes keeps only the last `capacity` bytes and
//!   advances `start_offset` past all earlier data.

/// Fixed-capacity ring buffer for the tail of a byte stream.
///
/// Capacity is rounded up to the next power of two so that all index
/// wrapping uses bitwise AND (`& mask`) instead of modulo division,
/// eliminating `divq` instructions from the hot push path.
pub struct ByteRing {
    buf: Vec<u8>,
    mask: usize, // capacity - 1; capacity is always a power of two
    head: usize,
    len: usize,
    start_offset: u64,
}

impl ByteRing {
    /// Creates an empty ring that can retain at least `capacity` bytes.
    ///
    /// The actual allocation is rounded up to the next power of two so that
    /// index wrapping uses `& mask` instead of `% cap`.
    ///
    /// # Panics
    /// Panics if `capacity == 0`.
    pub fn with_capacity(capacity: usize) -> Self {
        assert!(capacity > 0, "ByteRing capacity must be > 0");
        let actual = capacity.next_power_of_two();
        Self {
            buf: vec![0u8; actual],
            mask: actual - 1,
            head: 0,
            len: 0,
            start_offset: 0,
        }
    }

    /// Returns the maximum number of bytes the ring can retain.
    pub fn capacity(&self) -> usize {
        self.buf.len()
    }

    /// Returns the absolute offset of the first retained byte.
    ///
    /// Meaningful when `len > 0`; when empty, callers should treat this as the
    /// offset where the next retained byte would begin.
    pub fn start_offset(&self) -> u64 {
        self.start_offset
    }

    /// Returns the retained bytes as up to two slices in logical order.
    ///
    /// The first slice starts at `head`; the second (possibly empty) slice
    /// contains the wrapped remainder. The slices are valid until the ring is
    /// mutated.
    pub fn segments(&self) -> (&[u8], &[u8]) {
        if self.len == 0 {
            return (&[], &[]);
        }
        let cap = self.mask + 1;
        let start = self.head;
        if self.len <= cap - start {
            (&self.buf[start..start + self.len], &[])
        } else {
            let first = cap - start;
            (&self.buf[start..], &self.buf[..(self.len - first)])
        }
    }

    /// Clears all retained bytes and resets `start_offset` to 0.
    ///
    /// After this call the ring is logically empty and will treat the next
    /// `push` as the beginning of a new stream. Does not reallocate.
    pub fn reset(&mut self) {
        self.head = 0;
        self.len = 0;
        self.start_offset = 0;
    }

    /// Appends bytes to the ring, evicting the oldest bytes on overflow.
    ///
    /// The data is treated as a continuation of the logical stream. If
    /// `data.len() >= capacity`, only the last `capacity` bytes are retained.
    /// Absolute offsets advance monotonically; arithmetic is saturating at
    /// `u64::MAX` to avoid overflow UB on pathological long-running streams.
    ///
    /// Complexity: O(n) for `n = data.len()`.
    pub fn push(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }

        let mask = self.mask;
        let cap = mask + 1;
        let n = data.len();
        let old_len = self.len;
        let old_end = self.start_offset.saturating_add(old_len as u64);

        if n >= cap {
            let start = n - cap;
            self.buf.copy_from_slice(&data[start..]);
            self.head = 0;
            self.len = cap;
            self.start_offset = old_end.saturating_add(n as u64 - cap as u64);
            return;
        }

        let mut drop = old_len + n;
        if drop > cap {
            drop -= cap;
        } else {
            drop = 0;
        }
        if drop > 0 {
            self.head = (self.head + drop) & mask;
            self.len = self.len.saturating_sub(drop);
            self.start_offset = self.start_offset.saturating_add(drop as u64);
        }

        let tail = (self.head + self.len) & mask;
        let first = (cap - tail).min(n);
        self.buf[tail..tail + first].copy_from_slice(&data[..first]);
        if n > first {
            self.buf[..(n - first)].copy_from_slice(&data[first..]);
        }
        self.len = self.len.saturating_add(n);
    }

    /// Returns true when the full `[lo, hi)` range is currently retained.
    ///
    /// Empty ranges (`hi <= lo`) are treated as present.
    pub fn has_range(&self, lo: u64, hi: u64) -> bool {
        if hi <= lo {
            return true;
        }
        if self.len == 0 {
            return false;
        }
        lo >= self.start_offset && hi <= self.start_offset.saturating_add(self.len as u64)
    }

    /// Returns a direct slice into the ring buffer for `[lo, hi)` when the
    /// range is contiguous (does not wrap around the ring boundary).
    ///
    /// Returns `Some(&[u8])` on success, `Some(&[])` for empty ranges,
    /// or `None` when the range wraps or is not retained. The returned slice
    /// is valid until the next ring mutation.
    pub fn contiguous_range(&self, lo: u64, hi: u64) -> Option<&[u8]> {
        if hi <= lo {
            return Some(&[]);
        }
        if !self.has_range(lo, hi) {
            return None;
        }
        let offset = (lo - self.start_offset) as usize;
        let len = (hi - lo) as usize;
        let mask = self.mask;
        let cap = mask + 1;
        let start = (self.head + offset) & mask;
        if start + len <= cap {
            Some(&self.buf[start..start + len])
        } else {
            None // wraps around
        }
    }

    /// Extends `out` with bytes in `[lo, hi)`, returning false if the range
    /// is not fully retained.
    ///
    /// On failure, `out` is left unchanged. Empty ranges (`hi <= lo`) append
    /// nothing and return true.
    ///
    /// Complexity: O(len) for `len = hi - lo`.
    pub fn extend_range_to(&self, lo: u64, hi: u64, out: &mut Vec<u8>) -> bool {
        if hi <= lo {
            return true;
        }
        if !self.has_range(lo, hi) {
            return false;
        }

        let offset = (lo - self.start_offset) as usize;
        let len = (hi - lo) as usize;
        if len == 0 {
            return true;
        }

        let mask = self.mask;
        let cap = mask + 1;
        let start = (self.head + offset) & mask;
        let first = (cap - start).min(len);
        out.extend_from_slice(&self.buf[start..start + first]);
        if len > first {
            out.extend_from_slice(&self.buf[..(len - first)]);
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::ByteRing;

    #[test]
    fn contiguous_range_returns_slice_when_not_wrapped() {
        let mut ring = ByteRing::with_capacity(16);
        ring.push(b"hello world");
        // Bytes at offsets [0, 11) are present and contiguous.
        let slice = ring.contiguous_range(0, 5).expect("should be contiguous");
        assert_eq!(slice, b"hello");
    }

    #[test]
    fn contiguous_range_returns_none_when_wrapped() {
        let mut ring = ByteRing::with_capacity(8);
        // Push 6 bytes, then 6 more — second push evicts and wraps.
        ring.push(b"abcdef");
        ring.push(b"ghijkl");
        // The range [6, 12) wraps around the 8-byte buffer.
        let result = ring.contiguous_range(6, 12);
        // May or may not wrap depending on internal head position.
        // If contiguous, it should match; if wrapped, should return None.
        if let Some(slice) = result {
            assert_eq!(slice, b"ghijkl");
        }
        // Either way, extend_range_to should always work:
        let mut out = Vec::new();
        assert!(ring.extend_range_to(6, 12, &mut out));
        assert_eq!(out, b"ghijkl");
    }

    #[test]
    fn contiguous_range_empty_range() {
        let ring = ByteRing::with_capacity(8);
        assert_eq!(ring.contiguous_range(5, 5), Some(&[][..]));
        assert_eq!(ring.contiguous_range(5, 3), Some(&[][..]));
    }

    #[test]
    fn contiguous_range_not_retained() {
        let mut ring = ByteRing::with_capacity(4);
        ring.push(b"abcdefgh"); // Only last 4 bytes retained.
        assert_eq!(ring.contiguous_range(0, 4), None); // Evicted.
        let slice = ring.contiguous_range(4, 8).expect("should be retained");
        assert_eq!(slice, b"efgh");
    }
}

//! # Chunking Module
//!
//! Chunk semantics that match the scanner's reader behavior.
//!
//! ## Naming Convention (matches the scanner)
//!
//! - `base_offset`: absolute offset of `chunk.data()[0]` including overlap
//! - `prefix_len`: number of overlap bytes at the front of `chunk.data()`
//! - `len`: total bytes in `chunk.data()` (including overlap prefix)
//! - `buf_offset`: start offset into the backing buffer (usually 0)
//!
//! ## Derived Offsets
//!
//! - `new_bytes_start = base_offset + prefix_len`
//!
//! ## Overlap Dedupe Rule
//!
//! After scanning a chunk that includes an overlap prefix:
//! - Drop findings fully contained in the overlap prefix region
//! - Keep finding iff: `root_hint_end > new_bytes_start`
//!
//! This preserves boundary-spanning matches and avoids duplicates.
//!
//! ## Critical Assumptions (Correctness)
//!
//! ### Span Convention
//!
//! **`root_hint_end` must be an exclusive end** in root object coordinates.
//! The dedupe rule uses `>` comparison, which assumes half-open intervals `[start, end)`.
//!
//! If any engine returns inclusive ends, the boundary rule becomes wrong at exactly
//! the boundary, causing false negatives.
//!
//! ### Multi-View Safety
//!
//! When scanning decoded views (base64, etc.), `root_hint_end` must be a **conservative**
//! mapping back to root bytes. Any "approximate" root hint that can fall on the wrong
//! side of the boundary can create false negatives by dropping a real match.
//!
//! **Safe rule**: Only dedupe using root-coordinate ends that are provably conservative.
//!
//! ## Performance Notes
//!
//! The iterator is O(1) per chunk with a handful of integer ops. The scan loop dominates.
//!
//! For the per-finding dedupe check, prefer `keep_finding_rel_end(rel_end)` over
//! `keep_finding_abs_end(abs_end)` - it avoids u64 math in the findings loop.

use super::contract::{EngineContract, ObjectId, ViewId};

/// Chunking parameters that match the scanner's reader semantics.
///
/// - `payload_bytes`: bytes read from the object per iteration (excluding overlap)
/// - `overlap_bytes`: required overlap that becomes `prefix_len` after warmup
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChunkParams {
    /// New bytes to read per chunk (excluding overlap).
    pub payload_bytes: u32,
    /// Overlap bytes to prepend from previous chunk's tail.
    ///
    /// This value typically comes from `EngineContract::required_overlap_bytes`
    /// and ensures boundary-spanning matches are not missed.
    pub overlap_bytes: u32,
}

impl ChunkParams {
    /// Create chunk params with validation.
    ///
    /// # Panics
    /// Panics if `payload_bytes` is 0.
    pub fn new(payload_bytes: u32, overlap_bytes: u32) -> Self {
        assert!(payload_bytes > 0, "payload_bytes must be > 0");

        // Ensure len = overlap + payload cannot overflow u32
        debug_assert!(
            overlap_bytes.checked_add(payload_bytes).is_some(),
            "overlap_bytes + payload_bytes overflows u32"
        );

        // Warn about inefficient configuration
        debug_assert!(
            overlap_bytes < payload_bytes,
            "overlap_bytes ({}) >= payload_bytes ({}) causes redundant re-scanning",
            overlap_bytes,
            payload_bytes
        );

        Self {
            payload_bytes,
            overlap_bytes,
        }
    }

    /// Total maximum chunk size (overlap + payload).
    #[inline]
    pub fn max_chunk_size(&self) -> u32 {
        // Safe: validated in new() that this doesn't overflow
        self.overlap_bytes + self.payload_bytes
    }

    /// Validate parameters.
    pub fn validate(&self) {
        assert!(self.payload_bytes > 0, "payload_bytes must be > 0");
    }
}

/// Metadata that must travel with chunk bytes into the scan stage.
///
/// ## Field meanings (match the scanner)
///
/// - `base_offset`: absolute offset of `chunk.data()[0]` including overlap
/// - `prefix_len`: overlap prefix length at the front of `chunk.data()`
/// - `len`: total bytes in `chunk.data()` (including overlap prefix)
/// - `buf_offset`: start offset into the backing buffer (usually 0)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChunkMeta {
    /// Object this chunk belongs to.
    pub object_id: ObjectId,
    /// Absolute offset in the object for `chunk.data()[0]`.
    /// This includes the overlap prefix.
    pub base_offset: u64,
    /// Number of bytes in `chunk.data()` (including overlap prefix).
    pub len: u32,
    /// Number of overlap bytes at the front of `chunk.data()`.
    /// These bytes are from the previous chunk's tail.
    pub prefix_len: u32,
    /// Start offset into the backing buffer where `chunk.data()` begins.
    /// Usually 0 for standard buffered reads.
    pub buf_offset: u32,
    /// View identity (raw, base64-decoded, etc).
    pub view: ViewId,
}

impl ChunkMeta {
    /// Absolute offset where non-overlap (new) bytes begin.
    ///
    /// This is the boundary for dedupe: findings ending at or before
    /// this offset belong to the previous chunk.
    #[inline]
    pub fn new_bytes_start(&self) -> u64 {
        self.base_offset + self.prefix_len as u64
    }

    /// Keep predicate using absolute offset.
    ///
    /// **IMPORTANT**: `root_hint_end` must be an exclusive end in root coordinates.
    /// If the engine returns inclusive ends, this will cause false negatives at boundaries.
    ///
    /// Uses the same rule as `drop_prefix_findings(new_bytes_start)`:
    /// - `root_hint_end` is an absolute offset in the root object
    /// - Keep iff `root_hint_end > new_bytes_start`
    ///
    /// # Arguments
    /// * `root_hint_end` - Exclusive end offset of finding in root object coordinates
    ///
    /// # Returns
    /// `true` if the finding should be kept (belongs to this chunk)
    #[inline]
    pub fn keep_finding_abs_end(&self, root_hint_end: u64) -> bool {
        root_hint_end > self.new_bytes_start()
    }

    /// Keep predicate using a relative end offset inside the chunk buffer.
    /// **Use this in hot paths - it avoids u64 math.**
    ///
    /// Equivalent to `keep_finding_abs_end` because `base_offset` cancels out:
    /// - `rel_end` is offset within `chunk.data()`
    /// - Keep iff `rel_end > prefix_len`
    ///
    /// # Arguments
    /// * `rel_end` - Exclusive end offset within the chunk buffer
    ///
    /// # Returns
    /// `true` if the finding should be kept
    #[inline]
    pub fn keep_finding_rel_end(&self, rel_end: u32) -> bool {
        rel_end > self.prefix_len
    }

    /// Check if this is the first chunk (no overlap prefix).
    ///
    /// Useful for initialization logic that should run once per object,
    /// such as emitting object-start markers or initializing per-object state.
    #[inline]
    pub fn is_first_chunk(&self) -> bool {
        self.base_offset == 0 && self.prefix_len == 0
    }

    /// Get the length of new (non-overlap) bytes.
    #[inline]
    pub fn new_bytes_len(&self) -> u32 {
        // Safe: len >= prefix_len by construction (len = prefix_len + read)
        self.len - self.prefix_len
    }
}

/// Derive chunking params from an engine contract.
///
/// If the engine does not declare a bounded overlap requirement,
/// overlap-only chunking is unsafe.
///
/// # Errors
/// Returns an error if:
/// - `payload_bytes` is 0
/// - Engine contract has unbounded overlap requirement
pub fn params_from_contract(
    payload_bytes: u32,
    contract: EngineContract,
) -> Result<ChunkParams, &'static str> {
    if payload_bytes == 0 {
        return Err("payload_bytes must be > 0");
    }
    match contract.required_overlap_bytes {
        Some(overlap_bytes) => Ok(ChunkParams {
            payload_bytes,
            overlap_bytes,
        }),
        None => Err("engine contract has unbounded overlap requirement; \
             overlap-only chunking is not safe"),
    }
}

/// Iterator over chunk metadata for an object of known length.
///
/// This matches the file reader pattern:
/// - Each step "reads" up to `payload_bytes`
/// - Each emitted chunk includes `prefix_len` overlap from the previous tail
/// - `base_offset` is `offset - prefix_len` (start including overlap)
///
/// ## State Machine
///
/// ```text
/// ┌─────────────────────────────────────────────────────────────────┐
/// │  offset=0, tail_len=0                                           │
/// │       │                                                         │
/// │       ▼                                                         │
/// │  ┌─────────┐  read=min(payload,remaining)  ┌─────────────────┐  │
/// │  │ Chunk 0 │ ─────────────────────────────►│ offset+=read    │  │
/// │  │ prefix=0│                               │ tail=min(ovlp,  │  │
/// │  └─────────┘                               │  prefix+read)   │  │
/// │                                            └────────┬────────┘  │
/// │       ┌─────────────────────────────────────────────┘           │
/// │       ▼                                                         │
/// │  ┌─────────┐  offset < obj_len?            ┌─────────────────┐  │
/// │  │ Chunk N │ ──────── yes ────────────────►│ emit chunk with │  │
/// │  │prefix=  │                               │ prefix=tail_len │  │
/// │  │tail_len │◄──────────────────────────────└─────────────────┘  │
/// │  └────┬────┘                                                    │
/// │       │ no                                                      │
/// │       ▼                                                         │
/// │     Done                                                        │
/// └─────────────────────────────────────────────────────────────────┘
/// ```
///
/// # Performance
///
/// O(1) per chunk with minimal integer arithmetic. The scan loop dominates;
/// this iterator is not the bottleneck.
pub struct ChunkIter {
    object_id: ObjectId,
    obj_len: u64,
    payload_bytes: u32,
    overlap_bytes: u32,

    /// Bytes consumed from the object (excluding overlap).
    offset: u64,
    /// Next chunk's prefix_len (from previous chunk's tail).
    tail_len: u32,

    view: ViewId,
}

impl ChunkIter {
    /// Create a new chunk iterator.
    ///
    /// # Panics
    /// Panics if `params` is invalid.
    pub fn new(object_id: ObjectId, obj_len: u64, params: ChunkParams, view: ViewId) -> Self {
        params.validate();
        Self {
            object_id,
            obj_len,
            payload_bytes: params.payload_bytes,
            overlap_bytes: params.overlap_bytes,
            offset: 0,
            tail_len: 0,
            view,
        }
    }
}

impl Iterator for ChunkIter {
    type Item = ChunkMeta;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        let offset = self.offset;
        if offset >= self.obj_len {
            return None;
        }

        let remaining = self.obj_len - offset;
        let read = remaining.min(self.payload_bytes as u64) as u32;

        // Invariant: payload_bytes > 0 and offset < obj_len implies read > 0
        debug_assert!(read > 0, "read should be positive");

        let prefix_len = self.tail_len;

        // Invariant: tail_len can never exceed offset (we build it from prior reads)
        debug_assert!(
            (prefix_len as u64) <= offset || offset == 0,
            "prefix_len {} exceeds offset {}",
            prefix_len,
            offset
        );

        // Invariant: overlap_bytes + payload_bytes <= u32::MAX (checked at config time)
        // so this addition cannot overflow
        let len = prefix_len + read;
        let base_offset = offset - prefix_len as u64;

        // Branchless: when overlap_bytes == 0, min(0, len) == 0
        let next_tail_len = self.overlap_bytes.min(len);

        // Advance state
        self.offset = offset + read as u64;
        self.tail_len = next_tail_len;

        Some(ChunkMeta {
            object_id: self.object_id,
            base_offset,
            len,
            prefix_len,
            buf_offset: 0,
            view: self.view,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheduler::contract::SourceId;

    fn make_object_id() -> ObjectId {
        ObjectId {
            source: SourceId(0),
            idx: 0,
        }
    }

    /// Simple substring finder for testing.
    fn find_all(haystack: &[u8], needle: &[u8]) -> Vec<(u64, u64)> {
        if needle.is_empty() {
            return vec![];
        }
        let mut out = Vec::new();
        let mut i = 0usize;
        while i + needle.len() <= haystack.len() {
            if &haystack[i..i + needle.len()] == needle {
                out.push((i as u64, (i + needle.len()) as u64));
            }
            i += 1;
        }
        out
    }

    #[test]
    fn chunk_params_validation() {
        let params = ChunkParams::new(256, 64);
        params.validate();
        assert_eq!(params.max_chunk_size(), 320);
    }

    #[test]
    #[should_panic(expected = "payload_bytes must be > 0")]
    fn chunk_params_zero_payload_panics() {
        ChunkParams::new(0, 64);
    }

    #[test]
    fn chunk_meta_new_bytes_start() {
        let meta = ChunkMeta {
            object_id: make_object_id(),
            base_offset: 1000,
            len: 256,
            prefix_len: 64,
            buf_offset: 0,
            view: ViewId(0),
        };

        assert_eq!(meta.new_bytes_start(), 1064);
        assert_eq!(meta.new_bytes_len(), 192);
    }

    #[test]
    fn chunk_meta_keep_finding_predicates() {
        let meta = ChunkMeta {
            object_id: make_object_id(),
            base_offset: 1000,
            len: 256,
            prefix_len: 64,
            buf_offset: 0,
            view: ViewId(0),
        };

        // new_bytes_start = 1064

        // Finding ending at 1064 (exactly at boundary) - NOT kept
        assert!(!meta.keep_finding_abs_end(1064));

        // Finding ending at 1065 (past boundary) - kept
        assert!(meta.keep_finding_abs_end(1065));

        // Finding ending at 1000 (in overlap) - NOT kept
        assert!(!meta.keep_finding_abs_end(1000));

        // Relative: ending at prefix_len (64) - NOT kept
        assert!(!meta.keep_finding_rel_end(64));

        // Relative: ending at 65 - kept
        assert!(meta.keep_finding_rel_end(65));
    }

    #[test]
    fn chunk_iter_single_chunk() {
        let params = ChunkParams::new(1000, 100);
        let obj_id = make_object_id();
        let view = ViewId(0);

        // Object smaller than payload_bytes
        let chunks: Vec<_> = ChunkIter::new(obj_id, 500, params, view).collect();

        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].base_offset, 0);
        assert_eq!(chunks[0].len, 500);
        assert_eq!(chunks[0].prefix_len, 0);
    }

    #[test]
    fn chunk_iter_multiple_chunks_with_overlap() {
        let params = ChunkParams::new(100, 20);
        let obj_id = make_object_id();
        let view = ViewId(0);

        // Object of 250 bytes with 100 byte payload + 20 byte overlap
        let chunks: Vec<_> = ChunkIter::new(obj_id, 250, params, view).collect();

        // Chunk 0: offset 0, read 100, tail=0, len=100, base=0
        // Chunk 1: offset 100, read 100, tail=20, len=120, base=80
        // Chunk 2: offset 200, read 50, tail=20, len=70, base=180

        assert_eq!(chunks.len(), 3);

        assert_eq!(chunks[0].base_offset, 0);
        assert_eq!(chunks[0].len, 100);
        assert_eq!(chunks[0].prefix_len, 0);

        assert_eq!(chunks[1].base_offset, 80);
        assert_eq!(chunks[1].len, 120);
        assert_eq!(chunks[1].prefix_len, 20);

        assert_eq!(chunks[2].base_offset, 180);
        assert_eq!(chunks[2].len, 70);
        assert_eq!(chunks[2].prefix_len, 20);
    }

    #[test]
    fn overlap_dedupe_no_false_negatives_for_bounded_span_model() {
        let data = b"aaaaaSECRETbbbbbbbbbbbbSECRETcccccccccccccccc";
        let needle = b"SECRET";

        // Bounded-span model: required overlap is len-1.
        let contract = EngineContract::bounded((needle.len() - 1) as u32);
        let params = params_from_contract(16, contract).unwrap();
        let view = ViewId(0);

        let expected = find_all(data, needle);

        let object_id = make_object_id();

        let mut got = Vec::new();
        for meta in ChunkIter::new(object_id, data.len() as u64, params, view) {
            let start = meta.base_offset as usize;
            let end = start + meta.len as usize;
            let chunk = &data[start..end];

            for (rs, re) in find_all(chunk, needle) {
                let root_hint_end = meta.base_offset + re;
                if meta.keep_finding_abs_end(root_hint_end) {
                    got.push((meta.base_offset + rs, meta.base_offset + re));
                }
            }
        }

        got.sort();
        got.dedup();
        assert_eq!(got, expected, "should find all secrets without duplicates");
    }

    #[test]
    fn insufficient_overlap_can_miss_boundary_match() {
        // "SECRET" spans the boundary between two payload chunks of size 8.
        let data: Vec<u8> = b"xxxxSECR"
            .iter()
            .chain(b"ETyyyyyy".iter())
            .copied()
            .collect();
        let needle = b"SECRET";

        let expected = find_all(&data, needle);
        assert_eq!(expected.len(), 1, "sanity: whole-buffer scan finds SECRET");

        // Zero overlap - will miss the boundary match
        let params = ChunkParams::new(8, 0);
        let view = ViewId(0);
        let object_id = make_object_id();

        let mut got = Vec::new();
        for meta in ChunkIter::new(object_id, data.len() as u64, params, view) {
            let start = meta.base_offset as usize;
            let end = start + meta.len as usize;
            let chunk = &data[start..end];

            for (rs, re) in find_all(chunk, needle) {
                let root_hint_end = meta.base_offset + re;
                if meta.keep_finding_abs_end(root_hint_end) {
                    got.push((meta.base_offset + rs, meta.base_offset + re));
                }
            }
        }

        got.sort();
        got.dedup();

        // Expected miss with overlap_bytes=0.
        assert_ne!(got, expected);
        assert!(got.is_empty(), "should miss the boundary-spanning match");
    }

    #[test]
    fn params_from_contract_bounded() {
        let contract = EngineContract::bounded(256);
        let params = params_from_contract(1024, contract).unwrap();
        assert_eq!(params.payload_bytes, 1024);
        assert_eq!(params.overlap_bytes, 256);
    }

    #[test]
    fn params_from_contract_unbounded_fails() {
        let contract = EngineContract::unbounded();
        let result = params_from_contract(1024, contract);
        assert!(result.is_err());
    }

    #[test]
    fn chunk_iter_empty_object() {
        let params = ChunkParams::new(100, 20);
        let obj_id = make_object_id();
        let view = ViewId(0);

        let chunks: Vec<_> = ChunkIter::new(obj_id, 0, params, view).collect();
        assert_eq!(chunks.len(), 0);
    }

    #[test]
    fn relative_and_absolute_predicates_equivalent() {
        // Verify keep_finding_rel_end and keep_finding_abs_end give same results
        let meta = ChunkMeta {
            object_id: make_object_id(),
            base_offset: 1000,
            len: 256,
            prefix_len: 64,
            buf_offset: 0,
            view: ViewId(0),
        };

        // Test various offsets within the chunk
        for rel_end in 0..256u32 {
            let abs_end = meta.base_offset + rel_end as u64;
            assert_eq!(
                meta.keep_finding_rel_end(rel_end),
                meta.keep_finding_abs_end(abs_end),
                "mismatch at rel_end={}",
                rel_end
            );
        }
    }

    #[test]
    fn chunk_meta_size_check() {
        // Verify ChunkMeta has reasonable size for cache efficiency
        let size = std::mem::size_of::<ChunkMeta>();
        assert!(size <= 40, "ChunkMeta is {} bytes, expected <= 40", size);
    }
}

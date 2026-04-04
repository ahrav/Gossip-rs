//! Blob introduction walk for ODB-blob scan mode.
//!
//! This module traverses commits in topological order and discovers each
//! unique blob exactly once. It maintains seen-set bitmaps keyed by MIDX
//! indices so repeated trees/blobs are skipped without re-parsing.
//!
//! # Serial vs Parallel
//!
//! [`BlobIntroducer`] is the serial entry point — one thread processes all
//! commits sequentially using per-instance [`SeenSets`] (non-atomic
//! `DynamicBitSet`).
//!
//! [`introduce_parallel`] partitions the commit plan into chunks and
//! spawns multiple [`BlobIntroWorker`]s that share a single
//! [`AtomicSeenSets`]. Each tree/blob is claimed by exactly one worker
//! via `fetch_or` (mark-then-traverse), matching the GC mark-phase
//! architecture. Commit attribution is not a deterministic contract in
//! parallel mode (packed attribution is race-winner). For loose blobs,
//! per-worker duplicates are merged with deterministic context tie-breakers.
//! The blob SET is identical to the serial path.
//!
//! # Invariants
//! - Seen sets are sized from `midx.object_count` and never grow
//!   (the caller applies a capacity floor of 1 when the MIDX is empty
//!   because `AtomicSeenSets` panics on zero capacity).
//! - OID indices must be validated before use (caller responsibility).
//! - Tree and blob indices share the same index space but are tracked
//!   independently to avoid false positives.
//! - Paths are assembled in a reusable buffer and must not exceed
//!   `MAX_PATH_LEN`.
//! - In parallel mode, each tree/blob object is processed by exactly one
//!   worker (guaranteed by `AtomicBitSet::test_and_set` atomicity).

use crate::perf_stats;
use gossip_stdx::atomic_seen_sets::AtomicSeenSets;
use gossip_stdx::bitset::DynamicBitSet;

use super::byte_arena::ByteArena;
use super::errors::{MappingCandidateKind, TreeDiffError};
use super::midx::MidxView;
use super::object_id::OidBytes;
use super::object_store::{ObjectStore, ObjectStoreLayout, TreeBytes};
use super::oid_index::OidIndex;
use super::pack_candidates::{LooseCandidate, PackCandidate, PackCandidateCollector};
use super::path_policy::classify_path;
use super::repo_open::RepoJobState;
use super::runner::GitScanConfig;
use super::tree_candidate::{CandidateSink, ChangeKind};
use super::tree_delta_cache::TreeDeltaCache;
use super::tree_diff::TreeDiffStats;
use super::tree_diff_limits::TreeDiffLimits;
use super::tree_entry::{parse_entry, EntryKind, ParseOutcome, ParsedTreeEntry, TreeEntry};
use super::tree_stream::{TreeBytesReader, TreeStream};
use super::{CommitGraphIndex, PlannedCommit, TreeSource};

use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

const TREE_STREAM_BUF_BYTES: usize = 16 * 1024;
const MAX_PATH_LEN: usize = 4096;

/// Seen-set bitmaps for trees and blobs keyed by MIDX index.
///
/// Three independent bitsets are maintained:
/// - `trees` — tracks visited tree objects to skip entire subtrees.
/// - `blobs` — tracks emitted blob candidates (non-excluded).
/// - `blobs_excluded` — tracks blobs matched by path-exclusion policy.
///
/// Blobs and excluded blobs are tracked separately because a blob OID may
/// appear under both an excluded and a non-excluded path. If exclusion
/// shared the `blobs` set, the first encounter under an excluded path would
/// mark the blob as "seen" and suppress the legitimate non-excluded emit.
#[derive(Debug)]
pub struct SeenSets {
    trees: DynamicBitSet,
    blobs: DynamicBitSet,
    blobs_excluded: DynamicBitSet,
}

impl SeenSets {
    /// Creates empty seen sets sized to the MIDX object count.
    pub fn new(object_count: u32) -> Self {
        let bits = object_count as usize;
        Self {
            trees: DynamicBitSet::empty(bits),
            blobs: DynamicBitSet::empty(bits),
            blobs_excluded: DynamicBitSet::empty(bits),
        }
    }

    /// Clears all seen bits.
    pub fn clear(&mut self) {
        self.trees.clear();
        self.blobs.clear();
        self.blobs_excluded.clear();
    }

    /// Marks a tree index as seen, returning true if it was newly set.
    #[inline]
    pub fn mark_tree(&mut self, idx: u32) -> bool {
        let idx = idx as usize;
        if self.trees.is_set(idx) {
            false
        } else {
            self.trees.set(idx);
            true
        }
    }

    /// Marks a blob index as seen, returning true if it was newly set.
    #[inline]
    pub fn mark_blob(&mut self, idx: u32) -> bool {
        let idx = idx as usize;
        if self.blobs.is_set(idx) {
            false
        } else {
            self.blobs.set(idx);
            true
        }
    }

    /// Marks a blob index as excluded, returning true if it was newly set.
    #[inline]
    pub fn mark_blob_excluded(&mut self, idx: u32) -> bool {
        let idx = idx as usize;
        if self.blobs_excluded.is_set(idx) {
            false
        } else {
            self.blobs_excluded.set(idx);
            true
        }
    }

    /// Returns true if the tree index is already seen.
    #[inline]
    pub fn is_tree_seen(&self, idx: u32) -> bool {
        self.trees.is_set(idx as usize)
    }

    /// Returns true if the blob index is already seen.
    #[inline]
    pub fn is_blob_seen(&self, idx: u32) -> bool {
        self.blobs.is_set(idx as usize)
    }

    /// Returns true if the blob index is already marked excluded.
    #[inline]
    pub fn is_blob_excluded(&self, idx: u32) -> bool {
        self.blobs_excluded.is_set(idx as usize)
    }
}

/// Single slot in the [`LooseOidSet`] open-addressing hash table.
///
/// The `occupied` flag distinguishes empty slots from populated ones because
/// a zeroed `OidBytes` is a valid (if unlikely) key — the tag alone cannot
/// distinguish "never written" from "written with tag 0".
#[derive(Clone, Copy, Debug)]
struct LooseEntry {
    key: OidBytes,
    /// High byte of the hash; used for early rejection before full OID compare.
    tag: u8,
    occupied: bool,
}

impl LooseEntry {
    #[inline]
    fn empty() -> Self {
        Self {
            key: OidBytes::default(),
            tag: 0,
            occupied: false,
        }
    }
}

/// Fixed-capacity open-addressing hash set for loose OIDs.
///
/// Used for blobs not present in the MIDX (loose objects). The table uses
/// linear probing with a 70% load factor and power-of-two sizing for fast
/// modular indexing via bitmask. A one-byte tag (high bits of the hash)
/// provides early rejection before full 20/32-byte OID comparison.
///
/// The set is deliberately simple: no tombstones or deletion support,
/// matching the append-only nature of blob introduction.
#[derive(Debug)]
struct LooseOidSet {
    entries: Vec<LooseEntry>,
    mask: usize,
    len: u32,
    oid_len: u8,
    max_items: u32,
    kind: MappingCandidateKind,
}

impl LooseOidSet {
    fn new(max_items: u32, oid_len: u8, kind: MappingCandidateKind) -> Self {
        let max_items = max_items.max(1);
        let capacity = table_size_for_count(max_items as usize);
        Self {
            entries: vec![LooseEntry::empty(); capacity],
            mask: capacity - 1,
            len: 0,
            oid_len,
            max_items,
            kind,
        }
    }

    fn clear(&mut self) {
        self.entries.fill(LooseEntry::empty());
        self.len = 0;
    }

    fn contains(&self, oid: &OidBytes) -> bool {
        debug_assert_eq!(oid.len(), self.oid_len, "OID length mismatch");
        let hash = hash_oid(oid);
        let tag = (hash >> 56) as u8;
        let mut slot = (hash as usize) & self.mask;

        for _ in 0..self.entries.len() {
            let entry = &self.entries[slot];
            if !entry.occupied {
                return false;
            }
            if entry.tag == tag && entry.key == *oid {
                return true;
            }
            slot = (slot + 1) & self.mask;
        }

        false
    }

    fn insert(&mut self, oid: &OidBytes) -> Result<bool, TreeDiffError> {
        debug_assert_eq!(oid.len(), self.oid_len, "OID length mismatch");
        if self.len >= self.max_items {
            return Err(TreeDiffError::CandidateLimitExceeded {
                kind: self.kind,
                max: self.max_items,
                observed: self.len.saturating_add(1),
            });
        }

        let hash = hash_oid(oid);
        let tag = (hash >> 56) as u8;
        let mut slot = (hash as usize) & self.mask;

        for _ in 0..self.entries.len() {
            let entry = &mut self.entries[slot];
            if !entry.occupied {
                entry.key = *oid;
                entry.tag = tag;
                entry.occupied = true;
                self.len += 1;
                return Ok(true);
            }
            if entry.tag == tag && entry.key == *oid {
                return Ok(false);
            }
            slot = (slot + 1) & self.mask;
        }

        Err(TreeDiffError::CandidateLimitExceeded {
            kind: self.kind,
            max: self.max_items,
            observed: self.len.saturating_add(1),
        })
    }
}

/// Statistics for the blob introducer.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct BlobIntroStats {
    /// Number of commits visited.
    pub commits_visited: u64,
    /// Number of trees loaded.
    pub trees_loaded: u64,
    /// Total bytes loaded from trees.
    pub tree_bytes_loaded: u64,
    /// Peak in-flight tree bytes retained by the stack.
    pub tree_bytes_in_flight_peak: u64,
    /// Number of blobs emitted.
    pub blobs_emitted: u64,
    /// Number of subtrees skipped because the tree OID was already seen.
    pub subtrees_skipped: u64,
    /// Maximum stack depth reached.
    pub max_depth_reached: u16,
}

impl From<BlobIntroStats> for TreeDiffStats {
    fn from(stats: BlobIntroStats) -> Self {
        Self {
            trees_loaded: stats.trees_loaded,
            tree_bytes_loaded: stats.tree_bytes_loaded,
            tree_bytes_in_flight_peak: stats.tree_bytes_in_flight_peak,
            candidates_emitted: stats.blobs_emitted,
            subtrees_skipped: stats.subtrees_skipped,
            max_depth_reached: stats.max_depth_reached,
        }
    }
}

/// Reusable path builder for tree traversal.
///
/// Assembles file paths incrementally as the tree walk descends into
/// subtrees. Directory components are pushed via `push_dir` and popped
/// via `pop_dir`; leaf filenames are appended/removed with `push_leaf` /
/// `pop_leaf`. The `stack` records buffer positions at each directory
/// boundary so `pop_dir` can truncate back to the parent prefix.
///
/// Paths are capped at `MAX_PATH_LEN` bytes to bound memory and prevent
/// pathological trees from causing unbounded growth.
#[derive(Debug)]
struct PathBuilder {
    buf: Vec<u8>,
    stack: Vec<usize>,
}

impl PathBuilder {
    fn new(capacity: usize) -> Self {
        Self {
            buf: Vec::with_capacity(capacity),
            stack: Vec::with_capacity(64),
        }
    }

    fn clear(&mut self) {
        self.buf.clear();
        self.stack.clear();
    }

    fn push_dir(&mut self, name: &[u8]) -> Result<(), TreeDiffError> {
        let new_len = self.buf.len() + name.len() + 1;
        if new_len > MAX_PATH_LEN {
            return Err(TreeDiffError::PathTooLong {
                len: new_len,
                max: MAX_PATH_LEN,
            });
        }
        self.stack.push(self.buf.len());
        self.buf.extend_from_slice(name);
        self.buf.push(b'/');
        Ok(())
    }

    fn pop_dir(&mut self) {
        if let Some(len) = self.stack.pop() {
            self.buf.truncate(len);
        }
    }

    fn push_leaf(&mut self, name: &[u8]) -> Result<usize, TreeDiffError> {
        let new_len = self.buf.len() + name.len();
        if new_len > MAX_PATH_LEN {
            return Err(TreeDiffError::PathTooLong {
                len: new_len,
                max: MAX_PATH_LEN,
            });
        }
        let start = self.buf.len();
        self.buf.extend_from_slice(name);
        Ok(start)
    }

    fn pop_leaf(&mut self, start: usize) {
        self.buf.truncate(start);
    }

    #[inline]
    fn as_slice(&self) -> &[u8] {
        &self.buf
    }
}

/// Buffered tree cursor that holds the entire tree payload in memory.
///
/// Used for small trees (below `stream_threshold`) where the full payload
/// fits comfortably in the in-flight byte budget. Supports peek/advance
/// iteration with a one-entry lookahead cache: `peek_entry` parses and
/// caches the next entry; `advance` consumes it by bumping `pos`.
struct BufferedCursor {
    bytes: TreeBytes,
    pos: usize,
    oid_len: u8,
    cached: Option<ParsedTreeEntry>,
}

impl BufferedCursor {
    fn new(bytes: TreeBytes, oid_len: u8) -> Self {
        Self {
            bytes,
            pos: 0,
            oid_len,
            cached: None,
        }
    }

    fn peek_entry(&mut self) -> Result<Option<TreeEntry<'_>>, TreeDiffError> {
        if let Some(parsed) = self.cached {
            return Ok(Some(
                parsed.materialize(self.bytes.as_slice(), self.oid_len),
            ));
        }

        let data = self.bytes.as_slice();
        if self.pos >= data.len() {
            return Ok(None);
        }

        match parse_entry(&data[self.pos..], self.oid_len)? {
            ParseOutcome::Complete(mut parsed) => {
                parsed.offset_by(self.pos);
                self.cached = Some(parsed);
                Ok(Some(parsed.materialize(data, self.oid_len)))
            }
            ParseOutcome::Incomplete(stage) => Err(TreeDiffError::CorruptTree {
                detail: stage.error_detail(),
            }),
        }
    }

    fn advance(&mut self) -> Result<(), TreeDiffError> {
        if self.cached.is_none() {
            let _ = self.peek_entry()?;
        }
        if let Some(parsed) = self.cached.take() {
            self.pos = self.pos.saturating_add(parsed.entry_len);
        }
        Ok(())
    }

    fn in_flight_len(&self) -> usize {
        self.bytes.in_flight_len()
    }
}

/// Tree cursor selecting buffered vs streaming parsing.
///
/// Small trees (below `stream_threshold`) are kept fully in memory as a
/// `BufferedCursor` for random-access-friendly parsing. Large trees or
/// spilled trees use `TreeStream` to parse entries on demand without
/// buffering the entire payload, keeping the in-flight byte budget bounded.
enum TreeCursor {
    Buffered(BufferedCursor),
    Stream(TreeStream<TreeBytesReader>),
}

impl TreeCursor {
    fn new(bytes: TreeBytes, oid_len: u8, stream_threshold: usize) -> Self {
        let use_stream = bytes.len() >= stream_threshold || matches!(bytes, TreeBytes::Spilled(_));
        if use_stream {
            let reader = TreeBytesReader::new(bytes);
            let stream = TreeStream::new(reader, oid_len, TREE_STREAM_BUF_BYTES);
            Self::Stream(stream)
        } else {
            Self::Buffered(BufferedCursor::new(bytes, oid_len))
        }
    }

    fn peek_entry(&mut self) -> Result<Option<TreeEntry<'_>>, TreeDiffError> {
        match self {
            Self::Buffered(cursor) => cursor.peek_entry(),
            Self::Stream(stream) => stream.peek_entry(),
        }
    }

    fn advance(&mut self) -> Result<(), TreeDiffError> {
        match self {
            Self::Buffered(cursor) => cursor.advance(),
            Self::Stream(stream) => stream.advance(),
        }
    }

    fn in_flight_len(&self) -> u64 {
        match self {
            Self::Buffered(cursor) => cursor.in_flight_len() as u64,
            Self::Stream(stream) => stream.in_flight_len() as u64,
        }
    }
}

/// One level of the depth-first tree walk stack.
///
/// Each frame owns a [`TreeCursor`] for the tree at that depth and records
/// the tree's in-flight byte contribution so it can be subtracted from the
/// budget when the frame is popped.
struct TreeFrame {
    cursor: TreeCursor,
    /// Bytes charged to the in-flight budget for this tree.
    in_flight_len: u64,
}

/// Serial blob introducer: walks commits in plan order and discovers each
/// unique blob exactly once.
///
/// # Algorithm
///
/// For each commit, the root tree OID is resolved and walked depth-first.
/// At every tree/blob entry the MIDX index is checked:
///
/// - **Packed objects** (present in MIDX): deduped via the bitmap `SeenSets`.
/// - **Loose objects** (not in MIDX): deduped via the hash-based `LooseOidSet`.
///
/// Trees whose OID has already been visited are skipped entirely, pruning
/// the walk. Blobs whose path matches the exclusion policy are tracked
/// separately in `blobs_excluded` / `loose_excluded` to avoid suppressing
/// legitimate non-excluded paths for the same OID.
///
/// # Reusability
///
/// A single `BlobIntroducer` can be reused across multiple runs by calling
/// `reset_seen` (clears dedup state) and/or `reset_stats`. The transient
/// stack/path state is always cleaned up before `introduce` returns.
pub struct BlobIntroducer {
    max_depth: u16,
    oid_len: u8,
    path_builder: PathBuilder,
    name_scratch: Vec<u8>,
    stack: Vec<TreeFrame>,
    stats: BlobIntroStats,
    tree_bytes_in_flight_limit: u64,
    tree_bytes_in_flight: u64,
    stream_threshold: usize,
    seen: SeenSets,
    loose_seen: LooseOidSet,
    loose_excluded: LooseOidSet,
    // TODO: This should be configurabled. We want to be able to scan
    // binaries and also ignore certain file extensions.
    /// When true, skip the extension-based nonscannable filter so that
    /// binary-extension blobs reach the engine adapter for scanning.
    scan_binary: bool,
}

impl BlobIntroducer {
    /// Creates a new blob introducer sized to the MIDX object count.
    ///
    /// When `scan_binary` is true the extension-based nonscannable filter is
    /// disabled so that binary-extension blobs are emitted as candidates and
    /// reach the engine adapter for content scanning.
    pub fn new(
        limits: &TreeDiffLimits,
        oid_len: u8,
        object_count: u32,
        max_loose_oids: u32,
        scan_binary: bool,
    ) -> Self {
        assert!(
            oid_len == 20 || oid_len == 32,
            "OID length must be 20 or 32"
        );
        Self {
            max_depth: limits.max_tree_depth,
            oid_len,
            path_builder: PathBuilder::new(4096),
            name_scratch: Vec::with_capacity(256),
            stack: Vec::with_capacity(limits.max_tree_depth as usize),
            stats: BlobIntroStats::default(),
            tree_bytes_in_flight_limit: limits.max_tree_bytes_in_flight,
            tree_bytes_in_flight: 0,
            stream_threshold: limits.max_tree_cache_bytes.max(1) as usize,
            seen: SeenSets::new(object_count),
            loose_seen: LooseOidSet::new(max_loose_oids, oid_len, MappingCandidateKind::Loose),
            loose_excluded: LooseOidSet::new(max_loose_oids, oid_len, MappingCandidateKind::Loose),
            scan_binary,
        }
    }

    /// Returns the current stats.
    #[inline]
    pub fn stats(&self) -> &BlobIntroStats {
        &self.stats
    }

    /// Resets stats and in-flight accounting for a new run.
    ///
    /// Requires no in-flight traversal state; `introduce` clears that state
    /// before returning an error.
    pub fn reset_stats(&mut self) {
        debug_assert!(self.stack.is_empty(), "reset requires empty stack");
        self.stats = BlobIntroStats::default();
        self.tree_bytes_in_flight = 0;
    }

    /// Clears seen sets so the introducer can be re-run.
    pub fn reset_seen(&mut self) {
        self.seen.clear();
        self.loose_seen.clear();
        self.loose_excluded.clear();
    }

    /// Walks the commit plan and emits unique blob candidates.
    ///
    /// On error, clears traversal state so the introducer can be reused after
    /// handling the failure. Seen sets are preserved; call `reset_seen` if
    /// needed. The abort flag is checked before each commit and every 4096
    /// processed tree entries.
    ///
    /// # Errors
    ///
    /// Returns [`TreeDiffError`] on tree parse failures, capacity exhaustion,
    /// sink errors, or object-store faults. Returns
    /// [`TreeDiffError::Aborted`] if the cooperative abort flag is set.
    pub fn introduce<S: CandidateSink>(
        &mut self,
        source: &mut impl TreeSource,
        cg: &CommitGraphIndex,
        plan: &[PlannedCommit],
        oid_index: &OidIndex,
        abort: &AtomicBool,
        sink: &mut S,
    ) -> Result<BlobIntroStats, TreeDiffError> {
        self.reset_stats();

        let result = (|| {
            for PlannedCommit { pos, .. } in plan {
                if abort.load(Ordering::Relaxed) {
                    return Err(TreeDiffError::Aborted);
                }
                perf_stats::sat_add_u64(&mut self.stats.commits_visited, 1);
                let commit_id = pos.0;
                let root_oid = cg.root_tree_oid(*pos);

                if let Some(idx) = oid_index.get(&root_oid) {
                    if !self.seen.mark_tree(idx) {
                        perf_stats::sat_add_u64(&mut self.stats.subtrees_skipped, 1);
                        continue;
                    }
                }

                self.push_tree(source, &root_oid)?;
                self.walk_stack(source, oid_index, abort, sink, commit_id)?;
            }

            Ok(self.stats)
        })();

        if result.is_err() {
            self.reset_run_state();
        }

        result
    }

    /// Clears transient traversal state so a subsequent run can start cleanly.
    fn reset_run_state(&mut self) {
        self.stack.clear();
        self.path_builder.clear();
        self.tree_bytes_in_flight = 0;
    }

    fn push_tree(
        &mut self,
        source: &mut impl TreeSource,
        oid: &OidBytes,
    ) -> Result<(), TreeDiffError> {
        if self.stack.len() >= self.max_depth as usize {
            return Err(TreeDiffError::MaxTreeDepthExceeded {
                max_depth: self.max_depth,
            });
        }

        let bytes = source.load_tree(oid)?;
        perf_stats::sat_add_u64(&mut self.stats.trees_loaded, 1);
        perf_stats::sat_add_u64(&mut self.stats.tree_bytes_loaded, bytes.len() as u64);

        let cursor = TreeCursor::new(bytes, self.oid_len, self.stream_threshold);
        let in_flight_len = cursor.in_flight_len();
        let new_in_flight = self.tree_bytes_in_flight.saturating_add(in_flight_len);
        if new_in_flight > self.tree_bytes_in_flight_limit {
            return Err(TreeDiffError::TreeBytesBudgetExceeded {
                loaded: new_in_flight,
                budget: self.tree_bytes_in_flight_limit,
            });
        }
        self.tree_bytes_in_flight = new_in_flight;
        perf_stats::max_u64(
            &mut self.stats.tree_bytes_in_flight_peak,
            self.tree_bytes_in_flight,
        );

        self.stack.push(TreeFrame {
            cursor,
            in_flight_len,
        });
        perf_stats::max_u16(&mut self.stats.max_depth_reached, self.stack.len() as u16);
        Ok(())
    }

    fn pop_tree(&mut self) {
        if let Some(frame) = self.stack.pop() {
            self.tree_bytes_in_flight = self
                .tree_bytes_in_flight
                .saturating_sub(frame.in_flight_len);
        }
        self.path_builder.pop_dir();
    }

    /// Iteratively processes all tree frames on the stack, emitting blob
    /// candidates into `sink`.
    ///
    /// Uses the instance `SeenSets` for tree/blob dedup. On encountering a
    /// subtree, pushes a new frame; on exhausting a tree, pops it. Blob
    /// entries are checked against the path exclusion policy before emission.
    /// Checks the abort flag every 4096 tree entries for responsiveness on
    /// large trees.
    fn walk_stack<S: CandidateSink>(
        &mut self,
        source: &mut impl TreeSource,
        oid_index: &OidIndex,
        abort: &AtomicBool,
        sink: &mut S,
        commit_id: u32,
    ) -> Result<(), TreeDiffError> {
        let mut entry_count: u32 = 0;
        while let Some(frame) = self.stack.last_mut() {
            let entry = match frame.cursor.peek_entry()? {
                Some(entry) => entry,
                None => {
                    self.pop_tree();
                    continue;
                }
            };

            self.name_scratch.clear();
            self.name_scratch.extend_from_slice(entry.name);
            let kind = entry.kind;
            let mode = entry.mode;
            let oid = entry.oid()?;

            frame.cursor.advance()?;
            entry_count = entry_count.wrapping_add(1);
            if entry_count & 0xFFF == 0 && abort.load(Ordering::Relaxed) {
                self.reset_run_state();
                return Err(TreeDiffError::Aborted);
            }

            match kind {
                EntryKind::Tree => {
                    if let Some(idx) = oid_index.get(&oid) {
                        if !self.seen.mark_tree(idx) {
                            perf_stats::sat_add_u64(&mut self.stats.subtrees_skipped, 1);
                            continue;
                        }
                    }

                    self.path_builder.push_dir(&self.name_scratch)?;
                    if let Err(err) = self.push_tree(source, &oid) {
                        self.path_builder.pop_dir();
                        return Err(err);
                    }
                }
                EntryKind::RegularFile | EntryKind::ExecutableFile | EntryKind::Symlink => {
                    let leaf_start = self.path_builder.push_leaf(&self.name_scratch)?;
                    let path = self.path_builder.as_slice();
                    let class = classify_path(path);
                    // When scan_binary is set, honour the user's request to
                    // scan binary blobs by skipping the extension-based filter.
                    let excluded = !self.scan_binary && class.is_nonscannable();
                    let idx = oid_index.get(&oid);

                    if excluded {
                        if let Some(idx) = idx {
                            if self.seen.is_blob_excluded(idx) {
                                self.path_builder.pop_leaf(leaf_start);
                                continue;
                            }
                            self.seen.mark_blob_excluded(idx);
                        } else {
                            if self.loose_excluded.contains(&oid) {
                                self.path_builder.pop_leaf(leaf_start);
                                continue;
                            }
                            self.loose_excluded.insert(&oid)?;
                        }
                        self.path_builder.pop_leaf(leaf_start);
                        continue;
                    }

                    if let Some(idx) = idx {
                        if !self.seen.mark_blob(idx) {
                            self.path_builder.pop_leaf(leaf_start);
                            continue;
                        }
                    } else if !self.loose_seen.insert(&oid)? {
                        self.path_builder.pop_leaf(leaf_start);
                        continue;
                    }
                    let cand_flags = class.bits();
                    let mode_u16 = mode as u16;
                    sink.emit(
                        oid,
                        path,
                        commit_id,
                        0,
                        ChangeKind::Add,
                        mode_u16,
                        cand_flags,
                    )?;
                    perf_stats::sat_add_u64(&mut self.stats.blobs_emitted, 1);
                    self.path_builder.pop_leaf(leaf_start);
                }
                EntryKind::Gitlink | EntryKind::Unknown => {}
            }
        }

        Ok(())
    }
}

/// Returns the power-of-two table size for `count` items at ≤70% load.
///
/// A 70% max load factor (with power-of-two rounding lowering actual load)
/// keeps average probe length short. Power-of-two sizing enables bitmask
/// indexing.
fn table_size_for_count(count: usize) -> usize {
    const LOAD_FACTOR_NUM: usize = 7;
    const LOAD_FACTOR_DEN: usize = 10;
    let min_capacity = count
        .saturating_mul(LOAD_FACTOR_DEN)
        .div_ceil(LOAD_FACTOR_NUM);
    min_capacity.max(1).next_power_of_two()
}

/// Hashes an OID for the `LooseOidSet` hash table.
///
/// XORs the first and last 8 bytes (rotated) to mix positional entropy,
/// then applies a Stafford variant 13 finalizer (`mix64`). The high byte
/// of the result is used as a one-byte tag for early rejection.
#[inline]
fn hash_oid(oid: &OidBytes) -> u64 {
    let bytes = oid.as_slice();
    let head = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
    let tail = u64::from_le_bytes(bytes[bytes.len() - 8..].try_into().unwrap());
    let mut h = head ^ tail.rotate_left(32);
    h ^= (bytes.len() as u64) << 56;
    mix64(h)
}

/// Stafford variant 13 bit mixer — bijective finalizer for 64-bit hashes.
#[inline]
fn mix64(mut x: u64) -> u64 {
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58476d1ce4e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d049bb133111eb);
    x ^ (x >> 31)
}

// ---------------------------------------------------------------------------
// Parallel blob introduction
// ---------------------------------------------------------------------------

/// Per-worker results from parallel blob introduction.
pub(super) struct WorkerResult {
    pub packed: Vec<PackCandidate>,
    pub loose: Vec<LooseCandidate>,
    pub path_arena: ByteArena,
    pub stats: BlobIntroStats,
}

/// Parallel blob introduction worker.
///
/// Each worker holds its own `ObjectStore`, `PathBuilder`, `LooseOidSet`,
/// and `PackCandidateCollector`. The shared `AtomicSeenSets` provides
/// lock-free deduplication across workers: when a worker calls
/// `mark_tree(idx)` / `mark_blob(idx)`, the `fetch_or` guarantees exactly
/// one winner per bit.
///
/// Workers process disjoint chunks of `PlannedCommit` and produce per-worker
/// candidate lists that are merged after all workers finish.
struct BlobIntroWorker<'a> {
    max_depth: u16,
    oid_len: u8,
    path_builder: PathBuilder,
    name_scratch: Vec<u8>,
    stack: Vec<TreeFrame>,
    stats: BlobIntroStats,
    tree_bytes_in_flight_limit: u64,
    tree_bytes_in_flight: u64,
    stream_threshold: usize,
    seen: &'a AtomicSeenSets,
    loose_seen: LooseOidSet,
    loose_excluded: LooseOidSet,
    external_abort: &'a AtomicBool,
    error_abort: &'a AtomicBool,
    scan_binary: bool,
}

impl<'a> BlobIntroWorker<'a> {
    fn new(
        limits: &TreeDiffLimits,
        oid_len: u8,
        max_loose_oids: u32,
        seen: &'a AtomicSeenSets,
        external_abort: &'a AtomicBool,
        error_abort: &'a AtomicBool,
        scan_binary: bool,
    ) -> Self {
        Self {
            max_depth: limits.max_tree_depth,
            oid_len,
            path_builder: PathBuilder::new(4096),
            name_scratch: Vec::with_capacity(256),
            stack: Vec::with_capacity(limits.max_tree_depth as usize),
            stats: BlobIntroStats::default(),
            tree_bytes_in_flight_limit: limits.max_tree_bytes_in_flight,
            tree_bytes_in_flight: 0,
            stream_threshold: limits.max_tree_cache_bytes.max(1) as usize,
            seen,
            loose_seen: LooseOidSet::new(max_loose_oids, oid_len, MappingCandidateKind::Loose),
            loose_excluded: LooseOidSet::new(max_loose_oids, oid_len, MappingCandidateKind::Loose),
            external_abort,
            error_abort,
            scan_binary,
        }
    }

    #[inline]
    fn is_aborted(&self) -> bool {
        // Relaxed: external abort is a monotonic flag; see CancellationToken::as_atomic().
        // Acquire: error_abort must synchronize-with the store in the faulting worker so
        // that any side-effects (e.g. logged diagnostics) are visible before we act on it.
        self.external_abort.load(Ordering::Relaxed) || self.error_abort.load(Ordering::Acquire)
    }

    /// Processes a slice of planned commits, emitting candidates into `sink`.
    fn introduce_chunk<S: CandidateSink>(
        &mut self,
        source: &mut impl TreeSource,
        cg: &CommitGraphIndex,
        chunk: &[PlannedCommit],
        oid_index: &OidIndex,
        sink: &mut S,
    ) -> Result<(), TreeDiffError> {
        for PlannedCommit { pos, .. } in chunk {
            if self.is_aborted() {
                return Err(TreeDiffError::Aborted);
            }

            perf_stats::sat_add_u64(&mut self.stats.commits_visited, 1);
            let commit_id = pos.0;
            let root_oid = cg.root_tree_oid(*pos);

            if let Some(idx) = oid_index.get(&root_oid) {
                if !self.seen.mark_tree(idx as usize) {
                    perf_stats::sat_add_u64(&mut self.stats.subtrees_skipped, 1);
                    continue;
                }
            }

            self.push_tree(source, &root_oid)?;
            match self.walk_stack(source, oid_index, sink, commit_id) {
                Ok(()) => {}
                Err(TreeDiffError::Aborted) => return Err(TreeDiffError::Aborted),
                Err(err) => return Err(err),
            }
        }
        Ok(())
    }

    /// Loads a tree by OID and pushes it onto the walk stack.
    ///
    /// Tracks in-flight byte budget and records perf stats.
    fn push_tree(
        &mut self,
        source: &mut impl TreeSource,
        oid: &OidBytes,
    ) -> Result<(), TreeDiffError> {
        if self.stack.len() >= self.max_depth as usize {
            return Err(TreeDiffError::MaxTreeDepthExceeded {
                max_depth: self.max_depth,
            });
        }

        let bytes = source.load_tree(oid)?;
        perf_stats::sat_add_u64(&mut self.stats.trees_loaded, 1);
        perf_stats::sat_add_u64(&mut self.stats.tree_bytes_loaded, bytes.len() as u64);

        let cursor = TreeCursor::new(bytes, self.oid_len, self.stream_threshold);
        let in_flight_len = cursor.in_flight_len();
        let new_in_flight = self.tree_bytes_in_flight.saturating_add(in_flight_len);
        if new_in_flight > self.tree_bytes_in_flight_limit {
            return Err(TreeDiffError::TreeBytesBudgetExceeded {
                loaded: new_in_flight,
                budget: self.tree_bytes_in_flight_limit,
            });
        }
        self.tree_bytes_in_flight = new_in_flight;
        perf_stats::max_u64(
            &mut self.stats.tree_bytes_in_flight_peak,
            self.tree_bytes_in_flight,
        );

        self.stack.push(TreeFrame {
            cursor,
            in_flight_len,
        });
        perf_stats::max_u16(&mut self.stats.max_depth_reached, self.stack.len() as u16);
        Ok(())
    }

    fn pop_tree(&mut self) {
        if let Some(frame) = self.stack.pop() {
            self.tree_bytes_in_flight = self
                .tree_bytes_in_flight
                .saturating_sub(frame.in_flight_len);
        }
        self.path_builder.pop_dir();
    }

    /// Iteratively walks all frames on the stack, emitting blob candidates.
    ///
    /// Uses the shared `AtomicSeenSets` for tree/blob dedup. Checks the
    /// abort flag every 4096 tree entries for responsiveness on large trees.
    fn walk_stack<S: CandidateSink>(
        &mut self,
        source: &mut impl TreeSource,
        oid_index: &OidIndex,
        sink: &mut S,
        commit_id: u32,
    ) -> Result<(), TreeDiffError> {
        let mut entry_count: u32 = 0;
        while let Some(frame) = self.stack.last_mut() {
            let entry = match frame.cursor.peek_entry()? {
                Some(entry) => entry,
                None => {
                    self.pop_tree();
                    continue;
                }
            };

            self.name_scratch.clear();
            self.name_scratch.extend_from_slice(entry.name);
            let kind = entry.kind;
            let mode = entry.mode;
            let oid = entry.oid()?;

            frame.cursor.advance()?;

            // Check abort every 4096 tree entries for large-tree responsiveness.
            entry_count = entry_count.wrapping_add(1);
            if entry_count & 0xFFF == 0 && self.is_aborted() {
                self.reset_run_state();
                return Err(TreeDiffError::Aborted);
            }

            match kind {
                EntryKind::Tree => {
                    if let Some(idx) = oid_index.get(&oid) {
                        if !self.seen.mark_tree(idx as usize) {
                            perf_stats::sat_add_u64(&mut self.stats.subtrees_skipped, 1);
                            continue;
                        }
                    }

                    self.path_builder.push_dir(&self.name_scratch)?;
                    if let Err(err) = self.push_tree(source, &oid) {
                        self.path_builder.pop_dir();
                        return Err(err);
                    }
                }
                EntryKind::RegularFile | EntryKind::ExecutableFile | EntryKind::Symlink => {
                    let leaf_start = self.path_builder.push_leaf(&self.name_scratch)?;
                    let path = self.path_builder.as_slice();
                    let class = classify_path(path);
                    let excluded = !self.scan_binary && class.is_nonscannable();
                    let idx = oid_index.get(&oid);

                    if excluded {
                        if let Some(idx) = idx {
                            // `mark_blob_excluded` is a test-and-set in the atomic
                            // seen set; use it directly to avoid a separate atomic read.
                            if !self.seen.mark_blob_excluded(idx as usize) {
                                self.path_builder.pop_leaf(leaf_start);
                                continue;
                            }
                        } else {
                            if self.loose_excluded.contains(&oid) {
                                self.path_builder.pop_leaf(leaf_start);
                                continue;
                            }
                            self.loose_excluded.insert(&oid)?;
                        }
                        self.path_builder.pop_leaf(leaf_start);
                        continue;
                    }

                    if let Some(idx) = idx {
                        if !self.seen.mark_blob(idx as usize) {
                            self.path_builder.pop_leaf(leaf_start);
                            continue;
                        }
                    } else if !self.loose_seen.insert(&oid)? {
                        self.path_builder.pop_leaf(leaf_start);
                        continue;
                    }
                    let cand_flags = class.bits();
                    let mode_u16 = mode as u16;
                    sink.emit(
                        oid,
                        path,
                        commit_id,
                        0,
                        ChangeKind::Add,
                        mode_u16,
                        cand_flags,
                    )?;
                    perf_stats::sat_add_u64(&mut self.stats.blobs_emitted, 1);
                    self.path_builder.pop_leaf(leaf_start);
                }
                EntryKind::Gitlink | EntryKind::Unknown => {}
            }
        }

        Ok(())
    }

    fn reset_run_state(&mut self) {
        self.stack.clear();
        self.path_builder.clear();
        self.tree_bytes_in_flight = 0;
    }
}

/// Merged results from parallel blob introduction.
///
/// All per-worker candidate lists are concatenated and (for loose) deduplicated.
/// The `path_arena` owns every path byte referenced by `ByteRef` handles in
/// `packed` and `loose` — it must outlive any downstream consumer.
pub(super) struct ParallelIntroResult {
    pub packed: Vec<PackCandidate>,
    pub loose: Vec<LooseCandidate>,
    pub path_arena: ByteArena,
    pub stats: BlobIntroStats,
}

/// Runs blob introduction across multiple workers using shared `AtomicSeenSets`.
///
/// Pre-partitions `plan` into `~4 × worker_count` chunks. Workers claim
/// chunks via an atomic counter (dynamic work-partitioning). Each worker has
/// its own mutable `ObjectStore` caches and `PackCandidateCollector`; shared
/// immutable repo/pack layout is reused via [`ObjectStoreLayout`]. Dedup is
/// shared through `AtomicSeenSets`. `abort` is observed cooperatively while a
/// separate local error flag stops sibling workers after the first hard error
/// without mutating the caller-owned cancellation flag.
///
/// Cache budgets (`max_tree_cache_bytes`, `max_tree_delta_cache_bytes`,
/// `max_tree_spill_bytes`) are divided by `worker_count` with a floor
/// of 4 MB / 4 MB / 64 MB respectively.
///
/// Post-merge:
/// - Packed/loose candidates are concatenated.
/// - Path arenas are merged with offset rebasing (checked_add overflow),
///   bounded by the global `mapping_cfg_path_arena_capacity`.
/// - Loose candidates are deduplicated by OID with deterministic context tie-breakers.
/// - Global packed/loose caps are re-validated after merge.
/// - Stats use saturating sum for counters and max for peaks.
#[allow(clippy::too_many_arguments)]
pub(super) fn introduce_parallel<'a>(
    worker_count: usize,
    repo: &RepoJobState,
    config: &GitScanConfig,
    spill_dir: &Path,
    object_store_layout: &ObjectStoreLayout<'a>,
    cg: &CommitGraphIndex,
    plan: &[PlannedCommit],
    midx: &MidxView<'a>,
    oid_index: &OidIndex,
    mapping_cfg_path_arena_capacity: u32,
    mapping_cfg_max_packed: u32,
    mapping_cfg_max_loose: u32,
    abort: &AtomicBool,
) -> Result<ParallelIntroResult, TreeDiffError> {
    let worker_count = worker_count.max(1).min(plan.len().max(1));

    if plan.is_empty() {
        return Ok(ParallelIntroResult {
            packed: Vec::new(),
            loose: Vec::new(),
            path_arena: ByteArena::with_capacity(0),
            stats: BlobIntroStats::default(),
        });
    }

    // Pre-partition plan into ~4× worker_count chunks.
    let chunk_count = (worker_count * 4).min(plan.len());
    let chunk_size = plan.len().div_ceil(chunk_count);
    let chunks: Vec<&[PlannedCommit]> = plan.chunks(chunk_size).collect();
    let next_chunk = AtomicUsize::new(0);
    let error_abort = AtomicBool::new(false);

    let object_count = midx.object_count();
    let seen_len = (object_count as usize).max(1);

    // Shared AtomicSeenSets sized to MIDX object count.
    // `AtomicSeenSets` disallows zero capacity, but a valid MIDX can have zero
    // objects when a repository has no packs. In that case all lookups miss and
    // packed indices are never marked, so a capacity floor of 1 is safe.
    let seen = AtomicSeenSets::new(seen_len, seen_len);

    // Per-worker budget division.
    let divided_tree_cache = config.tree_diff.max_tree_cache_bytes / worker_count as u32;
    let per_worker_tree_cache = divided_tree_cache.max(4 * 1024 * 1024); // 4 MB floor
    let divided_delta_cache = config.tree_diff.max_tree_delta_cache_bytes / worker_count as u32;
    let per_worker_delta_cache = divided_delta_cache.max(4 * 1024 * 1024); // 4 MB floor
    if per_worker_delta_cache > divided_delta_cache {
        eprintln!(
            "note: per-worker delta cache floor (4 MiB) exceeds divided budget ({} KiB); \
             total memory will exceed configured max",
            divided_delta_cache / 1024,
        );
    }
    let per_worker_spill = config.tree_diff.max_tree_spill_bytes / worker_count as u64;
    let per_worker_spill = per_worker_spill.max(64 * 1024 * 1024); // 64 MB floor
    let per_worker_in_flight =
        (config.tree_diff.max_tree_bytes_in_flight / worker_count as u64).max(64 * 1024 * 1024); // 64 MB floor
    let per_worker_loose = per_worker_loose_limit(mapping_cfg_max_loose, worker_count);
    let per_worker_path_arena = (mapping_cfg_path_arena_capacity / worker_count as u32)
        .max(64 * 1024)
        .min(mapping_cfg_path_arena_capacity); // never exceed the original cap
    let per_worker_max_packed = (mapping_cfg_max_packed / worker_count as u32)
        .max(1024)
        .min(mapping_cfg_max_packed); // never exceed the original cap

    // Build per-worker limits with divided budgets.
    let per_worker_limits = TreeDiffLimits {
        max_tree_cache_bytes: per_worker_tree_cache,
        max_tree_delta_cache_bytes: per_worker_delta_cache,
        max_tree_spill_bytes: per_worker_spill,
        max_tree_bytes_in_flight: per_worker_in_flight,
        ..config.tree_diff
    };

    let auto_cache_fn = super::runner_exec::auto_tree_delta_cache_bytes;

    // Create core assigner for thread pinning (Linux only; None elsewhere).
    let core_assigner = if config.pin_threads {
        scanner_scheduler::affinity::CoreAssigner::new()
    } else {
        None
    };

    // Spawn workers with std::thread::scope.
    let results: Vec<Result<WorkerResult, TreeDiffError>> = std::thread::scope(|s| {
        let handles: Vec<_> = (0..worker_count)
            .map(|_| {
                let chunks = &chunks;
                let next_chunk = &next_chunk;
                let external_abort = abort;
                let error_abort = &error_abort;
                let seen = &seen;
                let per_worker_limits = &per_worker_limits;
                let core_assigner = &core_assigner;

                s.spawn(move || {
                    if let Some(ref a) = core_assigner {
                        a.pin_current_thread();
                    }
                    // Per-worker ObjectStore.
                    let auto_cache_bytes =
                        auto_cache_fn(object_count, per_worker_limits.max_tree_delta_cache_bytes);
                    let tree_delta_cache = TreeDeltaCache::new(auto_cache_bytes);
                    let mut object_store = ObjectStore::open_with_layout(
                        object_store_layout,
                        per_worker_limits,
                        spill_dir,
                        tree_delta_cache,
                    )?;

                    // Per-worker candidate collector with divided limits.
                    let mut collector = PackCandidateCollector::new(
                        midx,
                        oid_index,
                        per_worker_path_arena,
                        per_worker_max_packed,
                        per_worker_loose,
                    );

                    let mut worker = BlobIntroWorker::new(
                        per_worker_limits,
                        repo.object_format.oid_len(),
                        per_worker_loose,
                        seen,
                        external_abort,
                        error_abort,
                        config.engine_adapter.scan_binary,
                    );

                    // Claim and process chunks.
                    loop {
                        let idx = next_chunk.fetch_add(1, Ordering::Relaxed);
                        if idx >= chunks.len() {
                            break;
                        }
                        if let Err(err) = worker.introduce_chunk(
                            &mut object_store,
                            cg,
                            chunks[idx],
                            oid_index,
                            &mut collector,
                        ) {
                            if !matches!(err, TreeDiffError::Aborted) {
                                error_abort.store(true, Ordering::Release);
                            }
                            return Err(err);
                        }
                    }

                    let (packed, loose, path_arena) = collector.finish();
                    Ok(WorkerResult {
                        packed,
                        loose,
                        path_arena,
                        stats: worker.stats,
                    })
                })
            })
            .collect();

        handles
            .into_iter()
            .map(|h| {
                h.join().unwrap_or(Err(TreeDiffError::CorruptTree {
                    detail: "blob intro worker panicked",
                }))
            })
            .collect()
    });

    let mut first_error: Option<TreeDiffError> = None;
    let mut worker_results = Vec::new();
    for result in results {
        match result {
            Ok(wr) => {
                worker_results.push(wr);
            }
            Err(err) => match first_error {
                None => first_error = Some(err),
                // Prefer non-Aborted errors: a real error (e.g. CorruptTree)
                // is more informative than an Aborted triggered by sibling
                // worker fan-out. Workers joined in spawn order may report
                // Aborted before the root-cause error arrives.
                Some(TreeDiffError::Aborted) if !matches!(err, TreeDiffError::Aborted) => {
                    first_error = Some(err);
                }
                _ => {}
            },
        }
    }

    if let Some(err) = first_error {
        return Err(err);
    }

    merge_worker_results(
        worker_results,
        mapping_cfg_path_arena_capacity,
        mapping_cfg_max_packed,
        mapping_cfg_max_loose,
    )
}

/// Merge per-worker introduction outputs and enforce global candidate/arena caps.
///
/// Worker results are concatenated in order. Each worker's path arena is
/// appended to a single merged arena, and every candidate's `path_ref.off`
/// is rebased by the arena offset at the time of append. If the combined
/// arena exceeds `path_arena_capacity`, returns [`TreeDiffError::PathArenaFull`].
///
/// Loose candidates are deduplicated by OID with deterministic context
/// tie-breakers (see [`dedup_loose_by_oid`]). After dedup, the merged totals
/// are re-validated against `max_packed` and `max_loose` because per-worker
/// limits are approximate divisions of the global budget.
fn merge_worker_results(
    worker_results: Vec<WorkerResult>,
    path_arena_capacity: u32,
    max_packed: u32,
    max_loose: u32,
) -> Result<ParallelIntroResult, TreeDiffError> {
    let mut all_packed = Vec::new();
    let mut all_loose = Vec::new();
    let mut merged_stats = BlobIntroStats::default();
    let mut merged_arena = ByteArena::with_capacity(path_arena_capacity);

    for mut wr in worker_results {
        // Rebase path arena references in candidates.
        let base = merged_arena
            .append_arena(&wr.path_arena)
            .ok_or(TreeDiffError::PathArenaFull)?;

        if base > 0 {
            for cand in &mut wr.packed {
                cand.ctx.path_ref.off = cand
                    .ctx
                    .path_ref
                    .off
                    .checked_add(base)
                    .ok_or(TreeDiffError::PathArenaFull)?;
            }
            for cand in &mut wr.loose {
                cand.ctx.path_ref.off = cand
                    .ctx
                    .path_ref
                    .off
                    .checked_add(base)
                    .ok_or(TreeDiffError::PathArenaFull)?;
            }
        }

        all_packed.extend(wr.packed);
        all_loose.extend(wr.loose);

        // Merge stats: sum for counters, max for peaks.
        merged_stats.commits_visited = merged_stats
            .commits_visited
            .saturating_add(wr.stats.commits_visited);
        merged_stats.trees_loaded = merged_stats
            .trees_loaded
            .saturating_add(wr.stats.trees_loaded);
        merged_stats.tree_bytes_loaded = merged_stats
            .tree_bytes_loaded
            .saturating_add(wr.stats.tree_bytes_loaded);
        merged_stats.blobs_emitted = merged_stats
            .blobs_emitted
            .saturating_add(wr.stats.blobs_emitted);
        merged_stats.subtrees_skipped = merged_stats
            .subtrees_skipped
            .saturating_add(wr.stats.subtrees_skipped);
        merged_stats.tree_bytes_in_flight_peak = merged_stats
            .tree_bytes_in_flight_peak
            .max(wr.stats.tree_bytes_in_flight_peak);
        merged_stats.max_depth_reached = merged_stats
            .max_depth_reached
            .max(wr.stats.max_depth_reached);
    }

    // Deduplicate loose candidates by OID with deterministic context tie-breakers.
    dedup_loose_by_oid(&mut all_loose, &merged_arena);

    // Post-merge validation: ensure the merged totals respect the global caps.
    // Per-worker limits are divided approximations; the merged result can exceed
    // the original budget, so we re-check here.
    if all_packed.len() as u64 > max_packed as u64 {
        return Err(TreeDiffError::CandidateLimitExceeded {
            kind: MappingCandidateKind::Packed,
            max: max_packed,
            observed: all_packed.len().min(u32::MAX as usize) as u32,
        });
    }
    if all_loose.len() as u64 > max_loose as u64 {
        return Err(TreeDiffError::CandidateLimitExceeded {
            kind: MappingCandidateKind::Loose,
            max: max_loose,
            observed: all_loose.len().min(u32::MAX as usize) as u32,
        });
    }

    Ok(ParallelIntroResult {
        packed: all_packed,
        loose: all_loose,
        path_arena: merged_arena,
        stats: merged_stats,
    })
}

/// Returns the loose-candidate budget used by each parallel worker.
///
/// Divides `max_loose` by `worker_count` with ceiling division so no
/// candidates are lost to rounding. The result is clamped to `[1, max_loose]`
/// (with a special-case `0` when `max_loose` is zero). Post-merge validation
/// in [`merge_worker_results`] catches cases where the per-worker budgets
/// sum to more than the global cap.
fn per_worker_loose_limit(max_loose: u32, worker_count: usize) -> u32 {
    if max_loose == 0 {
        return 0;
    }
    let workers = worker_count.max(1) as u32;
    max_loose.div_ceil(workers).max(1).min(max_loose)
}

/// Deduplicates loose candidates by OID with deterministic context tie-breakers.
///
/// Ordering is:
/// `oid`, `commit_id`, `path bytes`, `parent_idx`, `change_kind`,
/// `ctx_flags`, `cand_flags`, `path_ref.off`, `path_ref.len`.
/// See [`cmp_loose_dedup_key`] for the full ordering rationale.
fn dedup_loose_by_oid(loose: &mut Vec<LooseCandidate>, path_arena: &ByteArena) {
    if loose.len() <= 1 {
        return;
    }
    loose.sort_unstable_by(|a, b| cmp_loose_dedup_key(a, b, path_arena));
    loose.dedup_by(|a, b| a.oid == b.oid);
}

/// Total ordering for [`LooseCandidate`] used by [`dedup_loose_by_oid`].
///
/// Primary key is `oid` so that `dedup_by` (which removes *consecutive*
/// duplicates) collapses all entries for the same blob.  The secondary
/// chain is a tie-breaker that decides *which* context survives dedup:
/// `sort_unstable_by` is not stable, but the first element in each
/// equal-oid run is kept by `dedup_by`, so the tie-breaker controls
/// which observation context wins.
///
/// Tie-breaker order (most-significant first):
///
/// 1. `commit_id` — prefer the earliest commit-graph position.
/// 2. path bytes  — lexicographic on the raw path (resolved from arena).
/// 3. `parent_idx` — prefer the first parent diff.
/// 4. `change_kind` — Add before Modify (lower discriminant wins).
/// 5. `ctx_flags` / `cand_flags` — deterministic but rarely differ.
/// 6. `path_ref.off` / `path_ref.len` — arena coordinates break ties
///    when two arena entries hold byte-identical paths at different
///    offsets (possible after cross-worker arena merges).  Without this,
///    the ordering would be partial and `sort_unstable_by` could yield
///    non-deterministic survivor selection across runs.
#[inline]
fn cmp_loose_dedup_key(
    a: &LooseCandidate,
    b: &LooseCandidate,
    path_arena: &ByteArena,
) -> std::cmp::Ordering {
    a.oid.cmp(&b.oid).then_with(|| {
        let a_path = path_arena.get(a.ctx.path_ref);
        let b_path = path_arena.get(b.ctx.path_ref);
        a.ctx
            .commit_id
            .cmp(&b.ctx.commit_id)
            .then_with(|| a_path.cmp(b_path))
            .then_with(|| a.ctx.parent_idx.cmp(&b.ctx.parent_idx))
            .then_with(|| a.ctx.change_kind.as_u8().cmp(&b.ctx.change_kind.as_u8()))
            .then_with(|| a.ctx.ctx_flags.cmp(&b.ctx.ctx_flags))
            .then_with(|| a.ctx.cand_flags.cmp(&b.ctx.cand_flags))
            // Arena coordinates make the ordering total when two entries
            // share byte-identical paths at different arena offsets.
            .then_with(|| a.ctx.path_ref.off.cmp(&b.ctx.path_ref.off))
            .then_with(|| a.ctx.path_ref.len.cmp(&b.ctx.path_ref.len))
    })
}

#[cfg(test)]
#[path = "blob_introducer_tests.rs"]
mod tests;

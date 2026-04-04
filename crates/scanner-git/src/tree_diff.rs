//! Tree diff walker for Git scanning.
//!
//! Performs OID-only tree diffs between two trees, emitting candidates
//! for changed blob-like entries. Uses explicit stack (no recursion) and
//! enforces depth limits.
//!
//! # Algorithm
//!
//! Merge-walk both trees in Git tree order (see `tree_order` module).
//! For each pair of entries:
//!
//! - new < old: Entry added in new tree -> emit candidate (if blob-like)
//! - new > old: Entry deleted -> skip (nothing to scan)
//! - new == old:
//!   - If tree: recurse only if subtree OIDs differ
//!   - If blob-like: emit candidate only if OIDs differ (modify)
//!   - If gitlink: skip (submodule commits not scanned)
//!
//! # Kind Changes (File <-> Directory)
//!
//! When an entry changes kind (e.g., file "foo" becomes dir "foo/"):
//! - Git tree ordering treats them as different entries (different terminators)
//! - file "foo" terminates with NUL (0x00)
//! - dir "foo/" terminates with '/' (0x2F)
//! - So file < dir when names match exactly
//! - Result: file deleted (skip) + dir added (recurse into new dir)
//!
//! # Kind Changes (Blob <-> Gitlink)
//!
//! When both entries are non-directories (same ordering):
//! - blob -> gitlink: skip (gitlinks not scanned)
//! - gitlink -> blob: emit candidate with ChangeKind::Add
//!
//! # Performance
//!
//! - O(n) where n is the number of changed entries
//! - Skips unchanged subtrees entirely (no recursion)
//! - No blob reads (OID comparison only)
//! - Fixed-size stack allocation (bounded depth)
//! - Stack is reused across diff_trees calls (no per-call allocation)
//! - Large or spill-backed trees are parsed with a streaming buffer
//!   to keep the working set bounded
//!
//! # Invariants
//! - `TreeSource` returns raw tree payload bytes (no object header) in
//!   canonical Git tree order.
//! - The configured `oid_len` is authoritative; mismatches are errors.
//! - `reset_stats()` must be called only when the diff stack is empty.
//!
//! # Output Ordering
//! Candidates are emitted in Git tree order for each diff. For merge commits,
//! the caller should invoke `diff_trees` once per parent; `parent_idx` tags
//! the candidate with which parent diff produced it.
//!
//! # Budgeting
//! The tree-bytes budget is enforced on in-flight bytes retained by the
//! walker. Call `reset_stats()` when starting a new repo job; the in-flight
//! tracker is reset and the diff stack must be empty.

use std::cmp::Ordering;
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};

use crate::perf_stats;

use super::errors::TreeDiffError;
use super::object_id::OidBytes;
use super::object_store::{TreeBytes, TreeSource};
use super::tree_candidate::{CandidateSink, ChangeKind};
use super::tree_diff_limits::TreeDiffLimits;
use super::tree_entry::{parse_entry, EntryKind, ParseOutcome, ParsedTreeEntry, TreeEntry};
use super::tree_order::git_tree_name_cmp;
use super::tree_stream::{TreeBytesReader, TreeStream};

/// Maximum path length in bytes.
///
/// This matches Linux's PATH_MAX (macOS PATH_MAX is 1024).
/// Paths exceeding this are rejected to prevent DoS via deeply nested trees.
const MAX_PATH_LEN: usize = 4096;
/// Streaming tree entry buffer size (bytes).
const TREE_STREAM_BUF_BYTES: usize = 16 * 1024;

/// Counters for tree diff operations.
///
/// Statistics are cumulative until `reset_stats()` is called. The
/// `tree_bytes_loaded` counter is informational; the in-flight budget
/// is enforced separately via the walker.
#[derive(Clone, Debug, Default)]
pub struct TreeDiffStats {
    /// Number of trees loaded.
    pub trees_loaded: u64,
    /// Total bytes loaded from trees.
    pub tree_bytes_loaded: u64,
    /// Peak in-flight tree bytes retained by the walker.
    pub tree_bytes_in_flight_peak: u64,
    /// Number of candidates emitted.
    pub candidates_emitted: u64,
    /// Number of subtrees skipped (same OID).
    pub subtrees_skipped: u64,
    /// Maximum stack depth reached.
    pub max_depth_reached: u16,
}

/// Stack frame for iterative tree diff.
struct DiffFrame {
    /// Cursor over the new tree.
    new_cursor: TreeCursor,
    /// Cursor over the old tree.
    old_cursor: TreeCursor,
    /// Path prefix length (where to truncate path_buf).
    prefix_len: usize,
}

/// Action to take after processing a pair of entries.
///
/// Using an enum avoids mutable borrow conflicts: we collect all the
/// information needed while holding an immutable reference to the frame,
/// then execute the action afterwards.
enum Action {
    /// Pop the current frame (both trees exhausted).
    Pop,
    /// Entry only in new tree: advance new cursor and process.
    AddedEntry {
        oid: OidBytes,
        kind: EntryKind,
        mode: u32,
    },
    /// Entry only in old tree (deletion, skip).
    DeletedEntry,
    /// Entries match (same name+type in ordering), names lexically equal.
    MatchedEntries {
        new_oid: OidBytes,
        old_oid: OidBytes,
        new_kind: EntryKind,
        old_kind: EntryKind,
        new_mode: u32,
    },
    /// new < old in tree ordering: entry added in new tree.
    NewBeforeOld {
        oid: OidBytes,
        kind: EntryKind,
        mode: u32,
    },
    /// new > old in tree ordering: entry deleted from old tree.
    OldBeforeNew,
}

/// Buffered tree cursor (slice-backed) with peek-one-entry lookahead.
///
/// `peek_entry` parses and caches the next entry; `advance` consumes
/// the cache and moves `pos` forward. This avoids re-parsing when the
/// diff loop peeks the same entry multiple times.
struct BufferedCursor {
    bytes: TreeBytes,
    pos: usize,
    cached: Option<ParsedTreeEntry>,
    oid_len: u8,
}

impl BufferedCursor {
    fn new(bytes: TreeBytes, oid_len: u8) -> Self {
        Self {
            bytes,
            pos: 0,
            cached: None,
            oid_len,
        }
    }

    fn peek_entry(&mut self) -> Result<Option<TreeEntry<'_>>, TreeDiffError> {
        if let Some(parsed) = self.cached {
            return Ok(Some(
                parsed.materialize(self.bytes.as_slice(), self.oid_len),
            ));
        }

        if self.pos >= self.bytes.len() {
            return Ok(None);
        }

        let remaining = &self.bytes.as_slice()[self.pos..];
        match parse_entry(remaining, self.oid_len)? {
            ParseOutcome::Complete(mut parsed) => {
                parsed.offset_by(self.pos);
                self.cached = Some(parsed);
                Ok(Some(
                    parsed.materialize(self.bytes.as_slice(), self.oid_len),
                ))
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

    fn in_flight_len(&self) -> u64 {
        self.bytes.in_flight_len() as u64
    }
}

/// Tree cursor selecting buffered vs streaming parsing.
///
/// Trees smaller than `stream_threshold` use `Buffered` (single slice).
/// Larger or spill-backed trees use `Stream` to avoid loading the
/// entire tree into memory at once.
enum TreeCursor {
    Buffered(BufferedCursor),
    Stream(TreeStream<TreeBytesReader>),
}

impl TreeCursor {
    /// Builds a cursor, selecting streaming for large or spill-backed trees.
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

    /// Returns an empty cursor with the configured OID length.
    fn empty(oid_len: u8) -> Self {
        Self::Buffered(BufferedCursor::new(TreeBytes::empty(), oid_len))
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
            Self::Buffered(cursor) => cursor.in_flight_len(),
            Self::Stream(stream) => stream.in_flight_len() as u64,
        }
    }
}

/// Tree diff walker configuration and state.
///
/// The walker maintains internal state (stack, path buffer, name scratch)
/// that is reused across multiple `diff_trees` calls for efficiency.
/// Candidate paths are assembled in a reusable buffer; sinks must copy
/// the provided path if they need to retain it.
///
/// # Invariants
/// - `stack.len() <= max_depth`
/// - `path_buf` holds the current path prefix for the top stack frame
pub struct TreeDiffWalker {
    /// Maximum recursion depth.
    max_depth: u16,
    /// OID length (20 or 32).
    oid_len: u8,
    /// Path buffer (reused across entries).
    path_buf: Vec<u8>,
    /// Reused entry-name scratch to avoid per-diff allocations.
    name_scratch: Vec<u8>,
    /// Diff stack (reused across calls).
    stack: Vec<DiffFrame>,
    /// Statistics.
    stats: TreeDiffStats,
    /// In-flight tree bytes budget.
    tree_bytes_in_flight_limit: u64,
    /// Current in-flight tree bytes retained by stack frames.
    tree_bytes_in_flight: u64,
    /// Threshold for switching to streaming parsing.
    stream_threshold: usize,
}

impl TreeDiffWalker {
    /// Creates a new tree diff walker.
    #[must_use]
    pub fn new(limits: &TreeDiffLimits, oid_len: u8) -> Self {
        assert!(
            oid_len == 20 || oid_len == 32,
            "OID length must be 20 or 32"
        );

        Self {
            max_depth: limits.max_tree_depth,
            oid_len,
            path_buf: Vec::with_capacity(4096),
            name_scratch: Vec::with_capacity(256),
            stack: Vec::with_capacity(limits.max_tree_depth as usize),
            stats: TreeDiffStats::default(),
            tree_bytes_in_flight_limit: limits.max_tree_bytes_in_flight,
            tree_bytes_in_flight: 0,
            stream_threshold: limits.max_tree_cache_bytes.max(1) as usize,
        }
    }

    /// Returns the current statistics.
    #[must_use]
    pub fn stats(&self) -> &TreeDiffStats {
        &self.stats
    }

    /// Resets statistics for a new repo job.
    ///
    /// Call this when starting a new repository scan to get fresh stats.
    /// The internal buffers (stack, path_buf) are retained for reuse.
    /// Each diff call releases all in-flight tree bytes before returning.
    pub fn reset_stats(&mut self) {
        debug_assert!(
            self.stack.is_empty(),
            "reset_stats must be called with an empty diff stack"
        );
        self.stats = TreeDiffStats::default();
        self.tree_bytes_in_flight = 0;
    }

    /// Diffs two trees, emitting candidates for changed blobs.
    ///
    /// # Arguments
    ///
    /// * `source` - Tree object loader
    /// * `candidates` - Output sink for candidates
    /// * `new_tree` - OID of the new (child) tree, or None for empty tree
    /// * `old_tree` - OID of the old (parent) tree, or None for empty tree
    /// * `commit_id` - Commit identifier for attribution
    /// * `parent_idx` - Which parent this diff is against (for merge commits)
    /// * `abort` - Cooperative cancellation flag checked during the walk
    ///
    /// # Errors
    ///
    /// - `CandidateBufferFull` if the candidate buffer is exhausted
    /// - `MaxTreeDepthExceeded` if recursion depth exceeds limit
    /// - `TreeBytesBudgetExceeded` if total tree bytes exceed budget
    /// - `PathTooLong` if a path exceeds MAX_PATH_LEN
    /// - Tree loading errors from the source
    ///
    /// # Notes
    ///
    /// - If `new_tree == old_tree`, this is a no-op.
    /// - `parent_idx` is preserved in candidate context for later merge/dedupe.
    /// - The candidate sink is appended to; it is not cleared by this call.
    /// - Candidate paths are borrowed from an internal buffer and are only
    ///   valid until the next emission.
    /// - Stats are cumulative across calls; `reset_stats()` clears counters.
    /// - All retained tree-byte charges are released before return, including
    ///   early-error exits, so retries start from a clean budget state.
    /// - The abort flag is checked every 4096 processed tree entries to bound
    ///   cancellation latency on large commits.
    pub fn diff_trees<S: TreeSource, C: CandidateSink>(
        &mut self,
        source: &mut S,
        candidates: &mut C,
        new_tree: Option<&OidBytes>,
        old_tree: Option<&OidBytes>,
        commit_id: u32,
        parent_idx: u8,
        abort: &AtomicBool,
    ) -> Result<(), TreeDiffError> {
        if new_tree == old_tree {
            return Ok(());
        }
        if abort.load(AtomicOrdering::Relaxed) {
            return Err(TreeDiffError::Aborted);
        }

        self.cleanup_after_diff_call();
        let mut name_scratch = std::mem::take(&mut self.name_scratch);
        name_scratch.clear();
        debug_assert!(
            name_scratch.is_empty(),
            "name_scratch must be cleared before diff_trees"
        );

        let result = (|| {
            let new_cursor = self.load_tree_cursor(source, new_tree)?;
            let old_cursor = self.load_tree_cursor(source, old_tree)?;

            self.stack.push(DiffFrame {
                new_cursor,
                old_cursor,
                prefix_len: 0,
            });

            let mut entry_count: u32 = 0;
            while !self.stack.is_empty() {
                let depth = self.stack.len() as u16;
                perf_stats::max_u16(&mut self.stats.max_depth_reached, depth);

                let action = {
                    let frame = self.stack.last_mut().expect("frame exists");
                    let new_entry = frame.new_cursor.peek_entry()?;
                    let old_entry = frame.old_cursor.peek_entry()?;

                    let action = compute_action(new_entry, old_entry, self.oid_len)?;
                    if matches!(
                        action,
                        Action::AddedEntry { .. }
                            | Action::MatchedEntries { .. }
                            | Action::NewBeforeOld { .. }
                    ) {
                        let entry = new_entry.expect("name requires new entry");
                        name_scratch.clear();
                        name_scratch.extend_from_slice(entry.name);
                    }
                    action
                };
                if !matches!(action, Action::Pop) {
                    entry_count = entry_count.wrapping_add(1);
                    if entry_count & 0xFFF == 0 && abort.load(AtomicOrdering::Relaxed) {
                        return Err(TreeDiffError::Aborted);
                    }
                }

                match action {
                    Action::Pop => {
                        let frame = self.stack.pop().expect("frame exists");
                        self.release_tree_bytes(frame.new_cursor.in_flight_len());
                        self.release_tree_bytes(frame.old_cursor.in_flight_len());
                        self.path_buf.truncate(frame.prefix_len);
                    }
                    Action::AddedEntry { oid, kind, mode } => {
                        debug_assert!(!name_scratch.is_empty());
                        let frame = self.stack.last_mut().expect("frame exists");
                        frame.new_cursor.advance()?;
                        self.handle_new_entry(
                            source,
                            candidates,
                            &oid,
                            &name_scratch,
                            kind,
                            mode,
                            commit_id,
                            parent_idx,
                        )?;
                    }
                    Action::DeletedEntry => {
                        let frame = self.stack.last_mut().expect("frame exists");
                        frame.old_cursor.advance()?;
                    }
                    Action::MatchedEntries {
                        new_oid,
                        old_oid,
                        new_kind,
                        old_kind,
                        new_mode,
                    } => {
                        debug_assert!(!name_scratch.is_empty());
                        let frame = self.stack.last_mut().expect("frame exists");
                        frame.new_cursor.advance()?;
                        frame.old_cursor.advance()?;
                        self.handle_matched_entries(
                            source,
                            candidates,
                            &new_oid,
                            &old_oid,
                            &name_scratch,
                            new_kind,
                            old_kind,
                            new_mode,
                            commit_id,
                            parent_idx,
                        )?;
                    }
                    Action::NewBeforeOld { oid, kind, mode } => {
                        debug_assert!(!name_scratch.is_empty());
                        let frame = self.stack.last_mut().expect("frame exists");
                        frame.new_cursor.advance()?;
                        self.handle_new_entry(
                            source,
                            candidates,
                            &oid,
                            &name_scratch,
                            kind,
                            mode,
                            commit_id,
                            parent_idx,
                        )?;
                    }
                    Action::OldBeforeNew => {
                        let frame = self.stack.last_mut().expect("frame exists");
                        frame.old_cursor.advance()?;
                    }
                }
            }

            Ok(())
        })();

        self.name_scratch = name_scratch;
        self.cleanup_after_diff_call();

        result
    }

    /// Loads tree data and updates cumulative stats and in-flight budget.
    ///
    /// `None` yields an empty tree without incrementing counters.
    fn load_tree_cursor<S: TreeSource>(
        &mut self,
        source: &mut S,
        oid: Option<&OidBytes>,
    ) -> Result<TreeCursor, TreeDiffError> {
        // Loading a tree increments stats and enforces the in-flight budget.
        if let Some(oid) = oid {
            let bytes = source.load_tree(oid)?;
            let bytes_len = bytes.len() as u64;
            let in_flight_len = bytes.in_flight_len() as u64;
            let new_in_flight = self.tree_bytes_in_flight.saturating_add(in_flight_len);
            perf_stats::sat_add_u64(&mut self.stats.trees_loaded, 1);
            perf_stats::sat_add_u64(&mut self.stats.tree_bytes_loaded, bytes_len);

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

            Ok(TreeCursor::new(bytes, self.oid_len, self.stream_threshold))
        } else {
            Ok(TreeCursor::empty(self.oid_len))
        }
    }

    fn release_tree_bytes(&mut self, len: u64) {
        self.tree_bytes_in_flight = self.tree_bytes_in_flight.saturating_sub(len);
    }

    /// Releases any tree-byte charges retained after a `diff_trees` call.
    ///
    /// Normally the walk loop pops all frames and releases in-flight bytes as
    /// it goes. Early errors can exit before that unwind completes (or before
    /// the root frame is pushed), so this cleanup makes retries on the same
    /// walker start from a clean budget state.
    fn cleanup_after_diff_call(&mut self) {
        while let Some(frame) = self.stack.pop() {
            self.release_tree_bytes(frame.new_cursor.in_flight_len());
            self.release_tree_bytes(frame.old_cursor.in_flight_len());
        }

        self.path_buf.clear();
        self.tree_bytes_in_flight = 0;
    }

    /// Processes an entry present only in the new tree.
    ///
    /// Trees are recursed into; blob-like entries emit an `Add` candidate.
    /// Gitlinks and unknown kinds are silently skipped.
    #[allow(clippy::too_many_arguments)]
    fn handle_new_entry<S: TreeSource, C: CandidateSink>(
        &mut self,
        source: &mut S,
        candidates: &mut C,
        oid: &OidBytes,
        name: &[u8],
        kind: EntryKind,
        mode: u32,
        commit_id: u32,
        parent_idx: u8,
    ) -> Result<(), TreeDiffError> {
        if kind.is_tree() {
            self.push_subtree_frame(source, oid, None, name)?;
        } else if kind.is_blob_like() {
            self.emit_candidate(
                candidates,
                oid,
                name,
                ChangeKind::Add,
                mode,
                commit_id,
                parent_idx,
            )?;
        }
        Ok(())
    }

    /// Processes a pair of entries with the same name in old and new trees.
    ///
    /// Implements the four-way kind matrix:
    /// - **tree / tree**: recurse if OIDs differ, skip if identical.
    /// - **non-tree / tree**: treat new subtree as entirely added.
    /// - **tree / non-tree**: emit the new blob as `Add`.
    /// - **non-tree / non-tree**: emit `Modify` if OIDs differ, skip if equal.
    ///
    /// Gitlinks on either side are handled implicitly: a gitlink-to-blob
    /// change emits the blob; a blob-to-gitlink change is skipped.
    #[allow(clippy::too_many_arguments)]
    fn handle_matched_entries<S: TreeSource, C: CandidateSink>(
        &mut self,
        source: &mut S,
        candidates: &mut C,
        new_oid: &OidBytes,
        old_oid: &OidBytes,
        name: &[u8],
        new_kind: EntryKind,
        old_kind: EntryKind,
        new_mode: u32,
        commit_id: u32,
        parent_idx: u8,
    ) -> Result<(), TreeDiffError> {
        if new_oid == old_oid && new_kind.is_tree() && old_kind.is_tree() {
            perf_stats::sat_add_u64(&mut self.stats.subtrees_skipped, 1);
            return Ok(());
        }

        match (new_kind.is_tree(), old_kind.is_tree()) {
            (true, true) => {
                self.push_subtree_frame(source, new_oid, Some(old_oid), name)?;
            }
            (true, false) => {
                // Old was non-tree, new is tree; treat as new tree added.
                self.push_subtree_frame(source, new_oid, None, name)?;
            }
            (false, true) => {
                // Old was tree, new is non-tree.
                if new_kind.is_blob_like() {
                    self.emit_candidate(
                        candidates,
                        new_oid,
                        name,
                        ChangeKind::Add,
                        new_mode,
                        commit_id,
                        parent_idx,
                    )?;
                }
            }
            (false, false) => {
                if new_kind.is_blob_like() {
                    if old_kind.is_blob_like() {
                        if new_oid != old_oid {
                            self.emit_candidate(
                                candidates,
                                new_oid,
                                name,
                                ChangeKind::Modify,
                                new_mode,
                                commit_id,
                                parent_idx,
                            )?;
                        }
                    } else {
                        self.emit_candidate(
                            candidates,
                            new_oid,
                            name,
                            ChangeKind::Add,
                            new_mode,
                            commit_id,
                            parent_idx,
                        )?;
                    }
                }
            }
        }

        Ok(())
    }

    /// Pushes a subtree frame, extending `path_buf` with `name/`.
    ///
    /// Enforces the depth limit and path length limit. Loads both new
    /// and old trees (when `old_oid` is `Some`), charging the in-flight
    /// byte budget for each.
    fn push_subtree_frame<S: TreeSource>(
        &mut self,
        source: &mut S,
        new_oid: &OidBytes,
        old_oid: Option<&OidBytes>,
        name: &[u8],
    ) -> Result<(), TreeDiffError> {
        // Extend the path buffer with "name/" for the subtree frame.
        if self.stack.len() >= self.max_depth as usize {
            return Err(TreeDiffError::MaxTreeDepthExceeded {
                max_depth: self.max_depth,
            });
        }

        let new_len = self.path_buf.len() + name.len() + 1;
        if new_len > MAX_PATH_LEN {
            return Err(TreeDiffError::PathTooLong {
                len: new_len,
                max: MAX_PATH_LEN,
            });
        }

        let prefix_len = self.path_buf.len();
        self.path_buf.extend_from_slice(name);
        self.path_buf.push(b'/');

        let new_cursor = self.load_tree_cursor(source, Some(new_oid))?;
        let old_cursor = self.load_tree_cursor(source, old_oid)?;

        self.stack.push(DiffFrame {
            new_cursor,
            old_cursor,
            prefix_len,
        });

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    /// Emits a candidate using the current path prefix plus `name`.
    ///
    /// The path slice is backed by an internal buffer that is reused on the
    /// next emission; sinks must copy the path if they need to retain it.
    fn emit_candidate<C: CandidateSink>(
        &mut self,
        candidates: &mut C,
        oid: &OidBytes,
        name: &[u8],
        change_kind: ChangeKind,
        mode: u32,
        commit_id: u32,
        parent_idx: u8,
    ) -> Result<(), TreeDiffError> {
        // Temporarily append the leaf name to the current path prefix.
        let full_len = self.path_buf.len() + name.len();
        if full_len > MAX_PATH_LEN {
            return Err(TreeDiffError::PathTooLong {
                len: full_len,
                max: MAX_PATH_LEN,
            });
        }

        let path_start = self.path_buf.len();
        self.path_buf.extend_from_slice(name);

        let mode_u16 = mode as u16;
        // Path classification is deferred until post-dedupe to avoid per-candidate work.
        let cand_flags = 0;

        candidates.emit(
            *oid,
            &self.path_buf,
            commit_id,
            parent_idx,
            change_kind,
            mode_u16,
            cand_flags,
        )?;

        perf_stats::sat_add_u64(&mut self.stats.candidates_emitted, 1);

        self.path_buf.truncate(path_start);

        Ok(())
    }
}

/// Computes the next action by comparing tree entries in Git tree order.
fn compute_action(
    new_entry: Option<TreeEntry<'_>>,
    old_entry: Option<TreeEntry<'_>>,
    oid_len: u8,
) -> Result<Action, TreeDiffError> {
    match (new_entry, old_entry) {
        (None, None) => Ok(Action::Pop),

        (Some(new_ent), None) => {
            let oid = convert_oid(new_ent.oid_bytes, oid_len)?;
            Ok(Action::AddedEntry {
                oid,
                kind: new_ent.kind,
                mode: new_ent.mode,
            })
        }

        (None, Some(_)) => Ok(Action::DeletedEntry),

        (Some(new_ent), Some(old_ent)) => {
            let cmp = git_tree_name_cmp(
                new_ent.name,
                new_ent.kind.is_tree(),
                old_ent.name,
                old_ent.kind.is_tree(),
            );

            match cmp {
                Ordering::Less => {
                    let oid = convert_oid(new_ent.oid_bytes, oid_len)?;
                    Ok(Action::NewBeforeOld {
                        oid,
                        kind: new_ent.kind,
                        mode: new_ent.mode,
                    })
                }
                Ordering::Greater => Ok(Action::OldBeforeNew),
                Ordering::Equal => {
                    let new_oid = convert_oid(new_ent.oid_bytes, oid_len)?;
                    let old_oid = convert_oid(old_ent.oid_bytes, oid_len)?;
                    Ok(Action::MatchedEntries {
                        new_oid,
                        old_oid,
                        new_kind: new_ent.kind,
                        old_kind: old_ent.kind,
                        new_mode: new_ent.mode,
                    })
                }
            }
        }
    }
}

/// Converts raw OID bytes into `OidBytes`, enforcing the configured length.
fn convert_oid(bytes: &[u8], oid_len: u8) -> Result<OidBytes, TreeDiffError> {
    OidBytes::try_from_slice(bytes).ok_or(TreeDiffError::InvalidOidLength {
        len: bytes.len(),
        expected: oid_len as usize,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CandidateBuffer;

    use std::collections::HashMap;
    use std::sync::atomic::AtomicBool;

    static NEVER_ABORT: AtomicBool = AtomicBool::new(false);

    struct MockTreeSource {
        trees: HashMap<OidBytes, Vec<u8>>,
    }

    impl MockTreeSource {
        fn new() -> Self {
            Self {
                trees: HashMap::new(),
            }
        }

        fn add_tree(&mut self, oid: OidBytes, data: Vec<u8>) {
            self.trees.insert(oid, data);
        }
    }

    impl TreeSource for MockTreeSource {
        fn load_tree(&mut self, oid: &OidBytes) -> Result<TreeBytes, TreeDiffError> {
            self.trees
                .get(oid)
                .cloned()
                .map(TreeBytes::Owned)
                .ok_or(TreeDiffError::TreeNotFound)
        }
    }

    fn make_entry(mode: &[u8], name: &[u8], oid: &[u8]) -> Vec<u8> {
        let mut entry = Vec::new();
        entry.extend_from_slice(mode);
        entry.push(b' ');
        entry.extend_from_slice(name);
        entry.push(0);
        entry.extend_from_slice(oid);
        entry
    }

    fn test_oid(val: u8) -> OidBytes {
        OidBytes::sha1([val; 20])
    }

    fn test_limits() -> TreeDiffLimits {
        TreeDiffLimits {
            max_candidates: 1000,
            max_tree_depth: 64,
            max_tree_bytes_in_flight: 1024 * 1024,
            ..TreeDiffLimits::RESTRICTIVE
        }
    }

    #[test]
    fn diff_identical_trees() {
        let mut source = MockTreeSource::new();
        let oid = test_oid(1);
        let data = make_entry(b"100644", b"file.txt", &[0xab; 20]);
        source.add_tree(oid, data);

        let limits = test_limits();
        let mut walker = TreeDiffWalker::new(&limits, 20);
        let mut candidates = CandidateBuffer::new(&limits, 20);

        walker
            .diff_trees(
                &mut source,
                &mut candidates,
                Some(&oid),
                Some(&oid),
                1,
                0,
                &NEVER_ABORT,
            )
            .unwrap();

        assert!(candidates.is_empty());
    }

    #[test]
    fn subtree_skipped_when_unchanged() {
        let mut source = MockTreeSource::new();

        let subdir_oid = test_oid(10);
        source.add_tree(subdir_oid, make_entry(b"100644", b"file.txt", &[0xab; 20]));

        let old_root = test_oid(1);
        source.add_tree(
            old_root,
            make_entry(b"40000", b"subdir", subdir_oid.as_slice()),
        );

        let new_root = test_oid(2);
        source.add_tree(
            new_root,
            make_entry(b"40000", b"subdir", subdir_oid.as_slice()),
        );

        let limits = test_limits();
        let mut walker = TreeDiffWalker::new(&limits, 20);
        let mut candidates = CandidateBuffer::new(&limits, 20);

        walker
            .diff_trees(
                &mut source,
                &mut candidates,
                Some(&new_root),
                Some(&old_root),
                1,
                0,
                &NEVER_ABORT,
            )
            .unwrap();

        assert!(candidates.is_empty());
        crate::test_utils::assert_perf_u64(walker.stats().subtrees_skipped, 1);
    }

    #[test]
    fn depth_limit_enforced() {
        let mut source = MockTreeSource::new();

        let file_oid = [0xab; 20];

        let c_tree = test_oid(13);
        source.add_tree(c_tree, make_entry(b"100644", b"file.txt", &file_oid));

        let b_tree = test_oid(12);
        source.add_tree(b_tree, make_entry(b"40000", b"c", c_tree.as_slice()));

        let a_tree = test_oid(11);
        source.add_tree(a_tree, make_entry(b"40000", b"b", b_tree.as_slice()));

        let root = test_oid(1);
        source.add_tree(root, make_entry(b"40000", b"a", a_tree.as_slice()));

        let limits = TreeDiffLimits {
            max_tree_depth: 2,
            ..test_limits()
        };
        let mut walker = TreeDiffWalker::new(&limits, 20);
        let mut candidates = CandidateBuffer::new(&limits, 20);

        let result = walker.diff_trees(
            &mut source,
            &mut candidates,
            Some(&root),
            None,
            1,
            0,
            &NEVER_ABORT,
        );

        assert!(matches!(
            result,
            Err(TreeDiffError::MaxTreeDepthExceeded { max_depth: 2 })
        ));
    }

    #[test]
    fn budget_error_releases_in_flight_bytes_for_retry() {
        let mut source = MockTreeSource::new();

        let new_oid = test_oid(1);
        let new_data = make_entry(b"100644", b"new.txt", &[0xaa; 20]);
        source.add_tree(new_oid, new_data.clone());

        let old_oid = test_oid(2);
        let old_data = make_entry(b"100644", b"old.txt", &[0xbb; 20]);
        source.add_tree(old_oid, old_data);

        let limits = TreeDiffLimits {
            max_tree_bytes_in_flight: new_data.len() as u64,
            ..test_limits()
        };
        let mut walker = TreeDiffWalker::new(&limits, 20);

        let mut first_candidates = CandidateBuffer::new(&limits, 20);
        let first = walker.diff_trees(
            &mut source,
            &mut first_candidates,
            Some(&new_oid),
            Some(&old_oid),
            1,
            0,
            &NEVER_ABORT,
        );
        assert!(matches!(
            first,
            Err(TreeDiffError::TreeBytesBudgetExceeded { .. })
        ));
        assert_eq!(walker.tree_bytes_in_flight, 0);

        let mut retry_candidates = CandidateBuffer::new(&limits, 20);
        walker
            .diff_trees(
                &mut source,
                &mut retry_candidates,
                Some(&new_oid),
                None,
                2,
                0,
                &NEVER_ABORT,
            )
            .unwrap();

        let resolved: Vec<_> = retry_candidates.iter_resolved().collect();
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].path, b"new.txt");
        assert_eq!(resolved[0].change_kind, ChangeKind::Add);
    }

    #[test]
    fn depth_error_releases_in_flight_bytes_for_retry() {
        let mut source = MockTreeSource::new();

        let file_oid = [0xab; 20];

        let c_tree = test_oid(13);
        source.add_tree(c_tree, make_entry(b"100644", b"file.txt", &file_oid));

        let b_tree = test_oid(12);
        source.add_tree(b_tree, make_entry(b"40000", b"c", c_tree.as_slice()));

        let a_tree = test_oid(11);
        source.add_tree(a_tree, make_entry(b"40000", b"b", b_tree.as_slice()));

        let deep_root = test_oid(1);
        source.add_tree(deep_root, make_entry(b"40000", b"a", a_tree.as_slice()));

        let retry_root = test_oid(3);
        source.add_tree(retry_root, make_entry(b"100644", b"retry.txt", &[0xcd; 20]));

        let limits = TreeDiffLimits {
            max_tree_depth: 2,
            max_tree_bytes_in_flight: 64,
            ..test_limits()
        };
        let mut walker = TreeDiffWalker::new(&limits, 20);

        let mut first_candidates = CandidateBuffer::new(&limits, 20);
        let first = walker.diff_trees(
            &mut source,
            &mut first_candidates,
            Some(&deep_root),
            None,
            1,
            0,
            &NEVER_ABORT,
        );
        assert!(matches!(
            first,
            Err(TreeDiffError::MaxTreeDepthExceeded { max_depth: 2 })
        ));
        assert!(walker.stack.is_empty());
        assert_eq!(walker.tree_bytes_in_flight, 0);

        let mut retry_candidates = CandidateBuffer::new(&limits, 20);
        walker
            .diff_trees(
                &mut source,
                &mut retry_candidates,
                Some(&retry_root),
                None,
                2,
                0,
                &NEVER_ABORT,
            )
            .unwrap();

        let resolved: Vec<_> = retry_candidates.iter_resolved().collect();
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].path, b"retry.txt");
        assert_eq!(resolved[0].change_kind, ChangeKind::Add);
    }

    #[test]
    fn gitlink_skipped() {
        let mut source = MockTreeSource::new();

        let new_oid = test_oid(1);
        let data = make_entry(b"160000", b"submodule", &[0xab; 20]);
        source.add_tree(new_oid, data);

        let limits = test_limits();
        let mut walker = TreeDiffWalker::new(&limits, 20);
        let mut candidates = CandidateBuffer::new(&limits, 20);

        walker
            .diff_trees(
                &mut source,
                &mut candidates,
                Some(&new_oid),
                None,
                1,
                0,
                &NEVER_ABORT,
            )
            .unwrap();

        assert!(candidates.is_empty());
    }

    #[test]
    fn gitlink_to_blob_emits_candidate() {
        let mut source = MockTreeSource::new();

        let old_oid = test_oid(1);
        source.add_tree(old_oid, make_entry(b"160000", b"module", &[0xaa; 20]));

        let new_oid = test_oid(2);
        let blob_oid = [0xbb; 20];
        source.add_tree(new_oid, make_entry(b"100644", b"module", &blob_oid));

        let limits = test_limits();
        let mut walker = TreeDiffWalker::new(&limits, 20);
        let mut candidates = CandidateBuffer::new(&limits, 20);

        walker
            .diff_trees(
                &mut source,
                &mut candidates,
                Some(&new_oid),
                Some(&old_oid),
                1,
                0,
                &NEVER_ABORT,
            )
            .unwrap();

        assert_eq!(candidates.len(), 1);
        let resolved: Vec<_> = candidates.iter_resolved().collect();
        assert_eq!(resolved[0].path, b"module");
        assert_eq!(resolved[0].change_kind, ChangeKind::Add);
    }

    #[test]
    fn blob_to_gitlink_skipped() {
        let mut source = MockTreeSource::new();

        let old_oid = test_oid(1);
        source.add_tree(old_oid, make_entry(b"100644", b"module", &[0xaa; 20]));

        let new_oid = test_oid(2);
        source.add_tree(new_oid, make_entry(b"160000", b"module", &[0xbb; 20]));

        let limits = test_limits();
        let mut walker = TreeDiffWalker::new(&limits, 20);
        let mut candidates = CandidateBuffer::new(&limits, 20);

        walker
            .diff_trees(
                &mut source,
                &mut candidates,
                Some(&new_oid),
                Some(&old_oid),
                1,
                0,
                &NEVER_ABORT,
            )
            .unwrap();

        assert!(candidates.is_empty());
    }

    #[test]
    fn file_becomes_directory() {
        let mut source = MockTreeSource::new();

        let old_oid = test_oid(1);
        source.add_tree(old_oid, make_entry(b"100644", b"foo", &[0xaa; 20]));

        let subdir_oid = test_oid(10);
        source.add_tree(subdir_oid, make_entry(b"100644", b"bar.txt", &[0xbb; 20]));

        let new_oid = test_oid(2);
        source.add_tree(new_oid, make_entry(b"40000", b"foo", subdir_oid.as_slice()));

        let limits = test_limits();
        let mut walker = TreeDiffWalker::new(&limits, 20);
        let mut candidates = CandidateBuffer::new(&limits, 20);

        walker
            .diff_trees(
                &mut source,
                &mut candidates,
                Some(&new_oid),
                Some(&old_oid),
                1,
                0,
                &NEVER_ABORT,
            )
            .unwrap();

        assert_eq!(candidates.len(), 1);
        let resolved: Vec<_> = candidates.iter_resolved().collect();
        assert_eq!(resolved[0].path, b"foo/bar.txt");
        assert_eq!(resolved[0].change_kind, ChangeKind::Add);
    }

    #[test]
    fn directory_becomes_file() {
        let mut source = MockTreeSource::new();

        let subdir_oid = test_oid(10);
        source.add_tree(subdir_oid, make_entry(b"100644", b"bar.txt", &[0xaa; 20]));

        let old_oid = test_oid(1);
        source.add_tree(old_oid, make_entry(b"40000", b"foo", subdir_oid.as_slice()));

        let new_oid = test_oid(2);
        let blob_oid = [0xbb; 20];
        source.add_tree(new_oid, make_entry(b"100644", b"foo", &blob_oid));

        let limits = test_limits();
        let mut walker = TreeDiffWalker::new(&limits, 20);
        let mut candidates = CandidateBuffer::new(&limits, 20);

        walker
            .diff_trees(
                &mut source,
                &mut candidates,
                Some(&new_oid),
                Some(&old_oid),
                1,
                0,
                &NEVER_ABORT,
            )
            .unwrap();

        assert_eq!(candidates.len(), 1);
        let resolved: Vec<_> = candidates.iter_resolved().collect();
        assert_eq!(resolved[0].path, b"foo");
        assert_eq!(resolved[0].change_kind, ChangeKind::Add);
    }

    #[test]
    fn path_too_long_rejected() {
        let mut source = MockTreeSource::new();

        let long_name = vec![b'a'; 2000];
        let file_oid = [0xab; 20];

        let l3_oid = test_oid(13);
        source.add_tree(l3_oid, make_entry(b"100644", b"f.txt", &file_oid));

        let l2_oid = test_oid(12);
        source.add_tree(l2_oid, make_entry(b"40000", &long_name, l3_oid.as_slice()));

        let l1_oid = test_oid(11);
        source.add_tree(l1_oid, make_entry(b"40000", &long_name, l2_oid.as_slice()));

        let root = test_oid(1);
        source.add_tree(root, make_entry(b"40000", &long_name, l1_oid.as_slice()));

        let limits = test_limits();
        let mut walker = TreeDiffWalker::new(&limits, 20);
        let mut candidates = CandidateBuffer::new(&limits, 20);

        let result = walker.diff_trees(
            &mut source,
            &mut candidates,
            Some(&root),
            None,
            1,
            0,
            &NEVER_ABORT,
        );

        assert!(matches!(result, Err(TreeDiffError::PathTooLong { .. })));
    }

    #[test]
    fn stats_tracking() {
        let mut source = MockTreeSource::new();

        let new_oid = test_oid(1);
        let data = make_entry(b"100644", b"file.txt", &[0xab; 20]);
        source.add_tree(new_oid, data.clone());

        let limits = test_limits();
        let mut walker = TreeDiffWalker::new(&limits, 20);
        let mut candidates = CandidateBuffer::new(&limits, 20);

        walker
            .diff_trees(
                &mut source,
                &mut candidates,
                Some(&new_oid),
                None,
                1,
                0,
                &NEVER_ABORT,
            )
            .unwrap();

        let stats = walker.stats();
        crate::test_utils::assert_perf_u64(stats.trees_loaded, 1);
        if cfg!(all(feature = "perf-stats", debug_assertions)) {
            assert_eq!(stats.tree_bytes_loaded as usize, data.len());
        } else {
            assert_eq!(stats.tree_bytes_loaded, 0);
        }
        crate::test_utils::assert_perf_u64(stats.candidates_emitted, 1);
    }

    #[test]
    fn stats_reset() {
        let mut source = MockTreeSource::new();
        let oid = test_oid(1);
        source.add_tree(oid, make_entry(b"100644", b"file.txt", &[0xab; 20]));

        let limits = test_limits();
        let mut walker = TreeDiffWalker::new(&limits, 20);
        let mut candidates = CandidateBuffer::new(&limits, 20);

        walker
            .diff_trees(
                &mut source,
                &mut candidates,
                Some(&oid),
                None,
                1,
                0,
                &NEVER_ABORT,
            )
            .unwrap();
        crate::test_utils::assert_perf_u64(walker.stats().candidates_emitted, 1);

        walker.reset_stats();
        assert_eq!(walker.stats().candidates_emitted, 0);
        assert_eq!(walker.stats().trees_loaded, 0);
    }

    #[test]
    fn stack_reused_across_calls() {
        let mut source = MockTreeSource::new();

        let oid1 = test_oid(1);
        source.add_tree(oid1, make_entry(b"100644", b"a.txt", &[0xaa; 20]));

        let oid2 = test_oid(2);
        source.add_tree(oid2, make_entry(b"100644", b"b.txt", &[0xbb; 20]));

        let limits = test_limits();
        let mut walker = TreeDiffWalker::new(&limits, 20);
        let mut candidates = CandidateBuffer::new(&limits, 20);

        walker
            .diff_trees(
                &mut source,
                &mut candidates,
                Some(&oid1),
                None,
                1,
                0,
                &NEVER_ABORT,
            )
            .unwrap();
        walker
            .diff_trees(
                &mut source,
                &mut candidates,
                Some(&oid2),
                None,
                2,
                0,
                &NEVER_ABORT,
            )
            .unwrap();

        assert_eq!(candidates.len(), 2);
    }

    #[test]
    fn symlink_emits_candidate() {
        let mut source = MockTreeSource::new();

        let new_oid = test_oid(1);
        let link_target_oid = [0xab; 20];
        let data = make_entry(b"120000", b"link", &link_target_oid);
        source.add_tree(new_oid, data);

        let limits = test_limits();
        let mut walker = TreeDiffWalker::new(&limits, 20);
        let mut candidates = CandidateBuffer::new(&limits, 20);

        walker
            .diff_trees(
                &mut source,
                &mut candidates,
                Some(&new_oid),
                None,
                1,
                0,
                &NEVER_ABORT,
            )
            .unwrap();

        assert_eq!(candidates.len(), 1);
    }

    #[test]
    fn abort_returns_cleanly_before_tree_walk() {
        let mut source = MockTreeSource::new();

        let new_oid = test_oid(1);
        source.add_tree(new_oid, make_entry(b"100644", b"file.txt", &[0xab; 20]));

        let limits = test_limits();
        let mut walker = TreeDiffWalker::new(&limits, 20);
        let mut candidates = CandidateBuffer::new(&limits, 20);
        let abort = AtomicBool::new(true);

        let result = walker.diff_trees(
            &mut source,
            &mut candidates,
            Some(&new_oid),
            None,
            1,
            0,
            &abort,
        );

        assert!(matches!(result, Err(TreeDiffError::Aborted)));
        assert!(walker.stack.is_empty());
        assert_eq!(walker.tree_bytes_in_flight, 0);
        assert!(candidates.is_empty());
    }
}

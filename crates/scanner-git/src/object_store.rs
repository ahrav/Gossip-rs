//! Object store abstraction for tree loading.
//!
//! Provides a pack/loose-backed object loader that returns raw tree
//! payload bytes (no `tree <size>\0` header). This is used by the
//! tree diff walker to avoid blob reads while traversing trees.
//! Tree payloads are cached in a fixed-size, set-associative tree cache
//! to avoid repeated inflations of hot subtrees. A separate delta base
//! cache keyed by `(pack_id, offset)` reuses decompressed tree bases when
//! resolving pack delta chains.
//!
//! # Contract
//! Implementations must return the raw, decompressed tree payload (no
//! header). Callers assume the returned buffer contains a sequence of
//! tree entries in Git tree order.
//!
//! # Lookup Order
//! - MIDX lookup into pack files (including delta resolution)
//! - Loose objects in `objects/` and alternates (if present)
//!
//! # Invariants
//! - `max_object_bytes` caps all inflated payloads and delta buffers
//! - Delta chains are bounded by `MAX_DELTA_DEPTH`
//! - `repo.mmaps.midx` must be populated before opening the store
//! - Tree cache is best-effort: oversize payloads are not cached
//! - Tree delta cache is best-effort: oversize bases are not cached
//! - Spill arena stores large tree payloads in a fixed-size mmapped file;
//!   spill indexing is best-effort and may disable itself when full
//! - `ObjectStore` is worker-local (`&mut self` API) and not shared
//!
//! # Load Pipeline
//! - Validate OID length
//! - Check tree cache for a pinned payload
//! - Check spill index for spilled payloads
//! - Load the object from pack or loose storage
//! - Verify the object kind is `tree`
//! - Spill large payloads (best-effort), otherwise insert into cache
//!
//! When the `git-perf` feature is enabled, tree-load cache/spill hit rates and
//! decode timings are recorded via the global perf counters.
//!
//! # Spill/Cache Behavior
//! Small payloads stay in RAM. Large payloads can be written to the spill arena
//! and optionally indexed for fast lookup. The spill index is open-addressed
//! and never deletes entries; once full, it is disabled and lookups fall back
//! to pack/loose reads.
//!
//! # Error semantics
//! - Missing objects surface as `TreeDiffError::TreeNotFound`.
//! - Non-tree objects surface as `TreeDiffError::NotATree`.
//! - Corrupt loose objects surface as `TreeDiffError::CorruptTree`.
//!
//! # Ordering
//! Pack lookup is attempted before loose objects. This mirrors typical Git
//! layouts where packs are the primary store and loose objects are a fallback.

use super::bytes::BytesView;
use std::fs;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::errors::TreeDiffError;
use super::midx::MidxView;
use super::object_id::OidBytes;
use super::pack_inflate::{
    apply_delta, inflate_exact_with, inflate_limited, inflate_limited_with, EntryKind, ObjectKind,
    PackFile, PackHeader,
};
use super::repo_open::RepoJobState;
use super::repo_paths;
use super::spill_arena::{SpillArena, SpillArenaError, SpillSlice};
use super::tree_cache::{TreeCache, TreeCacheHandle};
use super::tree_delta_cache::{TreeDeltaCache, TreeDeltaCacheHandle};
use super::tree_diff_limits::TreeDiffLimits;
use scanner_engine::perf_counters as perf;

/// Maximum entry header bytes to parse in pack files.
const MAX_ENTRY_HEADER_BYTES: usize = 64;
/// Maximum depth for delta chains.
const MAX_DELTA_DEPTH: u8 = 64;
/// Safety allowance for loose object headers (`"<type> <size>\0"`).
const LOOSE_HEADER_MAX_BYTES: usize = 64;
/// Minimum number of spill-index slots (power of two).
const MIN_SPILL_INDEX_ENTRIES: usize = 64;
/// Maximum number of spill-index slots (power of two).
const MAX_SPILL_INDEX_ENTRIES: usize = 1_048_576;

/// Fixed spill-index slot storing an OID key and spill offset/length.
///
/// `key_len == 0` denotes an empty slot. Entries are never deleted.
/// `key_bytes` is sized for the maximum supported OID (SHA-256); `key_len`
/// records the actual length (SHA-1 or SHA-256).
#[derive(Clone, Copy, Debug)]
struct SpillIndexEntry {
    key_len: u8,
    key_bytes: [u8; 32],
    offset: u64,
    len: u64,
}

impl SpillIndexEntry {
    const EMPTY: Self = Self {
        key_len: 0,
        key_bytes: [0u8; 32],
        offset: 0,
        len: 0,
    };

    fn is_empty(&self) -> bool {
        self.key_len == 0
    }

    fn matches(&self, oid: &OidBytes) -> bool {
        self.key_len == oid.len() && &self.key_bytes[..self.key_len as usize] == oid.as_slice()
    }

    fn set(&mut self, oid: &OidBytes, offset: u64, len: u64) {
        self.key_len = oid.len();
        self.key_bytes.fill(0);
        self.key_bytes[..oid.len() as usize].copy_from_slice(oid.as_slice());
        self.offset = offset;
        self.len = len;
    }
}

/// Fixed-size open-addressed hash table for spilled tree payloads.
///
/// Uses linear probing with OID-derived hashing (first 8 bytes of the OID
/// read as a little-endian u64). There are no tombstones; once all slots are
/// occupied, inserts fail and callers may disable indexing. This keeps lookup
/// and insert logic simple and deterministic at the cost of best-effort
/// behavior under high spill pressure.
///
/// Invariants:
/// - `slots.len()` is power-of-two so masking is cheap.
/// - `key_len == 0` marks an empty slot; no deletions are performed.
/// - An empty `slots` disables indexing (lookups return `None`).
/// - Inserts are best-effort; once full, callers can disable indexing.
#[derive(Debug)]
struct SpillIndex {
    mask: usize,
    slots: Vec<SpillIndexEntry>,
}

impl SpillIndex {
    /// Creates an index with best-effort capacity clamping.
    ///
    /// `entries == 0` disables indexing entirely.
    fn new(entries: usize) -> Self {
        if entries == 0 {
            return Self {
                mask: 0,
                slots: Vec::new(),
            };
        }

        let entries = entries.clamp(MIN_SPILL_INDEX_ENTRIES, MAX_SPILL_INDEX_ENTRIES);
        let entries = entries.next_power_of_two();
        let slots = vec![SpillIndexEntry::EMPTY; entries];
        Self {
            mask: entries - 1,
            slots,
        }
    }

    /// Returns the spill location for `oid` if present.
    ///
    /// Because the table has no tombstones, probing can stop on the first
    /// empty slot without risking false negatives.
    fn lookup(&self, oid: &OidBytes) -> Option<(u64, u64)> {
        if self.slots.is_empty() {
            return None;
        }

        let mut idx = (repo_paths::hash_oid(oid) as usize) & self.mask;
        for _ in 0..self.slots.len() {
            let entry = &self.slots[idx];
            if entry.is_empty() {
                return None;
            }
            if entry.matches(oid) {
                return Some((entry.offset, entry.len));
            }
            idx = (idx + 1) & self.mask;
        }
        None
    }

    /// Inserts or updates an OID -> spill location mapping.
    ///
    /// Returns `false` when indexing is disabled or the table is full.
    fn insert(&mut self, oid: &OidBytes, offset: u64, len: u64) -> bool {
        if self.slots.is_empty() {
            return false;
        }

        let mut idx = (repo_paths::hash_oid(oid) as usize) & self.mask;
        for _ in 0..self.slots.len() {
            let entry = &mut self.slots[idx];
            if entry.is_empty() || entry.matches(oid) {
                entry.set(oid, offset, len);
                return true;
            }
            idx = (idx + 1) & self.mask;
        }
        false
    }
}

/// Abstraction for loading raw tree payloads by OID.
///
/// Implementations resolve a Git tree object and return its decompressed
/// payload (without the `tree <size>\0` header). The `ObjectStore` in this
/// module is the primary implementation, backed by MIDX pack lookups, loose
/// objects, and a tree cache.
pub trait TreeSource {
    /// Loads a tree object by OID.
    ///
    /// Implementations may allocate per call; higher-level caches can lend
    /// pinned payloads to avoid repeated inflations of hot subtrees.
    /// Returned bytes are treated as read-only and are not retained by the
    /// caller beyond the `TreeBytes` value.
    ///
    /// # Contract
    /// - The returned bytes are the tree payload only (no loose header).
    /// - Missing objects should map to `TreeDiffError::TreeNotFound`.
    /// - Objects that are not trees should map to `TreeDiffError::NotATree`.
    ///
    /// # Errors
    /// - `TreeNotFound` if the object doesn't exist
    /// - `NotATree` if the object exists but isn't a tree
    fn load_tree(&mut self, oid: &OidBytes) -> Result<TreeBytes, TreeDiffError>;
}

/// Tree payload bytes returned by a `TreeSource`.
#[derive(Debug)]
pub enum TreeBytes {
    /// Borrowed bytes pinned in the tree cache.
    ///
    /// Dropping the handle releases the pin and may allow eviction.
    Cached(TreeCacheHandle),
    /// Owned bytes (e.g., from pack/loose reads).
    Owned(Vec<u8>),
    /// Bytes stored in the spill arena.
    ///
    /// The underlying spill arena must outlive the returned `TreeBytes` for
    /// the slice to remain valid.
    Spilled(SpillSlice),
}

impl TreeBytes {
    /// Returns an empty tree payload.
    #[must_use]
    pub fn empty() -> Self {
        Self::Owned(Vec::new())
    }

    /// Returns the tree payload as a byte slice.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        match self {
            Self::Cached(handle) => handle.as_slice(),
            Self::Owned(buf) => buf.as_slice(),
            Self::Spilled(slice) => slice.as_slice(),
        }
    }

    /// Returns the payload length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.as_slice().len()
    }

    /// Returns the RAM-resident byte count of this payload.
    ///
    /// Spilled payloads return 0 because their bytes live in the memory-mapped
    /// spill arena and do not count against the in-flight memory budget.
    /// Cached and owned payloads return their full length.
    #[must_use]
    pub fn in_flight_len(&self) -> usize {
        match self {
            Self::Cached(handle) => handle.as_slice().len(),
            Self::Owned(buf) => buf.len(),
            Self::Spilled(_) => 0,
        }
    }

    /// Returns true if the payload is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.as_slice().is_empty()
    }
}

/// Scratch buffers reused across delta resolution hops.
///
/// Eliminates per-hop `Vec::new()` / `Vec::with_capacity()` allocations
/// in [`ObjectStore::read_pack_object`]. The decompressor is reset before
/// each inflate call so no stale state leaks between objects.
///
/// # Buffer ping-pong protocol
///
/// During unwind, `base_buf` and `result_buf` alternate roles:
///
/// 1. Delta payload is inflated into `inflate_buf`.
/// 2. `apply_delta(base_buf, inflate_buf, result_buf, …)` produces output.
/// 3. For non-final frames, `swap(&mut base_buf, &mut result_buf)` so the
///    result becomes the base for the next frame.
///
/// The final frame leaves output in `result_buf`, which is moved to the
/// caller while `base_buf` stays allocated for reuse.
struct TreeDecodeBufs {
    de: flate2::Decompress,
    inflate_buf: Vec<u8>,
    result_buf: Vec<u8>,
    base_buf: Vec<u8>,
    delta_stack_pool: Vec<Vec<TreeDeltaFrame>>,
}

/// Owned scratch state temporarily detached across recursive REF-delta loads.
///
/// Holding these buffers outside [`TreeDecodeBufs`] makes the aliasing boundary
/// explicit: recursive loads operate on a fresh scratch session and cannot
/// mutate an outer frame's in-flight decode buffers.
#[derive(Debug)]
struct DetachedDecodeScratch {
    de: flate2::Decompress,
    inflate_buf: Vec<u8>,
    result_buf: Vec<u8>,
    base_buf: Vec<u8>,
}

impl std::fmt::Debug for TreeDecodeBufs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TreeDecodeBufs")
            .field("inflate_buf.cap", &self.inflate_buf.capacity())
            .field("result_buf.cap", &self.result_buf.capacity())
            .field("base_buf.cap", &self.base_buf.capacity())
            .field("delta_stack_pool.len", &self.delta_stack_pool.len())
            .finish()
    }
}

impl TreeDecodeBufs {
    fn new() -> Self {
        Self {
            de: flate2::Decompress::new(true),
            inflate_buf: Vec::new(),
            result_buf: Vec::new(),
            base_buf: Vec::new(),
            delta_stack_pool: vec![Vec::new()],
        }
    }

    /// Leases a reusable delta-frame stack for one decode operation.
    ///
    /// Recursive REF-delta loads can borrow independent stacks from this pool.
    #[inline]
    fn take_delta_stack(&mut self) -> Vec<TreeDeltaFrame> {
        let mut stack = self.delta_stack_pool.pop().unwrap_or_default();
        stack.clear();
        stack
    }

    /// Returns a previously leased delta-frame stack to the pool.
    #[inline]
    fn return_delta_stack(&mut self, mut stack: Vec<TreeDeltaFrame>) {
        stack.clear();
        self.delta_stack_pool.push(stack);
    }

    /// Detaches decode scratch so recursive loads cannot alias outer buffers.
    fn detach_recursive_scratch(&mut self) -> DetachedDecodeScratch {
        DetachedDecodeScratch {
            de: std::mem::replace(&mut self.de, flate2::Decompress::new(true)),
            inflate_buf: std::mem::take(&mut self.inflate_buf),
            result_buf: std::mem::take(&mut self.result_buf),
            base_buf: std::mem::take(&mut self.base_buf),
        }
    }

    /// Restores scratch previously detached via `detach_recursive_scratch`.
    fn restore_recursive_scratch(&mut self, detached: DetachedDecodeScratch) {
        self.de = detached.de;
        self.inflate_buf = detached.inflate_buf;
        self.result_buf = detached.result_buf;
        self.base_buf = detached.base_buf;
    }

    /// Moves caller-owned base bytes into decode scratch without copying.
    #[inline]
    fn swap_in_base(&mut self, incoming: &mut Vec<u8>) {
        std::mem::swap(&mut self.base_buf, incoming);
    }

    /// Moves resolved bytes out of `result_buf`.
    #[inline]
    fn take_result_output(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        std::mem::swap(&mut out, &mut self.result_buf);
        out
    }
}

/// One frame of a pending delta chain collected during the walk-forward
/// phase of iterative delta resolution.
#[derive(Clone, Copy, Debug)]
struct TreeDeltaFrame {
    /// Pack offset of this delta entry (used as cache key during unwind).
    offset: u64,
    /// Byte offset where the compressed delta payload begins in the pack.
    data_start: usize,
    /// Expected decompressed delta size (from the entry header).
    delta_size: usize,
}

/// Source of loaded object bytes, used for perf accounting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ObjectSource {
    Pack,
    Loose,
}

/// Fully decoded object loaded from a pack entry.
///
/// `chain_len` counts applied delta edges; non-delta entries have `chain_len=0`.
#[derive(Debug)]
struct DecodedTreeObject {
    kind: ObjectKind,
    bytes: Vec<u8>,
    chain_len: u8,
}

/// Result of object lookup across pack and loose stores.
///
/// `chain_len` is meaningful only for pack-backed objects.
#[derive(Debug)]
struct LoadedObject {
    kind: ObjectKind,
    bytes: Vec<u8>,
    source: ObjectSource,
    chain_len: u8,
}

/// Immutable repository layout shared by object store instances.
///
/// This contains repo-level metadata that is expensive to recompute and does
/// not change per worker: parsed MIDX view, resolved pack paths, and loose
/// object directories. Callers can build one layout and open multiple
/// per-worker [`ObjectStore`] instances from it.
#[derive(Debug, Clone)]
pub(super) struct ObjectStoreLayout<'a> {
    oid_len: u8,
    midx: MidxView<'a>,
    pack_paths: Arc<[PathBuf]>,
    loose_dirs: Arc<[PathBuf]>,
}

impl<'a> ObjectStoreLayout<'a> {
    /// Builds shared object-store layout from repository artifacts.
    ///
    /// This performs MIDX parse/validation plus pack/loose directory
    /// resolution once so worker-local stores can skip repeating it.
    pub(super) fn from_repo(repo: &'a RepoJobState) -> Result<Self, TreeDiffError> {
        let midx_bytes =
            repo.mmaps
                .midx
                .as_ref()
                .ok_or_else(|| TreeDiffError::ObjectStoreError {
                    detail: "midx bytes missing".to_string(),
                })?;
        let midx =
            MidxView::parse(midx_bytes.as_slice(), repo.object_format).map_err(store_error)?;
        Self::from_midx(repo, midx)
    }

    /// Builds shared object-store layout using a pre-parsed MIDX view.
    pub(super) fn from_midx(
        repo: &RepoJobState,
        midx: MidxView<'a>,
    ) -> Result<Self, TreeDiffError> {
        let pack_dirs = repo_paths::collect_pack_dirs(&repo.paths);
        let pack_names = repo_paths::list_pack_files(&pack_dirs).map_err(store_error)?;
        // Ensure every on-disk pack file is represented in the MIDX so
        // pack lookups are complete across alternates.
        midx.verify_completeness(pack_names.iter().map(|n| n.as_slice()))
            .map_err(store_error)?;

        let pack_paths = Arc::<[PathBuf]>::from(
            repo_paths::resolve_pack_paths(&midx, &pack_dirs).map_err(store_error)?,
        );
        let loose_dirs = Arc::<[PathBuf]>::from(repo_paths::collect_loose_dirs(&repo.paths));

        Ok(Self {
            oid_len: repo.object_format.oid_len(),
            midx,
            pack_paths,
            loose_dirs,
        })
    }
}

/// Pack/loose object store for tree loading.
///
/// Holds a borrowed MIDX view (tied to the repo job's bytes view lifetime) and
/// lazily maps pack files on demand. Pack bytes are cached so iterative delta
/// resolution can borrow pack data without aliasing `self`.
///
/// The tree cache stores decompressed payloads; cache hits return pinned
/// handles so callers can borrow the bytes without copying.
///
/// Delta resolution uses iterative walk-forward + unwind phases with
/// reusable scratch buffers (`decode_bufs`) to eliminate per-hop allocations.
#[derive(Debug)]
pub struct ObjectStore<'a> {
    oid_len: u8,
    max_object_bytes: usize,
    midx: MidxView<'a>,
    pack_paths: Arc<[PathBuf]>,
    pack_cache: Vec<Option<(BytesView, PackHeader)>>,
    loose_dirs: Arc<[PathBuf]>,
    tree_cache: TreeCache,
    tree_delta_cache: TreeDeltaCache,
    /// Reusable scratch buffers for iterative delta resolution.
    decode_bufs: TreeDecodeBufs,
    spill: Option<SpillArena>,
    /// Minimum payload size to consider spilling (smaller payloads stay in RAM).
    spill_min_bytes: usize,
    /// Set when the spill arena is out of space; disables further spills.
    spill_exhausted: bool,
    /// Best-effort index for spilled payloads (OID -> offset/len).
    spill_index: SpillIndex,
    /// Set when the index fills; subsequent spills are not indexed.
    spill_index_exhausted: bool,
}

impl<'a> ObjectStore<'a> {
    /// Opens an object store for the given repository job.
    ///
    /// The store resolves pack paths from the MIDX and uses a best-effort
    /// tree cache sized by `TreeDiffLimits`.
    ///
    /// Verifies that the MIDX covers all pack files found in pack directories,
    /// including alternates, so pack lookups are complete.
    ///
    /// `spill_dir` must be an existing directory used for the spill arena
    /// backing file. It should be on a fast local filesystem (e.g., tmpfs or
    /// local SSD) to keep large-tree reads predictable.
    ///
    /// # Errors
    /// Returns `TreeDiffError::ObjectStoreError` if the MIDX is malformed
    /// or pack files cannot be resolved. `acquire_midx` must have been
    /// called to populate `repo.mmaps.midx`.
    pub fn open(
        repo: &'a RepoJobState,
        limits: &TreeDiffLimits,
        spill_dir: &Path,
    ) -> Result<Self, TreeDiffError> {
        let tree_delta_cache = TreeDeltaCache::new(limits.max_tree_delta_cache_bytes);
        Self::open_with_tree_delta_cache(repo, limits, spill_dir, tree_delta_cache)
    }

    /// Opens an object store with a caller-provided tree delta cache.
    ///
    /// This allows runners to auto-size the cache based on repository
    /// metadata while preserving the default behavior of [`Self::open`].
    ///
    /// # Errors
    /// Returns `TreeDiffError::ObjectStoreError` if the MIDX is malformed
    /// or pack files cannot be resolved. `acquire_midx` must have been
    /// called to populate `repo.mmaps.midx`.
    pub fn open_with_tree_delta_cache(
        repo: &'a RepoJobState,
        limits: &TreeDiffLimits,
        spill_dir: &Path,
        tree_delta_cache: TreeDeltaCache,
    ) -> Result<Self, TreeDiffError> {
        let layout = ObjectStoreLayout::from_repo(repo)?;
        Self::open_with_layout(&layout, limits, spill_dir, tree_delta_cache)
    }

    /// Opens an object store from a shared immutable layout.
    ///
    /// This avoids recomputing repo/pack discovery work for each store.
    pub(super) fn open_with_layout(
        layout: &ObjectStoreLayout<'a>,
        limits: &TreeDiffLimits,
        spill_dir: &Path,
        tree_delta_cache: TreeDeltaCache,
    ) -> Result<Self, TreeDiffError> {
        let pack_cache = vec![None; layout.pack_paths.len()];
        let tree_cache = TreeCache::new(limits.max_tree_cache_bytes);
        let max_object_bytes = limits.max_tree_bytes_in_flight.min(usize::MAX as u64) as usize;
        let spill = SpillArena::new(spill_dir, limits.max_tree_spill_bytes).map_err(store_error)?;
        let spill_min_bytes = limits.max_tree_cache_bytes.max(1) as usize;
        let spill_index_entries = spill_index_entries(limits.max_tree_spill_bytes, spill_min_bytes);
        let spill_index = SpillIndex::new(spill_index_entries);

        Ok(Self {
            oid_len: layout.oid_len,
            max_object_bytes,
            midx: layout.midx,
            pack_paths: Arc::clone(&layout.pack_paths),
            pack_cache,
            loose_dirs: Arc::clone(&layout.loose_dirs),
            tree_cache,
            tree_delta_cache,
            decode_bufs: TreeDecodeBufs::new(),
            spill: Some(spill),
            spill_min_bytes,
            spill_exhausted: false,
            spill_index,
            spill_index_exhausted: false,
        })
    }

    /// Returns the configured OID length.
    #[must_use]
    pub const fn oid_len(&self) -> u8 {
        self.oid_len
    }

    /// Benchmark hook for iterative pack-offset decoding.
    ///
    /// This bypasses OID lookup so Criterion can isolate delta-chain
    /// resolution costs on the object-store hot path.
    #[cfg(feature = "bench")]
    pub fn bench_decode_pack_offset(
        &mut self,
        pack_id: u16,
        offset: u64,
        depth: u8,
    ) -> Result<(ObjectKind, usize, u8), TreeDiffError> {
        let (pack, pack_header) = self.pack_data(pack_id)?;
        let decoded =
            self.read_pack_object(pack_id, pack.as_ref(), pack_header, offset, depth, None)?;
        Ok((decoded.kind, decoded.bytes.len(), decoded.chain_len))
    }

    /// Loads an object by OID, resolving deltas up to `MAX_DELTA_DEPTH`.
    ///
    /// This prefers pack files over loose objects.
    fn load_object(
        &mut self,
        oid: &OidBytes,
    ) -> Result<(ObjectKind, Vec<u8>, ObjectSource), TreeDiffError> {
        let loaded = self.load_object_with_depth(oid, MAX_DELTA_DEPTH)?;
        Ok((loaded.kind, loaded.bytes, loaded.source))
    }

    /// Loads an object with an explicit remaining delta depth.
    ///
    /// `depth` counts remaining delta edges; when it reaches 0, delta
    /// resolution stops and the call fails with a depth error.
    fn load_object_with_depth(
        &mut self,
        oid: &OidBytes,
        depth: u8,
    ) -> Result<LoadedObject, TreeDiffError> {
        // Depth is decremented per delta hop to bound recursion.
        if let Some(obj) = self.load_object_from_pack(oid, depth)? {
            return Ok(LoadedObject {
                kind: obj.kind,
                bytes: obj.bytes,
                source: ObjectSource::Pack,
                chain_len: obj.chain_len,
            });
        }
        if let Some(obj) = self.load_object_from_loose(oid)? {
            return Ok(LoadedObject {
                kind: obj.0,
                bytes: obj.1,
                source: ObjectSource::Loose,
                chain_len: 0,
            });
        }
        Err(TreeDiffError::TreeNotFound)
    }

    /// Loads an object while isolating the caller's decode scratch buffers.
    ///
    /// Recursive REF-delta loads use this boundary so the inner decode path
    /// cannot alias or overwrite outer in-flight scratch state.
    fn load_object_with_isolated_decode_scratch(
        &mut self,
        oid: &OidBytes,
        depth: u8,
    ) -> Result<LoadedObject, TreeDiffError> {
        let detached = self.decode_bufs.detach_recursive_scratch();
        let loaded = self.load_object_with_depth(oid, depth);
        self.decode_bufs.restore_recursive_scratch(detached);
        loaded
    }

    /// Loads an object from pack storage via MIDX lookup.
    ///
    /// Returns `Ok(None)` when the OID is not present in the MIDX.
    fn load_object_from_pack(
        &mut self,
        oid: &OidBytes,
        depth: u8,
    ) -> Result<Option<DecodedTreeObject>, TreeDiffError> {
        // MIDX lookups are O(log N) on the OID list and return pack offsets.
        let idx = match self.midx.find_oid(oid).map_err(store_error)? {
            Some(idx) => idx,
            None => return Ok(None),
        };

        let (pack_id, offset) = self.midx.offset_at(idx).map_err(store_error)?;
        let (pack, pack_header) = self.pack_data(pack_id)?;
        let obj = self.read_pack_object(
            pack_id,
            pack.as_ref(),
            pack_header,
            offset,
            depth,
            Some(*oid),
        )?;
        Ok(Some(obj))
    }

    /// Resolves a pack object at `offset`, iteratively unwinding any delta
    /// chain.
    ///
    /// **Phase 1 — Walk forward**: follows OFS delta base offsets (and delta
    /// cache hits) without recursion, pushing one `TreeDeltaFrame` per hop.
    /// The walk terminates when a non-delta root is reached, a delta cache
    /// hit supplies the base bytes, or a REF delta requires a cross-pack
    /// base loaded via [`Self::load_object_with_isolated_decode_scratch`].
    ///
    /// **Phase 2 — Unwind backward**: iterates the frame stack in reverse,
    /// inflating each delta payload and applying it against the current base
    /// in `decode_bufs`, swapping `base_buf`/`result_buf` after each step.
    ///
    /// Scratch buffers in `decode_bufs` are reused across calls, eliminating
    /// per-hop `Vec::new()` / `Vec::with_capacity()` allocations that the
    /// previous recursive implementation performed.
    fn read_pack_object(
        &mut self,
        pack_id: u16,
        pack_bytes: &[u8],
        pack_header: PackHeader,
        offset: u64,
        depth: u8,
        root_oid: Option<OidBytes>,
    ) -> Result<DecodedTreeObject, TreeDiffError> {
        let mut delta_stack = self.decode_bufs.take_delta_stack();
        let result = self.read_pack_object_impl(
            pack_id,
            pack_bytes,
            pack_header,
            offset,
            depth,
            root_oid,
            &mut delta_stack,
        );
        self.decode_bufs.return_delta_stack(delta_stack);
        result
    }

    #[allow(unused_assignments)] // base_kind/base_chain_len initializers
    #[allow(clippy::too_many_arguments)]
    fn read_pack_object_impl(
        &mut self,
        pack_id: u16,
        pack_bytes: &[u8],
        pack_header: PackHeader,
        offset: u64,
        depth: u8,
        root_oid: Option<OidBytes>,
        delta_stack: &mut Vec<TreeDeltaFrame>,
    ) -> Result<DecodedTreeObject, TreeDiffError> {
        let pack = PackFile::from_header(pack_bytes, pack_header);
        let max_object_bytes = self.max_object_bytes;

        // -- Phase 1: Walk forward through the delta chain -----------------
        //
        // `delta_stack` is leased from decode scratch by read_pack_object.
        // Clear it defensively so stale frames cannot leak across calls.
        // Recursive REF-delta calls lease independent stacks from the pool.
        delta_stack.clear();
        let mut current_offset = offset;
        let mut remaining_depth = depth;
        let mut base_kind: ObjectKind = ObjectKind::Tree; // set below
        let mut base_chain_len: u8 = 0; // set below
        let mut cached_base: Option<TreeDeltaCacheHandle> = None;

        loop {
            let header = pack
                .entry_header_at(current_offset, MAX_ENTRY_HEADER_BYTES)
                .map_err(|err| TreeDiffError::ObjectStoreError {
                    detail: format!(
                        "pack {pack_id} offset {current_offset}: {err}{}",
                        format_root_oid(root_oid)
                    ),
                })?;

            let payload_size =
                usize::try_from(header.size).map_err(|_| TreeDiffError::ObjectStoreError {
                    detail: format!(
                        "pack {pack_id} offset {current_offset}: object size overflow{}",
                        format_root_oid(root_oid)
                    ),
                })?;

            if payload_size > max_object_bytes {
                let label = if delta_stack.is_empty() {
                    "object size"
                } else {
                    "delta payload size"
                };
                return Err(TreeDiffError::ObjectStoreError {
                    detail: format!(
                        "pack {pack_id} offset {current_offset}: {label} {payload_size} exceeds cap {max_object_bytes}{}",
                        format_root_oid(root_oid)
                    ),
                });
            }

            match header.kind {
                EntryKind::NonDelta { kind } => {
                    // Root of the chain: direct decode for non-delta objects,
                    // otherwise decode root base for pending unwind frames.
                    let out_buf = if delta_stack.is_empty() {
                        &mut self.decode_bufs.result_buf
                    } else {
                        &mut self.decode_bufs.base_buf
                    };
                    let (inflate_result, inflate_nanos) = perf::time(|| {
                        inflate_exact_with(
                            &mut self.decode_bufs.de,
                            pack.slice_from(header.data_start),
                            out_buf,
                            payload_size,
                        )
                    });
                    inflate_result.map_err(|err| TreeDiffError::ObjectStoreError {
                        detail: format!(
                            "pack {pack_id} offset {current_offset}: {err}{}",
                            format_root_oid(root_oid)
                        ),
                    })?;
                    perf::record_tree_inflate(out_buf.len(), inflate_nanos);
                    base_kind = kind;
                    base_chain_len = 0;
                    break;
                }

                EntryKind::OfsDelta { base_offset } => {
                    if remaining_depth == 0 {
                        return Err(TreeDiffError::ObjectStoreError {
                            detail: format!(
                                "pack {pack_id} offset {current_offset}: delta chain too deep{}",
                                format_root_oid(root_oid)
                            ),
                        });
                    }

                    // Check delta cache for the base.
                    let (cache_handle, cache_nanos) =
                        perf::time(|| self.tree_delta_cache.get_handle(pack_id, base_offset));

                    if let Some(handle) = cache_handle {
                        perf::record_tree_delta_cache_hit(handle.len());
                        perf::record_tree_delta_cache_hit_nanos(cache_nanos);

                        base_kind = handle.kind();
                        base_chain_len = handle.chain_len();
                        cached_base = Some(handle);

                        // Push this delta frame for unwind.
                        delta_stack.push(TreeDeltaFrame {
                            offset: current_offset,
                            data_start: header.data_start,
                            delta_size: payload_size,
                        });
                        break;
                    }

                    perf::record_tree_delta_cache_miss();
                    perf::record_tree_delta_cache_miss_nanos(cache_nanos);

                    // Push frame and follow the base offset.
                    delta_stack.push(TreeDeltaFrame {
                        offset: current_offset,
                        data_start: header.data_start,
                        delta_size: payload_size,
                    });
                    current_offset = base_offset;
                    remaining_depth -= 1;
                }

                EntryKind::RefDelta { base_oid } => {
                    if remaining_depth == 0 {
                        return Err(TreeDiffError::ObjectStoreError {
                            detail: format!(
                                "pack {pack_id} offset {current_offset}: delta chain too deep{}",
                                format_root_oid(root_oid)
                            ),
                        });
                    }

                    // Push this delta frame.
                    delta_stack.push(TreeDeltaFrame {
                        offset: current_offset,
                        data_start: header.data_start,
                        delta_size: payload_size,
                    });

                    // Isolate outer decode scratch from recursive REF-delta
                    // loads so nested resolution cannot alias outer buffers.
                    let mut loaded = self
                        .load_object_with_isolated_decode_scratch(&base_oid, remaining_depth - 1)?;
                    base_kind = loaded.kind;
                    base_chain_len = loaded.chain_len;

                    // Move loaded bytes into base scratch (no base-byte copy).
                    self.decode_bufs.swap_in_base(&mut loaded.bytes);
                    break;
                }
            }
        }

        // -- Fast path: non-delta object (no frames pushed) ----------------
        if delta_stack.is_empty() {
            perf::record_tree_delta_chain(0);
            if base_kind == ObjectKind::Tree {
                self.tree_delta_cache.insert(
                    pack_id,
                    offset,
                    base_kind,
                    0,
                    &self.decode_bufs.result_buf,
                );
            }
            let bytes = self.decode_bufs.take_result_output();
            return Ok(DecodedTreeObject {
                kind: base_kind,
                bytes,
                chain_len: 0,
            });
        }

        // -- Phase 2: Unwind the delta stack in reverse --------------------
        let total_frames = delta_stack.len();
        for (frame_idx, frame) in delta_stack.iter().rev().enumerate() {
            let is_last_frame = frame_idx + 1 == total_frames;

            // Inflate the delta payload into inflate_buf.
            let (inflate_result, inflate_nanos) = perf::time(|| {
                inflate_limited_with(
                    &mut self.decode_bufs.de,
                    pack.slice_from(frame.data_start),
                    &mut self.decode_bufs.inflate_buf,
                    frame.delta_size,
                )
            });
            inflate_result.map_err(|err| TreeDiffError::ObjectStoreError {
                detail: format!(
                    "pack {pack_id} offset {}: delta inflate failed: {err}{}",
                    frame.offset,
                    format_root_oid(root_oid)
                ),
            })?;
            perf::record_tree_inflate(self.decode_bufs.inflate_buf.len(), inflate_nanos);

            // Apply delta: base_buf × inflate_buf → result_buf.
            // Split borrow decode_bufs fields to satisfy the borrow checker.
            let using_cached_base = cached_base.is_some();
            let (apply_result, apply_nanos) = perf::time(|| {
                let TreeDecodeBufs {
                    ref base_buf,
                    ref inflate_buf,
                    ref mut result_buf,
                    ..
                } = self.decode_bufs;
                let base_bytes = if let Some(handle) = cached_base.as_ref() {
                    handle.as_slice()
                } else {
                    base_buf.as_slice()
                };
                apply_delta(base_bytes, inflate_buf, result_buf, max_object_bytes)
            });
            apply_result.map_err(|err| TreeDiffError::ObjectStoreError {
                detail: format!(
                    "pack {pack_id} offset {}: delta apply failed: {err}{}",
                    frame.offset,
                    format_root_oid(root_oid)
                ),
            })?;
            perf::record_tree_delta_apply(self.decode_bufs.result_buf.len(), apply_nanos);

            // Release pinned cache base before touching cache mutably below.
            if using_cached_base {
                cached_base = None;
            }

            if !is_last_frame {
                // Rotate: output becomes the next base.
                std::mem::swap(
                    &mut self.decode_bufs.base_buf,
                    &mut self.decode_bufs.result_buf,
                );
            }

            base_chain_len = base_chain_len.saturating_add(1);

            // Offer intermediate result to the delta cache.
            if base_kind == ObjectKind::Tree {
                let resolved = if is_last_frame {
                    self.decode_bufs.result_buf.as_slice()
                } else {
                    self.decode_bufs.base_buf.as_slice()
                };
                self.tree_delta_cache.insert(
                    pack_id,
                    frame.offset,
                    base_kind,
                    base_chain_len,
                    resolved,
                );
            }
        }

        perf::record_tree_delta_chain(base_chain_len);
        let bytes = self.decode_bufs.take_result_output();
        Ok(DecodedTreeObject {
            kind: base_kind,
            bytes,
            chain_len: base_chain_len,
        })
    }

    fn load_object_from_loose(
        &self,
        oid: &OidBytes,
    ) -> Result<Option<(ObjectKind, Vec<u8>)>, TreeDiffError> {
        // Loose objects are stored by hex fanout: <objects>/<2-hex>/<remaining-hex>.
        let hex = repo_paths::oid_to_hex(oid);
        let (dir, file) = hex.split_at(2);
        let dir_name = String::from_utf8_lossy(dir);
        let file_name = String::from_utf8_lossy(file);

        for base in self.loose_dirs.iter() {
            let path = base.join(dir_name.as_ref()).join(file_name.as_ref());
            let data = match fs::read(&path) {
                Ok(data) => data,
                Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
                Err(err) => {
                    return Err(TreeDiffError::ObjectStoreError {
                        detail: format!("loose object read failed: {err}"),
                    });
                }
            };

            let max_out = self.max_object_bytes.saturating_add(LOOSE_HEADER_MAX_BYTES);
            let mut out = Vec::with_capacity(max_out);
            inflate_limited(&data, &mut out, max_out).map_err(store_error)?;

            // Parse and validate the loose header before returning the payload.
            let (kind, payload) = repo_paths::parse_loose_object(&out, self.max_object_bytes)
                .map_err(map_loose_parse_error)?;
            return Ok(Some((kind, payload)));
        }

        Ok(None)
    }

    /// Returns cached pack bytes and pre-parsed header for the given pack id,
    /// mapping and validating the header if needed.
    ///
    /// Caching the `PackHeader` alongside the bytes avoids re-validating the
    /// "PACK" signature, version, and recomputing `data_end` on every call to
    /// `read_pack_object` — including recursive delta chain resolution where
    /// the same pack is parsed N times for a chain of depth N.
    fn pack_data(&mut self, pack_id: u16) -> Result<(BytesView, PackHeader), TreeDiffError> {
        // Pack files are immutable during the scan. Cache their bytes so
        // recursive delta resolution can reuse pack data cheaply.
        let idx = pack_id as usize;
        let path = self
            .pack_paths
            .get(idx)
            .ok_or_else(|| TreeDiffError::ObjectStoreError {
                detail: format!("pack id {pack_id} out of bounds"),
            })?;

        if self.pack_cache.get(idx).is_none() {
            return Err(TreeDiffError::ObjectStoreError {
                detail: "pack cache index out of bounds".to_string(),
            });
        }

        if self.pack_cache[idx].is_none() {
            let file = File::open(path).map_err(|err| TreeDiffError::ObjectStoreError {
                detail: format!("failed to open pack {}: {err}", path.display()),
            })?;
            // SAFETY: `Mmap::map` requires that the file is not concurrently
            // truncated or modified while mapped. Pack files are immutable in
            // a well-formed Git repository (writes create new packs). We also
            // detect concurrent maintenance via lock-file and fingerprint checks
            // in `artifacts_unchanged`. The mapping is read-only; we never
            // mutate through it.
            let mmap = unsafe {
                memmap2::Mmap::map(&file).map_err(|err| TreeDiffError::ObjectStoreError {
                    detail: format!("failed to mmap pack {}: {err}", path.display()),
                })?
            };
            let bv = BytesView::from_mmap(mmap);
            let header =
                PackFile::parse_header(bv.as_ref(), self.oid_len as usize).map_err(|err| {
                    TreeDiffError::ObjectStoreError {
                        detail: format!("pack {} header: {err}", path.display()),
                    }
                })?;
            self.pack_cache[idx] = Some((bv, header));
        }

        let (bv, header) = self.pack_cache[idx].as_ref().expect("pack bytes present");
        Ok((bv.clone(), *header))
    }

    /// Attempts to write a large payload into the spill arena.
    ///
    /// This is best-effort by design:
    /// - Small payloads remain in RAM.
    /// - Arena out-of-space disables future spills.
    /// - Index insert failure disables future index updates but still permits
    ///   arena appends.
    fn try_spill(
        &mut self,
        oid: &OidBytes,
        bytes: &[u8],
    ) -> Result<Option<SpillSlice>, TreeDiffError> {
        // Spilling is best-effort: we only spill large payloads and stop once
        // the arena reports out-of-space. Indexing is optional and can be
        // disabled if the table fills to avoid unbounded probe costs.
        if self.spill_exhausted || bytes.len() < self.spill_min_bytes {
            return Ok(None);
        }

        let Some(spill) = self.spill.as_mut() else {
            return Ok(None);
        };

        match spill.append(bytes) {
            Ok(slice) => {
                if !self.spill_index_exhausted {
                    let inserted = self.spill_index.insert(oid, slice.offset(), slice.len());
                    if !inserted {
                        // Index is full: keep spilling but stop indexing to avoid costly probes.
                        self.spill_index_exhausted = true;
                    }
                }
                Ok(Some(slice))
            }
            Err(SpillArenaError::OutOfSpace { .. }) => {
                self.spill_exhausted = true;
                Ok(None)
            }
            Err(err) => Err(TreeDiffError::ObjectStoreError {
                detail: err.to_string(),
            }),
        }
    }
}

impl TreeSource for ObjectStore<'_> {
    /// Loads and validates a tree payload.
    ///
    /// Lookup order is cache -> spill index -> pack/loose object store. Non-tree
    /// objects are rejected even if the OID resolves successfully.
    fn load_tree(&mut self, oid: &OidBytes) -> Result<TreeBytes, TreeDiffError> {
        let (result, nanos) = perf::time(|| {
            if oid.len() != self.oid_len {
                return Err(TreeDiffError::InvalidOidLength {
                    len: oid.len() as usize,
                    expected: self.oid_len as usize,
                });
            }

            if let Some(handle) = self.tree_cache.get_handle(oid) {
                perf::record_tree_cache_hit();
                return Ok(TreeBytes::Cached(handle));
            }

            if let Some((offset, len)) = self.spill_index.lookup(oid) {
                if let Some(spill) = self.spill.as_ref() {
                    perf::record_tree_spill_hit();
                    return Ok(TreeBytes::Spilled(spill.slice(offset, len)));
                }
            }

            let (obj_res, load_nanos) = perf::time(|| self.load_object(oid));
            let (kind, data, source) = obj_res?;
            perf::record_tree_object(data.len(), load_nanos, source == ObjectSource::Pack);

            if kind != ObjectKind::Tree {
                return Err(TreeDiffError::NotATree);
            }

            if let Some(slice) = self.try_spill(oid, &data)? {
                return Ok(TreeBytes::Spilled(slice));
            }

            // Cache is best-effort; failures are ignored.
            self.tree_cache.insert(*oid, &data);
            Ok(TreeBytes::Owned(data))
        });

        let bytes = result.as_ref().map(|payload| payload.len()).unwrap_or(0);
        perf::record_tree_load(bytes, nanos);
        result
    }
}

/// Computes the spill index capacity from spill size and spill threshold.
///
/// The result is clamped to a power-of-two range to bound RAM usage while
/// still allowing O(1) indexing for the largest spilled trees.
fn spill_index_entries(max_spill_bytes: u64, spill_min_bytes: usize) -> usize {
    if max_spill_bytes == 0 {
        return 0;
    }

    let min_bytes = spill_min_bytes.max(1) as u64;
    let mut entries = max_spill_bytes / min_bytes;
    if entries == 0 {
        entries = 1;
    }
    if entries > MAX_SPILL_INDEX_ENTRIES as u64 {
        entries = MAX_SPILL_INDEX_ENTRIES as u64;
    }
    let entries = entries as usize;
    let entries = entries.max(MIN_SPILL_INDEX_ENTRIES);
    entries.next_power_of_two()
}

/// Normalizes foreign errors into object-store context.
fn store_error<E: std::fmt::Display>(err: E) -> TreeDiffError {
    TreeDiffError::ObjectStoreError {
        detail: err.to_string(),
    }
}

/// Maps shared loose-object parse errors into object-store error variants.
fn map_loose_parse_error(err: repo_paths::LooseObjectParseError) -> TreeDiffError {
    match err {
        repo_paths::LooseObjectParseError::MissingHeaderTerminator => TreeDiffError::CorruptTree {
            detail: "missing object header terminator",
        },
        repo_paths::LooseObjectParseError::MissingKind => TreeDiffError::CorruptTree {
            detail: "missing object kind",
        },
        repo_paths::LooseObjectParseError::MissingSize => TreeDiffError::CorruptTree {
            detail: "missing object size",
        },
        repo_paths::LooseObjectParseError::InvalidHeader => TreeDiffError::CorruptTree {
            detail: "invalid object header",
        },
        repo_paths::LooseObjectParseError::InvalidSize => TreeDiffError::CorruptTree {
            detail: "invalid object size",
        },
        repo_paths::LooseObjectParseError::SizeExceedsCap { size, max_payload } => {
            TreeDiffError::ObjectStoreError {
                detail: format!("object size {size} exceeds cap {max_payload}"),
            }
        }
        repo_paths::LooseObjectParseError::SizeMismatch => TreeDiffError::CorruptTree {
            detail: "object size mismatch",
        },
        repo_paths::LooseObjectParseError::UnknownType => TreeDiffError::ObjectStoreError {
            detail: "unknown loose object type".to_string(),
        },
    }
}

/// Formats the root OID suffix used in pack decode diagnostics.
fn format_root_oid(root_oid: Option<OidBytes>) -> String {
    match root_oid {
        Some(oid) => format!(" (root oid {oid})"),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::TreeDecodeBufs;

    #[test]
    fn detached_recursive_scratch_restores_outer_buffers() {
        let mut bufs = TreeDecodeBufs::new();
        bufs.inflate_buf.extend_from_slice(b"inflate");
        bufs.result_buf.extend_from_slice(b"result");
        bufs.base_buf.extend_from_slice(b"base");

        let detached = bufs.detach_recursive_scratch();
        assert!(bufs.inflate_buf.is_empty());
        assert!(bufs.result_buf.is_empty());
        assert!(bufs.base_buf.is_empty());

        bufs.inflate_buf.extend_from_slice(b"inner-inflate");
        bufs.result_buf.extend_from_slice(b"inner-result");
        bufs.base_buf.extend_from_slice(b"inner-base");

        bufs.restore_recursive_scratch(detached);
        assert_eq!(bufs.inflate_buf.as_slice(), b"inflate");
        assert_eq!(bufs.result_buf.as_slice(), b"result");
        assert_eq!(bufs.base_buf.as_slice(), b"base");
    }

    #[test]
    fn detached_recursive_scratch_nests_by_ownership() {
        let mut bufs = TreeDecodeBufs::new();
        bufs.base_buf.extend_from_slice(b"outer");

        let outer = bufs.detach_recursive_scratch();
        bufs.base_buf.extend_from_slice(b"middle");

        let middle = bufs.detach_recursive_scratch();
        bufs.base_buf.extend_from_slice(b"inner");

        bufs.restore_recursive_scratch(middle);
        assert_eq!(bufs.base_buf.as_slice(), b"middle");

        bufs.restore_recursive_scratch(outer);
        assert_eq!(bufs.base_buf.as_slice(), b"outer");
    }

    #[test]
    fn swap_in_base_moves_vec_ownership_without_copy() {
        let mut bufs = TreeDecodeBufs::new();
        bufs.base_buf.extend_from_slice(b"outer-base");
        let old_base_ptr = bufs.base_buf.as_ptr();

        let mut incoming = Vec::from(&b"incoming-base"[..]);
        let incoming_ptr = incoming.as_ptr();

        bufs.swap_in_base(&mut incoming);

        assert_eq!(bufs.base_buf.as_slice(), b"incoming-base");
        assert_eq!(bufs.base_buf.as_ptr(), incoming_ptr);
        assert_eq!(incoming.as_slice(), b"outer-base");
        assert_eq!(incoming.as_ptr(), old_base_ptr);
    }

    #[test]
    fn take_result_output_preserves_base_capacity() {
        let mut bufs = TreeDecodeBufs::new();
        bufs.base_buf = Vec::with_capacity(64);
        bufs.base_buf.extend_from_slice(b"base");
        bufs.result_buf.extend_from_slice(b"resolved");
        let base_cap_before = bufs.base_buf.capacity();

        let out = bufs.take_result_output();

        assert_eq!(out.as_slice(), b"resolved");
        assert!(bufs.result_buf.is_empty());
        assert_eq!(bufs.base_buf.as_slice(), b"base");
        assert_eq!(bufs.base_buf.capacity(), base_cap_before);
    }

    // ── Delta resolution helpers and tests ──────────────────────────────

    use super::super::delta_test_helpers::{
        make_add_delta, make_copy_delta, make_mixed_delta, SyntheticPackBuilder,
    };
    use super::super::pack_inflate::{
        self, apply_delta, EntryKind as PackEntryKind, ObjectKind, PackFile,
    };
    use super::TreeDeltaCache;
    use super::MAX_DELTA_DEPTH;

    #[test]
    fn single_frame_ofs_delta_chain() {
        // Pack: base tree "AAAA", then OFS delta whose result is "BB"
        // (add-literal instruction only, no base copy).
        let base_data = b"AAAA";
        let delta_data = make_add_delta(base_data.len(), b"BB");

        let mut builder = SyntheticPackBuilder::new();
        let base_idx = builder.add_non_delta(2, base_data); // type 2 = tree
        let delta_idx = builder.add_ofs_delta(base_idx, &delta_data);
        let (pack_bytes, offsets) = builder.build();

        // Parse the pack.
        let pack_header = PackFile::parse_header(&pack_bytes, 20).unwrap();
        let pack = PackFile::from_header(&pack_bytes, pack_header);

        // Verify the base entry header.
        let base_header = pack.entry_header_at(offsets[base_idx], 64).unwrap();
        assert!(matches!(
            base_header.kind,
            PackEntryKind::NonDelta {
                kind: ObjectKind::Tree
            }
        ));
        assert_eq!(base_header.size, base_data.len() as u64);

        // Verify the delta entry header.
        let delta_header = pack.entry_header_at(offsets[delta_idx], 64).unwrap();
        assert!(
            matches!(delta_header.kind, PackEntryKind::OfsDelta { base_offset } if base_offset == offsets[base_idx])
        );
        assert_eq!(delta_header.size, delta_data.len() as u64);

        // Inflate the base and delta payloads, then apply.
        let mut de = flate2::Decompress::new(true);
        let mut inflated_base = Vec::new();
        pack_inflate::inflate_limited_with(
            &mut de,
            pack.slice_from(base_header.data_start),
            &mut inflated_base,
            1024,
        )
        .unwrap();
        assert_eq!(inflated_base, base_data);

        let mut inflated_delta = Vec::new();
        pack_inflate::inflate_limited_with(
            &mut de,
            pack.slice_from(delta_header.data_start),
            &mut inflated_delta,
            1024,
        )
        .unwrap();
        assert_eq!(inflated_delta, delta_data);

        // Apply the delta to get the resolved object.
        let mut result = Vec::new();
        apply_delta(&inflated_base, &inflated_delta, &mut result, 1024).unwrap();
        assert_eq!(result, b"BB");
    }

    #[test]
    fn multi_frame_delta_chain_buffer_rotation() {
        // 4-entry chain: base "AAAA" -> +BB -> +CC -> +DD
        let base_data = b"AAAA";
        let delta1 = make_mixed_delta(base_data.len(), 0, 4, b"BB"); // -> "AAAABB"
        let delta2 = make_mixed_delta(6, 0, 6, b"CC"); // -> "AAAABBCC"
        let delta3 = make_mixed_delta(8, 0, 8, b"DD"); // -> "AAAABBCCDD"

        let mut builder = SyntheticPackBuilder::new();
        let base_idx = builder.add_non_delta(2, base_data);
        let d1_idx = builder.add_ofs_delta(base_idx, &delta1);
        let d2_idx = builder.add_ofs_delta(d1_idx, &delta2);
        let d3_idx = builder.add_ofs_delta(d2_idx, &delta3);
        let (pack_bytes, offsets) = builder.build();

        let pack_header = PackFile::parse_header(&pack_bytes, 20).unwrap();
        let pack = PackFile::from_header(&pack_bytes, pack_header);

        // Walk the chain manually: inflate base, then apply each delta.
        let mut de = flate2::Decompress::new(true);

        let base_header = pack.entry_header_at(offsets[base_idx], 64).unwrap();
        let mut current = Vec::new();
        pack_inflate::inflate_limited_with(
            &mut de,
            pack.slice_from(base_header.data_start),
            &mut current,
            1024,
        )
        .unwrap();
        assert_eq!(current, base_data);

        // Apply delta1.
        let d1_header = pack.entry_header_at(offsets[d1_idx], 64).unwrap();
        let mut inflated_delta = Vec::new();
        pack_inflate::inflate_limited_with(
            &mut de,
            pack.slice_from(d1_header.data_start),
            &mut inflated_delta,
            1024,
        )
        .unwrap();
        let mut result = Vec::new();
        apply_delta(&current, &inflated_delta, &mut result, 1024).unwrap();
        assert_eq!(result, b"AAAABB");

        // Apply delta2 (swap buffers to simulate buffer rotation).
        let d2_header = pack.entry_header_at(offsets[d2_idx], 64).unwrap();
        pack_inflate::inflate_limited_with(
            &mut de,
            pack.slice_from(d2_header.data_start),
            &mut inflated_delta,
            1024,
        )
        .unwrap();
        std::mem::swap(&mut current, &mut result);
        apply_delta(&current, &inflated_delta, &mut result, 1024).unwrap();
        assert_eq!(result, b"AAAABBCC");

        // Apply delta3.
        let d3_header = pack.entry_header_at(offsets[d3_idx], 64).unwrap();
        pack_inflate::inflate_limited_with(
            &mut de,
            pack.slice_from(d3_header.data_start),
            &mut inflated_delta,
            1024,
        )
        .unwrap();
        std::mem::swap(&mut current, &mut result);
        apply_delta(&current, &inflated_delta, &mut result, 1024).unwrap();
        assert_eq!(result, b"AAAABBCCDD");
    }

    #[test]
    fn deep_delta_chain_entries_parse_correctly() {
        // Build a chain deeper than MAX_DELTA_DEPTH (64) and verify every
        // entry header is parseable. The depth limit itself is enforced
        // during resolution in `read_pack_object_impl`, which requires a
        // full ObjectStore and is not exercised here.
        let base_data = b"base";
        let mut builder = SyntheticPackBuilder::new();
        let base_idx = builder.add_non_delta(2, base_data);

        let mut prev_idx = base_idx;
        // 66 deltas on top of the base => 67 entries total.
        for i in 0..66 {
            let suffix = format!("{i:02}");
            let prev_size = base_data.len() + i * 2;
            let delta = make_mixed_delta(prev_size, 0, prev_size, suffix.as_bytes());
            prev_idx = builder.add_ofs_delta(prev_idx, &delta);
        }

        let (pack_bytes, offsets) = builder.build();
        let pack_header = PackFile::parse_header(&pack_bytes, 20).unwrap();
        let pack = PackFile::from_header(&pack_bytes, pack_header);

        // Verify each entry in the chain is parseable.
        for (i, &offset) in offsets.iter().enumerate() {
            let header = pack.entry_header_at(offset, 64).unwrap();
            if i == 0 {
                assert!(matches!(
                    header.kind,
                    PackEntryKind::NonDelta {
                        kind: ObjectKind::Tree
                    }
                ));
            } else {
                assert!(
                    matches!(header.kind, PackEntryKind::OfsDelta { .. }),
                    "entry {i} should be OFS delta"
                );
            }
        }

        // The chain has base + 66 deltas = 67 entries.
        // MAX_DELTA_DEPTH is 64, so the chain exceeds the limit.
        assert!(offsets.len() > MAX_DELTA_DEPTH as usize + 1);
    }

    #[test]
    fn cache_hit_short_circuits_walk_forward() {
        // Verify TreeDeltaCache stores and retrieves delta bases correctly,
        // which is the mechanism ObjectStore uses to short-circuit walks.
        let mut cache = TreeDeltaCache::new(64 * 1024);
        let base_bytes = b"cached-tree-base-payload";

        // Insert a cached base at pack_id=1, offset=100.
        assert!(cache.insert(1, 100, ObjectKind::Tree, 2, base_bytes));

        // Verify cache hit returns correct data.
        let handle = cache.get_handle(1, 100).expect("cache hit");
        assert_eq!(handle.as_slice(), base_bytes);
        assert_eq!(handle.kind(), ObjectKind::Tree);
        assert_eq!(handle.chain_len(), 2);

        // Verify cache miss for different keys.
        assert!(cache.get_handle(1, 200).is_none());
        assert!(cache.get_handle(2, 100).is_none());

        // Apply a copy-all delta to the cached base.
        let delta_copy = make_copy_delta(base_bytes.len(), 0, base_bytes.len());
        let mut result = Vec::new();
        apply_delta(handle.as_slice(), &delta_copy, &mut result, 1024).unwrap();
        assert_eq!(result, base_bytes);

        drop(handle);

        // Apply a mixed delta (partial copy + literal) to the cached base.
        let delta_add = make_mixed_delta(base_bytes.len(), 0, 10, b"EXTRA");
        let handle2 = cache.get_handle(1, 100).expect("cache hit after drop");
        let mut result2 = Vec::new();
        apply_delta(handle2.as_slice(), &delta_add, &mut result2, 1024).unwrap();
        assert_eq!(&result2[..10], &base_bytes[..10]);
        assert_eq!(&result2[10..], b"EXTRA");
    }

    #[test]
    fn corrupt_delta_payload_propagates_error() {
        // Build a pack where the delta's zlib data is corrupted.
        let base_data = b"AAAA";
        let mut builder = SyntheticPackBuilder::new();
        let base_idx = builder.add_non_delta(2, base_data);

        let delta_data = make_add_delta(base_data.len(), b"BB");
        let delta_idx = builder.add_ofs_delta(base_idx, &delta_data);
        let (mut pack_bytes, offsets) = builder.build();

        // Locate the delta's zlib data start.
        let pack_header = PackFile::parse_header(&pack_bytes, 20).unwrap();
        let pack = PackFile::from_header(&pack_bytes, pack_header);
        let delta_header = pack.entry_header_at(offsets[delta_idx], 64).unwrap();

        // Overwrite zlib bytes with garbage.
        let corrupt_start = delta_header.data_start;
        for b in &mut pack_bytes[corrupt_start..corrupt_start + 4] {
            *b = 0xFF;
        }

        // Re-parse the pack (header is still valid).
        let pack_header2 = PackFile::parse_header(&pack_bytes, 20).unwrap();
        let pack2 = PackFile::from_header(&pack_bytes, pack_header2);
        let delta_header2 = pack2.entry_header_at(offsets[delta_idx], 64).unwrap();

        // Inflate the corrupt data — must fail.
        let mut de = flate2::Decompress::new(true);
        let mut out = Vec::new();
        let result = pack_inflate::inflate_limited_with(
            &mut de,
            pack2.slice_from(delta_header2.data_start),
            &mut out,
            1024,
        );
        assert!(
            result.is_err(),
            "corrupt zlib data should produce an inflate error"
        );
    }
}

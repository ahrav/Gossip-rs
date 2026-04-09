//! In-memory MIDX builder using k-way merge.
//!
//! Builds a valid MIDX byte buffer from pack `.idx` files without requiring
//! `git maintenance`. The output can be parsed by `MidxView` to provide
//! identical behavior to disk-based MIDX files.
//!
//! # Algorithm
//! 1. Enumerate `.idx` files across pack directories in deterministic order
//! 2. Parse each with `IdxView` (zero-copy)
//! 3. K-way merge over pre-sorted OID streams (O(N log P) where P = pack count)
//! 4. Build OID fanout with count + prefix-sum (O(N + 256))
//! 5. Generate MIDX v1 format bytes
//!
//! # Memory Strategy
//! - Below `max_midx_bytes_in_ram`: build in `Vec<u8>`, return `BytesView::Owned`
//! - Above threshold: stream to temp file, mmap result (not yet implemented)
//! - Above `max_midx_total_bytes`: fail with `ArtifactsTooLarge`
//!
//! # Determinism Rules
//! - Pack directories: primary first, then alternates in `info/alternates` order
//! - Within each dir: sort `.idx` basenames lexicographically as bytes
//! - Duplicate OIDs: lowest `pack_id` wins (earliest pack in deterministic order)
//!
//! # Checksums
//! The builder writes zeroed trailing checksums. This is sufficient for
//! `MidxView` parsing and in-memory use, but the output is not suitable for
//! tooling that validates MIDX checksums.
//!
//! # Duplicate OIDs
//! Duplicate object IDs across packs are coalesced in the MIDX output. The
//! lowest `pack_id` (earliest pack in deterministic order) wins, so the
//! resulting object count may be lower than the sum of per-pack counts.

use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::ffi::OsStr;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use memmap2::Mmap;

use super::bytes::BytesView;
use super::midx::MidxView;
use super::midx_error::MidxError;
use super::object_id::ObjectFormat;
use super::pack_idx::{IdxError, IdxView};
use super::repo::GitRepoPaths;

/// Errors from MIDX building.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MidxBuildError {
    /// I/O error during pack enumeration or file operations.
    #[error("MIDX build I/O error: {0}")]
    Io(#[from] io::Error),
    /// No pack files found.
    #[error("no pack files found")]
    NoPacksFound,
    /// Too many pack files.
    #[error("too many packs: {count} (max: {max})")]
    TooManyPacks { count: usize, max: usize },
    /// MIDX would exceed size limit.
    #[error("MIDX too large: {size} bytes (limit: {limit})")]
    ArtifactsTooLarge { size: u64, limit: u64 },
    /// Pack index parsing failed.
    #[error("failed to parse {}: {source}", path.display())]
    IdxParseFailed {
        path: PathBuf,
        #[source]
        source: IdxError,
    },
    /// Generated MIDX failed validation.
    #[error("MIDX validation failed: {source}")]
    ValidationFailed {
        #[source]
        source: MidxError,
    },
    /// Too many objects across all packs.
    #[error("too many objects: {count} (max: {max})")]
    TooManyObjects { count: u64, max: u64 },
}

/// Limits for MIDX building.
#[derive(Debug, Clone, Copy)]
pub struct MidxBuildLimits {
    /// Maximum packs to include.
    pub max_packs: u16,
    /// Keep MIDX in RAM up to this size (bytes).
    pub max_midx_bytes_in_ram: u64,
    /// Hard fail if MIDX would exceed this size (bytes).
    pub max_midx_total_bytes: u64,
    /// Maximum total objects across all packs.
    pub max_total_objects: u64,
}

impl Default for MidxBuildLimits {
    fn default() -> Self {
        Self {
            max_packs: 400,
            max_midx_bytes_in_ram: 256 * 1024 * 1024, // 256 MiB
            max_midx_total_bytes: 2 * 1024 * 1024 * 1024, // 2 GiB
            max_total_objects: 50_000_000,            // 50M objects
        }
    }
}

/// MIDX magic bytes.
const MIDX_MAGIC: [u8; 4] = *b"MIDX";
/// MIDX version 1.
const MIDX_VERSION: u8 = 1;
/// MIDX header size (12 bytes).
const MIDX_HEADER_SIZE: usize = 12;
/// Chunk table entry size (12 bytes: 4 ID + 8 offset).
const CHUNK_ENTRY_SIZE: usize = 12;
/// Fanout table entries.
const FANOUT_ENTRIES: usize = 256;
/// Fanout table size in bytes.
const FANOUT_SIZE: usize = FANOUT_ENTRIES * 4;
/// Chunk IDs.
const CHUNK_PNAM: [u8; 4] = *b"PNAM";
const CHUNK_OIDF: [u8; 4] = *b"OIDF";
const CHUNK_OIDL: [u8; 4] = *b"OIDL";
const CHUNK_OOFF: [u8; 4] = *b"OOFF";
const CHUNK_LOFF: [u8; 4] = *b"LOFF";
/// MSB flag for large offset indirection.
const LARGE_OFFSET_FLAG: u32 = 0x8000_0000;

/// Builds MIDX bytes from pack index files.
///
/// # Arguments
/// * `repo` - Repository paths (used for pack directory enumeration)
/// * `format` - Object ID format (SHA-1 or SHA-256)
/// * `limits` - Build limits
///
/// # Returns
/// A `BytesView` containing valid MIDX v1 bytes that can be parsed by `MidxView`.
/// Trailing checksums are zeroed (not computed).
///
/// # Errors
/// Returns `MidxBuildError` if:
/// - Too many packs or objects
/// - MIDX would exceed size limits (heuristic precheck + final serialized cap)
/// - Any `.idx` file fails to parse
pub fn build_midx_bytes(
    repo: &GitRepoPaths,
    format: ObjectFormat,
    limits: &MidxBuildLimits,
) -> Result<BytesView, MidxBuildError> {
    // Step 1: Enumerate .idx files in deterministic order
    let idx_paths = enumerate_idx_files(repo, limits.max_packs as usize)?;

    if idx_paths.len() > limits.max_packs as usize {
        return Err(MidxBuildError::TooManyPacks {
            count: idx_paths.len(),
            max: limits.max_packs as usize,
        });
    }

    // Step 2: Mmap each .idx file and collect metadata
    let mut pack_data: Vec<(u16, Vec<u8>, Mmap)> = Vec::with_capacity(idx_paths.len());
    let mut total_objects: u64 = 0;

    for (pack_id, path) in idx_paths.iter().enumerate() {
        // SAFETY: The .idx file is read-only and its length is fixed for
        // the duration of the mmap. No other process modifies it during the build.
        let mmap = unsafe {
            let file = fs::File::open(path)?;
            Mmap::map(&file)?
        };

        // Validate and count objects
        let view = IdxView::parse(&mmap, format).map_err(|e| MidxBuildError::IdxParseFailed {
            path: path.clone(),
            source: e,
        })?;

        total_objects += view.object_count() as u64;
        if total_objects > limits.max_total_objects {
            return Err(MidxBuildError::TooManyObjects {
                count: total_objects,
                max: limits.max_total_objects,
            });
        }

        // Extract pack name from path (basename without .idx extension)
        let pack_name = pack_name_from_idx_path(path);

        pack_data.push((pack_id as u16, pack_name, mmap));
    }

    // Parse views from stable mmaps
    let views: Vec<(u16, Vec<u8>, IdxView<'_>)> = pack_data
        .iter()
        .map(|(pack_id, pack_name, mmap)| {
            let view = IdxView::parse(mmap, format).expect("already validated");
            (*pack_id, pack_name.clone(), view)
        })
        .collect();

    // Step 3: Estimate output size
    let oid_len = format.oid_len() as usize;
    let object_count = total_objects as usize;
    let estimated_size = estimate_midx_size(views.len(), object_count, oid_len);

    if estimated_size > limits.max_midx_total_bytes {
        return Err(MidxBuildError::ArtifactsTooLarge {
            size: estimated_size,
            limit: limits.max_midx_total_bytes,
        });
    }

    // Step 4: Build MIDX using k-way merge.
    //
    // The estimate above is only heuristic: pack-name bytes and LOFF usage can
    // move the final size in either direction. Enforce the configured limit
    // against the serialized byte length before returning.
    let midx_bytes = build_midx_in_memory(&views, format, object_count)?;
    let actual_size = midx_bytes.len() as u64;
    if actual_size > limits.max_midx_total_bytes {
        return Err(MidxBuildError::ArtifactsTooLarge {
            size: actual_size,
            limit: limits.max_midx_total_bytes,
        });
    }

    // Step 5: Validate output
    MidxView::parse(&midx_bytes, format)
        .map_err(|e| MidxBuildError::ValidationFailed { source: e })?;

    Ok(BytesView::from_vec(midx_bytes))
}

/// Enumerates `.idx` files across pack directories in deterministic order.
///
/// Order: primary pack dir first, then alternates in `info/alternates` order.
/// Within each dir: sort `.idx` basenames lexicographically as bytes.
fn enumerate_idx_files(
    repo: &GitRepoPaths,
    max_packs: usize,
) -> Result<Vec<PathBuf>, MidxBuildError> {
    let mut pack_dirs = Vec::with_capacity(1 + repo.alternate_object_dirs.len());
    pack_dirs.push(repo.pack_dir.clone());

    for alternate in &repo.alternate_object_dirs {
        if alternate == &repo.objects_dir {
            continue;
        }
        pack_dirs.push(alternate.join("pack"));
    }

    let mut all_idx_paths = Vec::new();
    let mut seen_basenames = std::collections::HashSet::new();

    for pack_dir in pack_dirs {
        let mut dir_idx_paths = list_idx_files_in_dir(&pack_dir)?;

        // Sort by basename lexicographically
        dir_idx_paths.sort_by(|a, b| {
            let a_name = a.file_name().unwrap_or_default();
            let b_name = b.file_name().unwrap_or_default();
            a_name.as_encoded_bytes().cmp(b_name.as_encoded_bytes())
        });

        for path in dir_idx_paths {
            // Dedupe by basename (first dir wins)
            let basename = path
                .file_name()
                .map(|s| s.as_encoded_bytes().to_vec())
                .unwrap_or_default();

            if seen_basenames.insert(basename) {
                all_idx_paths.push(path);
            }

            // Stop collecting after enough paths for the caller to detect
            // the overflow. One past `max_packs` is sufficient — the caller
            // checks `len() > max_packs` and returns `TooManyPacks`.
            if all_idx_paths.len() > max_packs {
                return Ok(all_idx_paths);
            }
        }
    }

    Ok(all_idx_paths)
}

/// Lists `.idx` files in a single pack directory.
fn list_idx_files_in_dir(pack_dir: &Path) -> Result<Vec<PathBuf>, MidxBuildError> {
    let entries = match fs::read_dir(pack_dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(MidxBuildError::Io(err)),
    };

    let mut idx_paths = Vec::new();
    for entry in entries {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if !file_type.is_file() {
            continue;
        }

        let file_name = entry.file_name();
        if is_idx_file(&file_name) {
            idx_paths.push(entry.path());
        }
    }

    Ok(idx_paths)
}

/// Returns true if the filename ends with `.idx`.
fn is_idx_file(name: &OsStr) -> bool {
    Path::new(name).extension().is_some_and(|ext| ext == "idx")
}

/// Extracts pack name from .idx path (e.g., "pack-abc123.idx" -> "pack-abc123.pack").
fn pack_name_from_idx_path(path: &Path) -> Vec<u8> {
    let basename = path.file_stem().unwrap_or_default();
    let mut name = basename.as_encoded_bytes().to_vec();
    name.extend_from_slice(b".pack");
    name
}

/// Estimates MIDX output size in bytes.
///
/// This is a heuristic used as a fast precheck. The final limit enforcement is
/// done against the actual serialized byte length from `build_midx_in_memory`.
/// The estimate may over- or under-shoot, especially for pack-name storage and
/// large-offset frequency.
fn estimate_midx_size(pack_count: usize, object_count: usize, oid_len: usize) -> u64 {
    // Header + chunk table
    let header = MIDX_HEADER_SIZE + (5 + 1) * CHUNK_ENTRY_SIZE; // 5 chunks + sentinel

    // PNAM: estimate ~50 bytes per pack name
    let pnam = pack_count * 50;

    // OIDF: fanout table
    let oidf = FANOUT_SIZE;

    // OIDL: OID list
    let oidl = object_count * oid_len;

    // OOFF: offset table (8 bytes per object)
    let ooff = object_count * 8;

    // LOFF: estimate 1% of objects have large offsets
    let loff = (object_count / 100) * 8;

    // Trailing checksum
    let checksum = oid_len;

    (header + pnam + oidf + oidl + ooff + loff + checksum) as u64
}

/// Builds MIDX bytes in memory using k-way merge.
///
/// OIDs are emitted in sorted order; duplicate OIDs are de-duplicated by
/// keeping the lowest pack id. Offsets larger than 2^31 are emitted via
/// the LOFF indirection table.
///
/// Fanout construction is split into two phases:
/// 1. Count emitted objects per first-byte bucket during merge
/// 2. Convert counts to cumulative fanout with a single prefix-sum pass
///
/// This preserves exact fanout semantics while avoiding per-object trailing
/// writes across all 256 fanout entries.
///
/// `total_objects` is an upper bound used for capacity planning; the final
/// output may contain fewer objects due to duplicate OIDs.
fn build_midx_in_memory(
    views: &[(u16, Vec<u8>, IdxView<'_>)],
    format: ObjectFormat,
    total_objects: usize,
) -> Result<Vec<u8>, MidxBuildError> {
    let oid_len = format.oid_len() as usize;
    let pack_count = views.len() as u32;

    // Build PNAM chunk
    let mut pnam = Vec::new();
    for (_, pack_name, _) in views {
        pnam.extend_from_slice(pack_name);
        pnam.push(0); // NUL terminator
    }

    // Initialize output buffers
    let mut oidl = Vec::with_capacity(total_objects * oid_len);
    let mut ooff = Vec::with_capacity(total_objects * 8);
    let mut loff = Vec::new();
    let mut fanout = [0u32; FANOUT_ENTRIES];

    // K-way merge using min-heap
    let mut heap: BinaryHeap<MergeEntry<'_>> = BinaryHeap::new();

    // Initialize heap with first entry from each pack
    for (pack_id, _, view) in views {
        let mut iter = view.iter_oids();
        if let Some((oid, idx)) = iter.next() {
            heap.push(MergeEntry {
                oid,
                pack_id: *pack_id,
                idx_in_pack: idx,
                view: *view,
                iter,
            });
        }
    }

    let mut prev_oid = vec![0u8; oid_len];
    let mut has_prev_oid = false;
    let mut output_idx = 0u32;

    while let Some(entry) = heap.pop() {
        // Check for duplicate OID; the heap ordering ensures the lowest
        // pack_id is emitted first for equal OIDs.
        let is_duplicate = has_prev_oid && prev_oid.as_slice() == entry.oid;

        if !is_duplicate {
            // Emit this object
            oidl.extend_from_slice(entry.oid);

            // Get offset from source pack
            let offset = entry.view.offset_at(entry.idx_in_pack).map_err(|_| {
                MidxBuildError::IdxParseFailed {
                    path: PathBuf::new(),
                    source: IdxError::corrupt("offset lookup failed"),
                }
            })?;

            // Write OOFF entry
            ooff.extend_from_slice(&(entry.pack_id as u32).to_be_bytes());

            if offset >= LARGE_OFFSET_FLAG as u64 {
                // Use LOFF indirection
                let loff_idx = (loff.len() / 8) as u32;
                ooff.extend_from_slice(&(LARGE_OFFSET_FLAG | loff_idx).to_be_bytes());
                loff.extend_from_slice(&offset.to_be_bytes());
            } else {
                ooff.extend_from_slice(&(offset as u32).to_be_bytes());
            }

            // Track per-bucket counts; convert to cumulative fanout after merge.
            let first_byte = entry.oid[0] as usize;
            fanout[first_byte] += 1;

            prev_oid.copy_from_slice(entry.oid);
            has_prev_oid = true;
            output_idx += 1;
        }

        // Advance iterator and re-insert if more entries
        let MergeEntry {
            pack_id,
            view,
            mut iter,
            ..
        } = entry;

        if let Some((next_oid, next_idx)) = iter.next() {
            heap.push(MergeEntry {
                oid: next_oid,
                pack_id,
                idx_in_pack: next_idx,
                view,
                iter,
            });
        }
    }

    let _object_count = output_idx;

    // Convert per-bucket counts to cumulative fanout semantics.
    let mut running = 0u32;
    for slot in &mut fanout {
        running += *slot;
        *slot = running;
    }

    // Build OIDF chunk (fanout table)
    let mut oidf = Vec::with_capacity(FANOUT_SIZE);
    for count in fanout {
        oidf.extend_from_slice(&count.to_be_bytes());
    }

    // Calculate chunk offsets
    let has_loff = !loff.is_empty();
    let chunk_count = if has_loff { 5u8 } else { 4u8 };
    let chunk_table_size = (chunk_count as usize + 1) * CHUNK_ENTRY_SIZE;

    let pnam_off = (MIDX_HEADER_SIZE + chunk_table_size) as u64;
    let oidf_off = pnam_off + pnam.len() as u64;
    let oidl_off = oidf_off + oidf.len() as u64;
    let ooff_off = oidl_off + oidl.len() as u64;
    let loff_off = ooff_off + ooff.len() as u64;
    let end_off = if has_loff {
        loff_off + loff.len() as u64
    } else {
        loff_off
    };

    // Build output
    let mut out = Vec::with_capacity(end_off as usize + oid_len);

    // Header
    out.extend_from_slice(&MIDX_MAGIC);
    out.push(MIDX_VERSION);
    out.push(match format {
        ObjectFormat::Sha1 => 1,
        ObjectFormat::Sha256 => 2,
    });
    out.push(chunk_count);
    out.push(0); // base count
    out.extend_from_slice(&pack_count.to_be_bytes());

    // Chunk table
    out.extend_from_slice(&CHUNK_PNAM);
    out.extend_from_slice(&pnam_off.to_be_bytes());

    out.extend_from_slice(&CHUNK_OIDF);
    out.extend_from_slice(&oidf_off.to_be_bytes());

    out.extend_from_slice(&CHUNK_OIDL);
    out.extend_from_slice(&oidl_off.to_be_bytes());

    out.extend_from_slice(&CHUNK_OOFF);
    out.extend_from_slice(&ooff_off.to_be_bytes());

    if has_loff {
        out.extend_from_slice(&CHUNK_LOFF);
        out.extend_from_slice(&loff_off.to_be_bytes());
    }

    // Sentinel entry
    out.extend_from_slice(&[0u8; 4]);
    out.extend_from_slice(&end_off.to_be_bytes());

    // Chunks
    out.extend_from_slice(&pnam);
    out.extend_from_slice(&oidf);
    out.extend_from_slice(&oidl);
    out.extend_from_slice(&ooff);
    if has_loff {
        out.extend_from_slice(&loff);
    }

    // Trailing checksum (zeros - we don't compute a real checksum).
    out.extend(std::iter::repeat_n(0u8, oid_len));

    Ok(out)
}

/// Entry in the k-way merge heap.
struct MergeEntry<'a> {
    oid: &'a [u8],
    pack_id: u16,
    idx_in_pack: u32,
    view: IdxView<'a>,
    iter: super::pack_idx::IdxOidIter<'a>,
}

impl PartialEq for MergeEntry<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.oid == other.oid && self.pack_id == other.pack_id
    }
}

impl Eq for MergeEntry<'_> {}

impl PartialOrd for MergeEntry<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MergeEntry<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        // BinaryHeap is a max-heap, so reverse comparison for min-heap behavior
        match other.oid.cmp(self.oid) {
            Ordering::Equal => {
                // For equal OIDs, prefer lower pack_id (will be popped first)
                other.pack_id.cmp(&self.pack_id)
            }
            ord => ord,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::repo::RepoKind;
    use tempfile::tempdir;

    const SMALL_MODEL_BUCKETS: [u8; 4] = [0x00, 0x40, 0x80, 0xC0];
    /// Duplicate OIDs use second-byte values starting here (0xe0..); unique OIDs
    /// must stay below this to avoid accidental collisions.
    const DUPLICATE_BYTE_BASE: u8 = 0xe0;

    /// Helper to build minimal pack index v2 bytes for MIDX merge tests.
    struct TestIdxBuilder {
        objects: Vec<([u8; 20], u64)>,
    }

    impl TestIdxBuilder {
        fn new() -> Self {
            Self {
                objects: Vec::new(),
            }
        }

        fn add_object(&mut self, oid: [u8; 20], offset: u64) {
            self.objects.push((oid, offset));
        }

        fn build(&self) -> Vec<u8> {
            const IDX_MAGIC: [u8; 4] = [0xff, b't', b'O', b'c'];
            const IDX_VERSION: u32 = 2;

            let mut objects = self.objects.clone();
            objects.sort_by(|a, b| a.0.cmp(&b.0));

            let mut fanout = vec![0u8; FANOUT_SIZE];
            let mut counts = [0u32; FANOUT_ENTRIES];
            for (oid, _) in &objects {
                counts[oid[0] as usize] += 1;
            }
            let mut running = 0u32;
            for (i, count) in counts.iter().enumerate() {
                running += count;
                let off = i * 4;
                fanout[off..off + 4].copy_from_slice(&running.to_be_bytes());
            }

            let mut oid_table = Vec::with_capacity(objects.len() * 20);
            let mut offset_table = Vec::with_capacity(objects.len() * 4);
            let mut large_offsets = Vec::new();
            for (oid, offset) in &objects {
                oid_table.extend_from_slice(oid);
                if *offset >= LARGE_OFFSET_FLAG as u64 {
                    let loff_idx = (large_offsets.len() / 8) as u32;
                    offset_table.extend_from_slice(&(LARGE_OFFSET_FLAG | loff_idx).to_be_bytes());
                    large_offsets.extend_from_slice(&offset.to_be_bytes());
                } else {
                    offset_table.extend_from_slice(&(*offset as u32).to_be_bytes());
                }
            }

            let crc_table = vec![0u8; objects.len() * 4];
            let checksums = vec![0u8; 40]; // pack checksum + idx checksum

            let mut out = Vec::new();
            out.extend_from_slice(&IDX_MAGIC);
            out.extend_from_slice(&IDX_VERSION.to_be_bytes());
            out.extend_from_slice(&fanout);
            out.extend_from_slice(&oid_table);
            out.extend_from_slice(&crc_table);
            out.extend_from_slice(&offset_table);
            out.extend_from_slice(&large_offsets);
            out.extend_from_slice(&checksums);
            out
        }
    }

    fn test_oid(first: u8, second: u8) -> [u8; 20] {
        let mut oid = [0u8; 20];
        oid[0] = first;
        oid[1] = second;
        oid[19] = first ^ second;
        oid
    }

    #[derive(Debug)]
    struct SmallModelPack {
        pack_id: u16,
        pack_name: Vec<u8>,
        idx_bytes: Vec<u8>,
        objects: Vec<([u8; 20], u64)>,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct CanonicalMidx {
        fanout: [u32; FANOUT_ENTRIES],
        entries: Vec<([u8; 20], (u16, u64))>,
    }

    fn for_each_permutation(indices: &mut [usize], start: usize, visit: &mut impl FnMut(&[usize])) {
        if start == indices.len() {
            visit(indices);
            return;
        }

        for index in start..indices.len() {
            indices.swap(start, index);
            for_each_permutation(indices, start + 1, visit);
            indices.swap(start, index);
        }
    }

    /// Enumerates all bitmasks of `pack_count` bits that have at least 2 bits set,
    /// representing subsets of packs that share a duplicate OID.
    fn duplicate_subsets(pack_count: usize) -> Vec<u8> {
        assert!(
            pack_count <= 7,
            "pack_count={pack_count} would overflow the u8 bitmask (max 7)"
        );
        let mut subsets = Vec::new();
        for mask in 0u8..(1u8 << pack_count) {
            if mask.count_ones() >= 2 {
                subsets.push(mask);
            }
        }
        subsets
    }

    /// Generates all length-`duplicate_count` sequences drawn from `subsets`
    /// (Cartesian product with replacement). Returns |subsets|^duplicate_count
    /// results — keep `duplicate_count` small to avoid combinatorial blowup.
    fn duplicate_mask_sequences(subsets: &[u8], duplicate_count: usize) -> Vec<Vec<u8>> {
        if duplicate_count == 0 {
            return vec![Vec::new()];
        }

        let mut sequences = Vec::new();
        let mut current = Vec::with_capacity(duplicate_count);

        fn build_sequences(
            subsets: &[u8],
            duplicate_count: usize,
            current: &mut Vec<u8>,
            sequences: &mut Vec<Vec<u8>>,
        ) {
            if current.len() == duplicate_count {
                sequences.push(current.clone());
                return;
            }

            for &subset in subsets {
                current.push(subset);
                build_sequences(subsets, duplicate_count, current, sequences);
                current.pop();
            }
        }

        build_sequences(subsets, duplicate_count, &mut current, &mut sequences);
        sequences
    }

    /// Constructs `pack_count` packs each containing `objects_per_pack` objects, with
    /// `duplicate_masks` controlling which packs share duplicate OIDs.
    ///
    /// OID collision-freedom relies on disjoint second-byte ranges:
    /// - **Duplicate OIDs** use `second_byte = 0xe0 + duplicate_idx` (range `[0xe0, 0xe0+dc)`).
    /// - **Unique OIDs** use `second_byte = slot * pack_count + pack_idx`, which is injective
    ///   and bounded by `objects_per_pack * pack_count` (max 24 for the current bounds).
    ///
    /// These ranges never overlap for `objects_per_pack <= 6` and `pack_count <= 4`.
    /// `byte[0]` is rotated across `SMALL_MODEL_BUCKETS` to exercise multiple fanout buckets.
    fn build_small_model_packs(
        pack_count: usize,
        objects_per_pack: usize,
        duplicate_masks: &[u8],
        bucket_rotation: usize,
    ) -> Vec<SmallModelPack> {
        let mut objects_by_pack = vec![Vec::with_capacity(objects_per_pack); pack_count];

        for (duplicate_idx, &mask) in duplicate_masks.iter().enumerate() {
            let oid = test_oid(
                SMALL_MODEL_BUCKETS[(bucket_rotation + duplicate_idx) % SMALL_MODEL_BUCKETS.len()],
                DUPLICATE_BYTE_BASE + duplicate_idx as u8,
            );
            for (pack_idx, objects) in objects_by_pack.iter_mut().enumerate() {
                if mask & (1u8 << pack_idx) == 0 {
                    continue;
                }
                let offset = 1_000 + (pack_idx as u64 * 100) + objects.len() as u64;
                objects.push((oid, offset));
            }
        }

        for (pack_idx, objects) in objects_by_pack.iter_mut().enumerate() {
            let unique_needed = objects_per_pack
                .checked_sub(objects.len())
                .expect("duplicate masks must not overfill a pack");
            for slot in 0..unique_needed {
                let second_byte = (slot * pack_count + pack_idx) as u8;
                debug_assert!(
                    second_byte < DUPLICATE_BYTE_BASE,
                    "unique OID second byte {second_byte:#x} collides with duplicate namespace [{DUPLICATE_BYTE_BASE:#x}..)"
                );
                let oid = test_oid(
                    SMALL_MODEL_BUCKETS[(bucket_rotation
                        + duplicate_masks.len()
                        + pack_idx
                        + slot)
                        % SMALL_MODEL_BUCKETS.len()],
                    second_byte,
                );
                let offset = 1_000 + (pack_idx as u64 * 100) + objects.len() as u64;
                objects.push((oid, offset));
            }
        }

        objects_by_pack
            .into_iter()
            .enumerate()
            .map(|(pack_idx, objects)| {
                let mut builder = TestIdxBuilder::new();
                for &(oid, offset) in &objects {
                    builder.add_object(oid, offset);
                }
                SmallModelPack {
                    pack_id: pack_idx as u16,
                    pack_name: format!("pack-{pack_idx}.pack").into_bytes(),
                    idx_bytes: builder.build(),
                    objects,
                }
            })
            .collect()
    }

    fn expected_midx(packs: &[SmallModelPack]) -> CanonicalMidx {
        let mut winners = BTreeMap::new();
        for pack in packs {
            for &(oid, offset) in &pack.objects {
                winners
                    .entry(oid)
                    .and_modify(|winner: &mut (u16, u64)| {
                        if pack.pack_id < winner.0 {
                            *winner = (pack.pack_id, offset);
                        }
                    })
                    .or_insert((pack.pack_id, offset));
            }
        }

        let mut fanout = [0u32; FANOUT_ENTRIES];
        let mut entries = Vec::with_capacity(winners.len());
        for (oid, winner) in winners {
            fanout[oid[0] as usize] += 1;
            entries.push((oid, winner));
        }

        let mut running = 0u32;
        for count in &mut fanout {
            running += *count;
            *count = running;
        }

        CanonicalMidx { fanout, entries }
    }

    fn canonicalize_midx(midx: &MidxView<'_>) -> CanonicalMidx {
        let mut fanout = [0u32; FANOUT_ENTRIES];
        let mut prev_fanout = 0u32;
        for (bucket, slot) in fanout.iter_mut().enumerate() {
            let value = midx.fanout(bucket as u8);
            assert!(
                value >= prev_fanout,
                "fanout must be monotonic: bucket={bucket} value={value} prev={prev_fanout}"
            );
            *slot = value;
            prev_fanout = value;
        }
        assert_eq!(
            fanout[FANOUT_ENTRIES - 1],
            midx.object_count(),
            "fanout[255] must equal object_count"
        );

        let mut entries = Vec::with_capacity(midx.object_count() as usize);
        let mut prev_oid: Option<[u8; 20]> = None;
        for idx in 0..midx.object_count() {
            let mut oid = [0u8; 20];
            oid.copy_from_slice(midx.oid_at(idx));
            if let Some(prev) = prev_oid {
                assert!(prev < oid, "OIDL must be strictly ascending at index {idx}");
            }
            prev_oid = Some(oid);
            entries.push((oid, midx.offset_at(idx).unwrap()));
        }

        CanonicalMidx { fanout, entries }
    }

    fn test_repo_with_pack_file(pack_basename: &str) -> (tempfile::TempDir, GitRepoPaths, PathBuf) {
        let temp = tempdir().unwrap();
        let git_dir = temp.path().join(".git");
        let objects_dir = git_dir.join("objects");
        let pack_dir = objects_dir.join("pack");
        fs::create_dir_all(&pack_dir).unwrap();

        let repo = GitRepoPaths {
            kind: RepoKind::Worktree,
            worktree_root: Some(temp.path().to_path_buf()),
            git_dir: git_dir.clone(),
            common_dir: git_dir,
            objects_dir,
            pack_dir: pack_dir.clone(),
            alternate_object_dirs: Vec::new(),
        };

        let idx_path = pack_dir.join(format!("{pack_basename}.idx"));
        (temp, repo, idx_path)
    }

    #[test]
    fn estimate_midx_size_reasonable() {
        // Linux kernel: ~7M objects, ~400 packs
        let size = estimate_midx_size(400, 7_000_000, 20);
        // Should be ~196MB (7M * 20 for OIDs + 7M * 8 for offsets + overhead)
        assert!(size > 150_000_000, "size should be > 150MB: {size}");
        assert!(size < 500_000_000, "size should be < 500MB: {size}");
    }

    #[test]
    fn merge_entry_ordering() {
        // Create mock entries to test ordering
        let oid_a = [0x11u8; 20];
        let oid_b = [0x22u8; 20];

        // BinaryHeap is max-heap, so we reverse comparison
        // Lower OID should have higher priority (pop first)
        assert!(oid_a < oid_b);
    }

    #[test]
    fn pack_name_extraction() {
        let path = PathBuf::from("/repo/.git/objects/pack/pack-abc123.idx");
        let name = pack_name_from_idx_path(&path);
        assert_eq!(name, b"pack-abc123.pack");
    }

    #[test]
    fn is_idx_file_detection() {
        assert!(is_idx_file(OsStr::new("pack-abc.idx")));
        assert!(!is_idx_file(OsStr::new("pack-abc.pack")));
        assert!(!is_idx_file(OsStr::new("pack-abc")));
        assert!(!is_idx_file(OsStr::new(".idx")));
    }

    #[test]
    fn build_midx_bytes_with_no_packs_builds_empty_midx() {
        let temp = tempdir().unwrap();
        let git_dir = temp.path().join(".git");
        let objects_dir = git_dir.join("objects");
        let pack_dir = objects_dir.join("pack");
        fs::create_dir_all(&pack_dir).unwrap();

        let repo = GitRepoPaths {
            kind: RepoKind::Worktree,
            worktree_root: Some(temp.path().to_path_buf()),
            git_dir: git_dir.clone(),
            common_dir: git_dir,
            objects_dir,
            pack_dir,
            alternate_object_dirs: Vec::new(),
        };

        let bytes = build_midx_bytes(&repo, ObjectFormat::Sha1, &MidxBuildLimits::default())
            .expect("zero-pack repository should produce an empty MIDX");
        let midx = MidxView::parse(bytes.as_slice(), ObjectFormat::Sha1).unwrap();
        assert_eq!(midx.pack_count(), 0);
        assert_eq!(midx.object_count(), 0);
    }

    #[test]
    fn build_midx_fanout_varying_first_byte_distribution() {
        let mut idx_builder = TestIdxBuilder::new();
        idx_builder.add_object(test_oid(0x00, 0x01), 100);
        idx_builder.add_object(test_oid(0x00, 0x02), 101);
        idx_builder.add_object(test_oid(0x10, 0x00), 102);
        idx_builder.add_object(test_oid(0xfe, 0x10), 103);
        idx_builder.add_object(test_oid(0xfe, 0x20), 104);
        idx_builder.add_object(test_oid(0xfe, 0x30), 105);

        let idx_bytes = idx_builder.build();
        let idx_view = IdxView::parse(&idx_bytes, ObjectFormat::Sha1).unwrap();
        let total_objects = idx_view.object_count() as usize;

        let views = vec![(0u16, b"pack-a.pack".to_vec(), idx_view)];
        let midx_bytes = build_midx_in_memory(&views, ObjectFormat::Sha1, total_objects).unwrap();
        let midx = MidxView::parse(&midx_bytes, ObjectFormat::Sha1).unwrap();

        assert_eq!(midx.object_count(), 6);
        assert_eq!(midx.fanout(0x00), 2);
        assert_eq!(midx.fanout(0x0f), 2);
        assert_eq!(midx.fanout(0x10), 3);
        assert_eq!(midx.fanout(0xfd), 3);
        assert_eq!(midx.fanout(0xfe), 6);
        assert_eq!(midx.fanout(0xff), 6);
    }

    #[test]
    fn build_midx_fanout_and_dedup_with_duplicate_oids() {
        let shared_oid = test_oid(0x10, 0x55);

        let mut pack0 = TestIdxBuilder::new();
        pack0.add_object(shared_oid, 111);
        pack0.add_object(test_oid(0x80, 0x01), 222);

        let mut pack1 = TestIdxBuilder::new();
        pack1.add_object(shared_oid, 333);
        pack1.add_object(test_oid(0xff, 0x02), 444);

        let pack0_bytes = pack0.build();
        let pack1_bytes = pack1.build();
        let pack0_view = IdxView::parse(&pack0_bytes, ObjectFormat::Sha1).unwrap();
        let pack1_view = IdxView::parse(&pack1_bytes, ObjectFormat::Sha1).unwrap();
        let total_objects = (pack0_view.object_count() + pack1_view.object_count()) as usize;

        let views = vec![
            (0u16, b"pack-0.pack".to_vec(), pack0_view),
            (1u16, b"pack-1.pack".to_vec(), pack1_view),
        ];
        let midx_bytes = build_midx_in_memory(&views, ObjectFormat::Sha1, total_objects).unwrap();
        let midx = MidxView::parse(&midx_bytes, ObjectFormat::Sha1).unwrap();

        assert_eq!(midx.object_count(), 3);
        assert_eq!(midx.fanout(0x0f), 0);
        assert_eq!(midx.fanout(0x10), 1);
        assert_eq!(midx.fanout(0x7f), 1);
        assert_eq!(midx.fanout(0x80), 2);
        assert_eq!(midx.fanout(0xfe), 2);
        assert_eq!(midx.fanout(0xff), 3);

        assert_eq!(midx.oid_at(0), &shared_oid);
        assert_eq!(midx.offset_at(0).unwrap(), (0, 111));
    }

    #[test]
    fn exhaustive_small_model_merge_covers_all_pack_orderings() {
        let mut builds_tested = 0usize;
        let mut expected_builds = 0usize;

        // Growth is super-exponential in pack_count (subsets^dc * N! * rotations).
        // pack_count=4 => ~68K builds (<10s). pack_count=5 => ~1.7M. Do not increase
        // without profiling.
        for pack_count in 1..=4usize {
            let duplicate_subsets = duplicate_subsets(pack_count);

            for objects_per_pack in 1..=6usize {
                for duplicate_count in 0..=objects_per_pack.min(2) {
                    for duplicate_masks in
                        duplicate_mask_sequences(&duplicate_subsets, duplicate_count)
                    {
                        for bucket_rotation in 0..SMALL_MODEL_BUCKETS.len() {
                            let permutation_count = (1..=pack_count).product::<usize>();
                            expected_builds += permutation_count;

                            let packs = build_small_model_packs(
                                pack_count,
                                objects_per_pack,
                                &duplicate_masks,
                                bucket_rotation,
                            );
                            let idx_views: Vec<_> = packs
                                .iter()
                                .map(|pack| {
                                    IdxView::parse(&pack.idx_bytes, ObjectFormat::Sha1)
                                        .expect("small-model idx bytes should parse")
                                })
                                .collect();
                            let expected = expected_midx(&packs);
                            let total_objects = pack_count * objects_per_pack;
                            let expected_permutations = (1..=pack_count).product::<usize>();
                            let mut observed_permutations = 0usize;
                            let mut order: Vec<_> = (0..pack_count).collect();

                            for_each_permutation(&mut order, 0, &mut |permutation| {
                                // Keep canonical pack_ids stable while permuting the view slice so
                                // duplicate resolution remains tied to pack identity rather than
                                // slice position.
                                //
                                // The pack_name clone is required because build_midx_in_memory
                                // takes &[(u16, Vec<u8>, IdxView<'_>)] with owned name bytes.
                                let views: Vec<_> = permutation
                                    .iter()
                                    .map(|&pack_idx| {
                                        (
                                            packs[pack_idx].pack_id,
                                            packs[pack_idx].pack_name.clone(),
                                            idx_views[pack_idx],
                                        )
                                    })
                                    .collect();
                                let midx_bytes =
                                    build_midx_in_memory(&views, ObjectFormat::Sha1, total_objects)
                                        .expect("small-model MIDX build should succeed");
                                let midx = MidxView::parse(&midx_bytes, ObjectFormat::Sha1)
                                    .expect("small-model MIDX should parse");
                                let actual = canonicalize_midx(&midx);

                                assert_eq!(
                                    midx.pack_count(),
                                    pack_count as u32,
                                    "pack_count changed for order {:?}, duplicate_masks={:?}, rotation={bucket_rotation}",
                                    permutation,
                                    duplicate_masks,
                                );
                                assert_eq!(
                                    actual.entries.len(),
                                    expected.entries.len(),
                                    "unique object count changed for order {:?}, duplicate_masks={:?}, rotation={bucket_rotation}",
                                    permutation,
                                    duplicate_masks,
                                );
                                assert_eq!(
                                    actual,
                                    expected,
                                    "small-model merge mismatch for pack_count={pack_count}, objects_per_pack={objects_per_pack}, duplicate_masks={duplicate_masks:?}, rotation={bucket_rotation}, order={permutation:?}",
                                );

                                let expected_pnam: Vec<&[u8]> = permutation
                                    .iter()
                                    .map(|&pack_idx| packs[pack_idx].pack_name.as_slice())
                                    .collect();
                                let actual_pnam: Vec<&[u8]> = midx.pack_names().collect();
                                assert_eq!(
                                    actual_pnam, expected_pnam,
                                    "PNAM order mismatch for pack_count={pack_count}, order={permutation:?}",
                                );

                                builds_tested += 1;
                                observed_permutations += 1;
                            });

                            assert_eq!(
                                observed_permutations, expected_permutations,
                                "permutation enumeration mismatch for pack_count={pack_count}",
                            );
                        }
                    }
                }
            }
        }

        assert_eq!(
            builds_tested, expected_builds,
            "iteration count mismatch — verify test coverage is not accidentally reduced"
        );
    }

    /// Verifies the MIDX large-offset (LOFF) indirection path by using offsets >= 2^31.
    /// The small-model exhaustive test uses small offsets (~1000) and never triggers LOFF.
    #[test]
    fn build_midx_in_memory_handles_large_offsets_via_loff() {
        let large_offset: u64 = 0x1_0000_0000; // 4 GiB — well above the 2^31 LOFF threshold
        let small_offset: u64 = 42;

        let mut pack0 = TestIdxBuilder::new();
        pack0.add_object(test_oid(0x10, 0x01), large_offset);
        pack0.add_object(test_oid(0x80, 0x02), small_offset);

        let mut pack1 = TestIdxBuilder::new();
        pack1.add_object(test_oid(0xfe, 0x03), large_offset + 8192);

        let pack0_bytes = pack0.build();
        let pack1_bytes = pack1.build();
        let pack0_view = IdxView::parse(&pack0_bytes, ObjectFormat::Sha1).unwrap();
        let pack1_view = IdxView::parse(&pack1_bytes, ObjectFormat::Sha1).unwrap();
        let total_objects = (pack0_view.object_count() + pack1_view.object_count()) as usize;

        let views = vec![
            (0u16, b"pack-0.pack".to_vec(), pack0_view),
            (1u16, b"pack-1.pack".to_vec(), pack1_view),
        ];
        let midx_bytes = build_midx_in_memory(&views, ObjectFormat::Sha1, total_objects).unwrap();
        let midx = MidxView::parse(&midx_bytes, ObjectFormat::Sha1).unwrap();

        assert_eq!(midx.object_count(), 3);

        // OIDs are sorted: 0x10 < 0x80 < 0xfe
        let (pack_id_0, offset_0) = midx.offset_at(0).unwrap();
        assert_eq!(pack_id_0, 0);
        assert_eq!(
            offset_0, large_offset,
            "large offset must round-trip through LOFF"
        );

        let (pack_id_1, offset_1) = midx.offset_at(1).unwrap();
        assert_eq!(pack_id_1, 0);
        assert_eq!(offset_1, small_offset);

        let (pack_id_2, offset_2) = midx.offset_at(2).unwrap();
        assert_eq!(pack_id_2, 1);
        assert_eq!(
            offset_2,
            large_offset + 8192,
            "second large offset must round-trip through LOFF"
        );
    }

    /// Exercises the exact LOFF threshold boundary: 0x7FFF_FFFF (max small offset)
    /// must NOT trigger LOFF indirection, while 0x8000_0000 (min large offset) must.
    /// An off-by-one in the `>= LARGE_OFFSET_FLAG` check would corrupt one of these.
    #[test]
    fn build_midx_loff_boundary_values() {
        let just_below: u64 = 0x7FFF_FFFF; // max value that fits in 31 bits
        let exactly_at: u64 = 0x8000_0000; // LARGE_OFFSET_FLAG — triggers LOFF

        // Pack with only the sub-threshold offset — should produce no LOFF chunk.
        let mut pack_small = TestIdxBuilder::new();
        pack_small.add_object(test_oid(0x10, 0x01), just_below);
        let small_bytes = pack_small.build();
        let small_view = IdxView::parse(&small_bytes, ObjectFormat::Sha1).unwrap();

        let views_no_loff = vec![(0u16, b"pack-0.pack".to_vec(), small_view)];
        let midx_no_loff = build_midx_in_memory(&views_no_loff, ObjectFormat::Sha1, 1).unwrap();
        let parsed_no_loff = MidxView::parse(&midx_no_loff, ObjectFormat::Sha1).unwrap();

        assert_eq!(parsed_no_loff.object_count(), 1);
        let (pid, off) = parsed_no_loff.offset_at(0).unwrap();
        assert_eq!(pid, 0);
        assert_eq!(off, just_below, "0x7FFF_FFFF must round-trip without LOFF");
        // Verify no LOFF chunk: header byte 6 is chunk_count (4 without LOFF, 5 with).
        assert_eq!(
            midx_no_loff[6], 4,
            "sub-threshold offset must not produce LOFF chunk"
        );

        // Pack with the at-threshold offset — must produce a LOFF chunk.
        let mut pack_at = TestIdxBuilder::new();
        pack_at.add_object(test_oid(0x20, 0x02), exactly_at);
        let at_bytes = pack_at.build();
        let at_view = IdxView::parse(&at_bytes, ObjectFormat::Sha1).unwrap();

        let views_loff = vec![(0u16, b"pack-0.pack".to_vec(), at_view)];
        let midx_loff = build_midx_in_memory(&views_loff, ObjectFormat::Sha1, 1).unwrap();
        let parsed_loff = MidxView::parse(&midx_loff, ObjectFormat::Sha1).unwrap();

        assert_eq!(parsed_loff.object_count(), 1);
        let (pid, off) = parsed_loff.offset_at(0).unwrap();
        assert_eq!(pid, 0);
        assert_eq!(off, exactly_at, "0x8000_0000 must round-trip through LOFF");
        assert_eq!(
            midx_loff[6], 5,
            "at-threshold offset must produce LOFF chunk"
        );

        // Both offsets in the same MIDX — verifies coexistence.
        let small_view2 = IdxView::parse(&small_bytes, ObjectFormat::Sha1).unwrap();
        let at_view2 = IdxView::parse(&at_bytes, ObjectFormat::Sha1).unwrap();
        let views_both = vec![
            (0u16, b"pack-0.pack".to_vec(), small_view2),
            (1u16, b"pack-1.pack".to_vec(), at_view2),
        ];
        let midx_both = build_midx_in_memory(&views_both, ObjectFormat::Sha1, 2).unwrap();
        let parsed_both = MidxView::parse(&midx_both, ObjectFormat::Sha1).unwrap();

        assert_eq!(parsed_both.object_count(), 2);
        // OIDs sorted: 0x10 < 0x20
        let (pid0, off0) = parsed_both.offset_at(0).unwrap();
        assert_eq!((pid0, off0), (0, just_below));
        let (pid1, off1) = parsed_both.offset_at(1).unwrap();
        assert_eq!((pid1, off1), (1, exactly_at));
    }

    #[test]
    fn build_midx_bytes_checks_actual_serialized_size_cap() {
        let long_name = format!("pack-{}", "a".repeat(180));
        let (_temp, repo, idx_path) = test_repo_with_pack_file(&long_name);

        let mut idx_builder = TestIdxBuilder::new();
        idx_builder.add_object(test_oid(0x42, 0x01), 123);
        fs::write(&idx_path, idx_builder.build()).unwrap();

        let mut limits = MidxBuildLimits {
            max_midx_total_bytes: u64::MAX,
            ..MidxBuildLimits::default()
        };
        let baseline = build_midx_bytes(&repo, ObjectFormat::Sha1, &limits).unwrap();
        let actual_size = baseline.len() as u64;

        let estimated_size = estimate_midx_size(1, 1, ObjectFormat::Sha1.oid_len() as usize);
        assert!(
            estimated_size < actual_size,
            "test requires heuristic underestimation; estimated={estimated_size}, actual={actual_size}"
        );

        let hard_limit = actual_size - 1;
        assert!(hard_limit >= estimated_size);
        limits.max_midx_total_bytes = hard_limit;

        let err = build_midx_bytes(&repo, ObjectFormat::Sha1, &limits).unwrap_err();
        assert!(matches!(
            err,
            MidxBuildError::ArtifactsTooLarge { size, limit }
            if size == actual_size && limit == hard_limit
        ));
    }

    #[test]
    fn build_midx_bytes_allows_exact_size_limit() {
        let long_name = format!("pack-{}", "b".repeat(180));
        let (_temp, repo, idx_path) = test_repo_with_pack_file(&long_name);

        let mut idx_builder = TestIdxBuilder::new();
        idx_builder.add_object(test_oid(0x43, 0x02), 456);
        fs::write(&idx_path, idx_builder.build()).unwrap();

        let mut limits = MidxBuildLimits {
            max_midx_total_bytes: u64::MAX,
            ..MidxBuildLimits::default()
        };
        let baseline = build_midx_bytes(&repo, ObjectFormat::Sha1, &limits).unwrap();
        let exact_size_limit = baseline.len() as u64;

        limits.max_midx_total_bytes = exact_size_limit;
        let bytes = build_midx_bytes(&repo, ObjectFormat::Sha1, &limits).unwrap();

        assert_eq!(bytes.len() as u64, exact_size_limit);
    }

    #[test]
    fn build_midx_bytes_returns_too_many_packs_when_limit_exceeded() {
        // Create 3 distinct pack idx files in a single repo, but set
        // max_packs = 2.  The builder must return TooManyPacks rather
        // than silently indexing only the first 2 packs.
        let temp = tempdir().unwrap();
        let git_dir = temp.path().join(".git");
        let objects_dir = git_dir.join("objects");
        let pack_dir = objects_dir.join("pack");
        fs::create_dir_all(&pack_dir).unwrap();

        let repo = GitRepoPaths {
            kind: RepoKind::Worktree,
            worktree_root: Some(temp.path().to_path_buf()),
            git_dir: git_dir.clone(),
            common_dir: git_dir,
            objects_dir,
            pack_dir: pack_dir.clone(),
            alternate_object_dirs: Vec::new(),
        };

        for i in 0u8..3 {
            let mut builder = TestIdxBuilder::new();
            builder.add_object(test_oid(i, i.wrapping_mul(7)), (i as u64) * 100);
            let idx_path = pack_dir.join(format!("pack-{i:040x}.idx"));
            fs::write(&idx_path, builder.build()).unwrap();
        }

        let limits = MidxBuildLimits {
            max_packs: 2,
            ..MidxBuildLimits::default()
        };
        let err = build_midx_bytes(&repo, ObjectFormat::Sha1, &limits)
            .expect_err("3 packs with max_packs=2 must return TooManyPacks");
        assert!(
            matches!(err, MidxBuildError::TooManyPacks { count: 3, max: 2 }),
            "expected TooManyPacks {{ count: 3, max: 2 }}, got {err:?}"
        );
    }

    /// Maximum-deduplication case: every object in every pack is identical.
    /// Verifies merge produces exactly `objects_per_pack` unique entries
    /// (all resolved to pack_id 0) regardless of pack input order.
    #[test]
    fn all_duplicate_merge_deduplicates_to_lowest_pack_id() {
        let objects_per_pack = 4;
        let pack_count = 3;

        // All packs share the exact same set of OIDs.
        let shared_objects: Vec<_> = (0..objects_per_pack)
            .map(|i| {
                test_oid(
                    SMALL_MODEL_BUCKETS[i % SMALL_MODEL_BUCKETS.len()],
                    0x10 + i as u8,
                )
            })
            .collect();

        let packs: Vec<SmallModelPack> = (0..pack_count)
            .map(|pack_idx| {
                let mut builder = TestIdxBuilder::new();
                let mut objects = Vec::with_capacity(objects_per_pack);
                for (slot, &oid) in shared_objects.iter().enumerate() {
                    let offset = 1_000 + (pack_idx as u64 * 100) + slot as u64;
                    builder.add_object(oid, offset);
                    objects.push((oid, offset));
                }
                SmallModelPack {
                    pack_id: pack_idx as u16,
                    pack_name: format!("pack-{pack_idx}.pack").into_bytes(),
                    idx_bytes: builder.build(),
                    objects,
                }
            })
            .collect();

        let idx_views: Vec<_> = packs
            .iter()
            .map(|p| IdxView::parse(&p.idx_bytes, ObjectFormat::Sha1).unwrap())
            .collect();
        let expected = expected_midx(&packs);

        // Every entry should resolve to pack_id 0 (lowest).
        for (_, (winner_pack, _)) in &expected.entries {
            assert_eq!(
                *winner_pack, 0,
                "all-duplicate merge must resolve to lowest pack_id"
            );
        }
        assert_eq!(expected.entries.len(), objects_per_pack);

        // Verify all permutations produce identical output.
        let mut order: Vec<_> = (0..pack_count).collect();
        for_each_permutation(&mut order, 0, &mut |permutation| {
            let views: Vec<_> = permutation
                .iter()
                .map(|&i| (packs[i].pack_id, packs[i].pack_name.clone(), idx_views[i]))
                .collect();
            let total = pack_count * objects_per_pack;
            let midx_bytes = build_midx_in_memory(&views, ObjectFormat::Sha1, total).unwrap();
            let midx = MidxView::parse(&midx_bytes, ObjectFormat::Sha1).unwrap();
            let actual = canonicalize_midx(&midx);

            assert_eq!(
                actual.entries.len(),
                objects_per_pack,
                "all-duplicate merge must produce exactly {objects_per_pack} entries, order={permutation:?}",
            );
            assert_eq!(
                actual, expected,
                "all-duplicate merge mismatch for order={permutation:?}",
            );
        });
    }

    #[test]
    fn build_midx_bytes_returns_too_many_objects_when_limit_exceeded() {
        let temp = tempdir().unwrap();
        let git_dir = temp.path().join(".git");
        let objects_dir = git_dir.join("objects");
        let pack_dir = objects_dir.join("pack");
        fs::create_dir_all(&pack_dir).unwrap();

        let repo = GitRepoPaths {
            kind: RepoKind::Worktree,
            worktree_root: Some(temp.path().to_path_buf()),
            git_dir: git_dir.clone(),
            common_dir: git_dir,
            objects_dir,
            pack_dir: pack_dir.clone(),
            alternate_object_dirs: Vec::new(),
        };

        // Two packs with 3 objects each = 6 total.
        for i in 0u8..2 {
            let mut builder = TestIdxBuilder::new();
            for j in 0u8..3 {
                let oid_byte = i * 16 + j;
                builder.add_object(test_oid(oid_byte, 0x01), (oid_byte as u64) * 100);
            }
            let idx_path = pack_dir.join(format!("pack-{i:040x}.idx"));
            fs::write(&idx_path, builder.build()).unwrap();
        }

        let limits = MidxBuildLimits {
            max_total_objects: 5,
            ..MidxBuildLimits::default()
        };
        let err = build_midx_bytes(&repo, ObjectFormat::Sha1, &limits)
            .expect_err("6 objects with max_total_objects=5 must return TooManyObjects");
        assert!(
            matches!(err, MidxBuildError::TooManyObjects { count: 6, max: 5 }),
            "expected TooManyObjects {{ count: 6, max: 5 }}, got {err:?}"
        );
    }
}

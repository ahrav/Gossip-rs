//! Pack planning for pack decode.
//!
//! Builds per-pack plans that describe which offsets must be decoded to
//! satisfy candidate blobs, including pack-local delta bases up to a
//! configured depth. The plan also records delta dependencies and basic
//! execution metadata for later execution strategies.
//!
//! REF deltas whose base is missing from the current pack are treated as
//! external dependencies and are not expanded further.
//!
//! # Algorithm
//! 1. Group candidates by `pack_id`.
//! 2. Parse entry headers for candidate offsets and resolve REF deltas.
//! 3. Expand a pack-local base closure up to `max_delta_depth`.
//! 4. Materialize sorted `need_offsets`, delta dependencies, and exec order.
//!
//! # Invariants
//! - `need_offsets` is sorted and unique.
//! - `candidate_offsets` is sorted by offset (ties by candidate index).
//! - `exec_order` indices refer to `need_offsets`.

use std::collections::VecDeque;
use std::fmt;

use ahash::{AHashMap, AHashSet};

use super::midx::MidxView;
use super::midx_error::MidxError;
use super::object_id::OidBytes;
use super::pack_candidates::PackCandidate;
use super::pack_inflate::{EntryKind, PackFile, PackParseError};
use super::pack_plan_model::{
    BaseLoc, CandidateAtOffset, DeltaDep, DeltaKind, PackPlan, PackPlanStats, NONE_U32,
};

/// Default safety bound for pack entry headers.
const DEFAULT_MAX_HEADER_BYTES: usize = 64;
/// Default maximum delta chain depth.
const DEFAULT_MAX_DELTA_DEPTH: u8 = 64;
/// Default maximum offsets tracked during planning.
const DEFAULT_MAX_WORKLIST_ENTRIES: usize = 1_000_000;
/// Default maximum REF base lookups during planning.
const DEFAULT_MAX_BASE_LOOKUPS: usize = 1_000_000;

/// Config for pack planning.
///
/// `max_delta_depth` counts delta edges from a candidate to its base.
/// A depth of 0 disables base expansion entirely.
#[derive(Clone, Copy, Debug)]
pub struct PackPlanConfig {
    /// Maximum delta chain depth to traverse (0 disables base expansion).
    pub max_delta_depth: u8,
    /// Safety bound for header parsing.
    pub max_header_bytes: usize,
    /// Maximum number of unique offsets tracked during planning.
    pub max_worklist_entries: usize,
    /// Maximum REF base lookups during planning.
    pub max_base_lookups: usize,
}

impl Default for PackPlanConfig {
    fn default() -> Self {
        Self {
            max_delta_depth: DEFAULT_MAX_DELTA_DEPTH,
            max_header_bytes: DEFAULT_MAX_HEADER_BYTES,
            max_worklist_entries: DEFAULT_MAX_WORKLIST_ENTRIES,
            max_base_lookups: DEFAULT_MAX_BASE_LOOKUPS,
        }
    }
}

/// Errors from pack planning.
///
/// Planning failures are fatal for the pack: no partial plan is emitted.
#[derive(Debug)]
pub enum PackPlanError {
    /// Pack parsing failed.
    PackParse(PackParseError),
    /// A candidate offset points outside the pack.
    CandidateOffsetOutOfRange { pack_id: u16, offset: u64 },
    /// `pack_id` does not exist in the provided pack list.
    PackIdOutOfRange { pack_id: u16, pack_count: usize },
    /// Unique offsets exceeded the configured worklist limit.
    WorklistLimitExceeded { limit: usize, observed: usize },
    /// REF base lookups exceeded the configured limit.
    BaseLookupLimitExceeded { limit: usize, observed: usize },
    /// Delta dependency graph contains a cycle.
    DeltaCycleDetected { pack_id: u16, offset: u64 },
    /// MIDX lookup or ordering error.
    MidxError(MidxError),
}

impl fmt::Display for PackPlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PackParse(err) => write!(f, "{err}"),
            Self::CandidateOffsetOutOfRange { pack_id, offset } => {
                write!(
                    f,
                    "candidate offset {offset} out of range for pack {pack_id}"
                )
            }
            Self::PackIdOutOfRange {
                pack_id,
                pack_count,
            } => {
                write!(
                    f,
                    "pack id {pack_id} out of range (pack count {pack_count})"
                )
            }
            Self::WorklistLimitExceeded { limit, observed } => {
                write!(
                    f,
                    "pack plan worklist exceeded limit {limit} (saw {observed})"
                )
            }
            Self::BaseLookupLimitExceeded { limit, observed } => {
                write!(
                    f,
                    "pack plan base lookups exceeded limit {limit} (saw {observed})"
                )
            }
            Self::DeltaCycleDetected { pack_id, offset } => {
                write!(
                    f,
                    "delta cycle detected in pack {pack_id} at offset {offset}"
                )
            }
            Self::MidxError(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for PackPlanError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::PackParse(err) => Some(err),
            Self::MidxError(err) => Some(err),
            _ => None,
        }
    }
}

impl From<PackParseError> for PackPlanError {
    fn from(err: PackParseError) -> Self {
        Self::PackParse(err)
    }
}

impl From<MidxError> for PackPlanError {
    fn from(err: MidxError) -> Self {
        Self::MidxError(err)
    }
}

/// Resolves OIDs to pack offsets.
///
/// Implementations should return `Ok(None)` for missing OIDs rather than
/// treating them as errors; missing bases are tracked as external.
pub trait OidResolver {
    /// Returns `(pack_id, offset)` for the given OID if present.
    fn resolve(&self, oid: &OidBytes) -> Result<Option<(u16, u64)>, PackPlanError>;
}

impl<'a> OidResolver for MidxView<'a> {
    fn resolve(&self, oid: &OidBytes) -> Result<Option<(u16, u64)>, PackPlanError> {
        let Some(idx) = self.find_oid(oid)? else {
            return Ok(None);
        };
        let (pack_id, offset) = self.offset_at(idx)?;
        Ok(Some((pack_id, offset)))
    }
}

/// Header-only pack view for planning.
///
/// Expects the full pack bytes including the trailing hash. The view
/// only parses headers and does not verify checksums.
#[derive(Debug)]
pub struct PackView<'a> {
    file: PackFile<'a>,
    object_count: u32,
    oid_len: u8,
}

impl<'a> PackView<'a> {
    /// Parse a pack view from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns `PackParseError` if the pack header is invalid.
    pub fn parse(bytes: &'a [u8], oid_len: u8) -> Result<Self, PackParseError> {
        let file = PackFile::parse(bytes, oid_len as usize)?;
        let object_count = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        Ok(Self {
            file,
            object_count,
            oid_len,
        })
    }

    /// Parse the entry header at the given offset.
    ///
    /// The offset must point at an entry header (typically from MIDX/IDX).
    pub fn entry_header_at(
        &self,
        offset: u64,
        max_header_bytes: usize,
    ) -> Result<super::pack_inflate::EntryHeader, PackParseError> {
        self.file.entry_header_at(offset, max_header_bytes)
    }

    /// Returns the pack object count from the header.
    #[inline]
    #[must_use]
    pub const fn object_count(&self) -> u32 {
        self.object_count
    }

    /// Returns the configured OID length for this pack.
    #[inline]
    #[must_use]
    pub const fn oid_len(&self) -> u8 {
        self.oid_len
    }
}

/// Parsed entry metadata cached during planning.
#[derive(Clone, Copy, Debug)]
enum ParsedEntry {
    NonDelta,
    Ofs {
        base_offset: u64,
        data_start: u64,
        delta_size: u64,
    },
    Ref {
        base_oid: OidBytes,
        base: Option<(u16, u64)>,
        data_start: u64,
        delta_size: u64,
    },
}

/// Worklist entry for delta-base expansion.
#[derive(Clone, Copy, Debug)]
struct WorkItem {
    offset: u64,
    depth: u8,
}

/// Build pack plans for the given candidates.
///
/// Plans are deterministic for identical inputs. Candidates may share the
/// same pack offset; they are preserved as distinct entries in
/// `PackPlan.candidates` while `need_offsets` is deduplicated.
///
/// `packs` must be indexed by `pack_id` (PNAM order). Unused pack slots may
/// be `None`; referenced pack IDs must be `Some`, otherwise
/// `PackIdOutOfRange` is returned.
///
/// # Errors
///
/// Returns `PackPlanError` for invalid pack headers, out-of-range offsets,
/// or resolver failures.
pub fn build_pack_plans<'a, R: OidResolver>(
    mut candidates: Vec<PackCandidate>,
    packs: &[Option<PackView<'a>>],
    resolver: &R,
    config: &PackPlanConfig,
) -> Result<Vec<PackPlan>, PackPlanError> {
    if candidates.is_empty() {
        return Ok(Vec::new());
    }

    let (mut buckets, pack_ids) = bucket_pack_candidates_sparse(candidates.drain(..), packs.len())?;

    let mut plans = Vec::with_capacity(pack_ids.len());
    for pack_id in pack_ids {
        let pack_idx = pack_id as usize;
        let pack = packs.get(pack_idx).and_then(|pack| pack.as_ref()).ok_or(
            PackPlanError::PackIdOutOfRange {
                pack_id,
                pack_count: packs.len(),
            },
        )?;
        let pack_candidates = buckets[pack_idx].take().unwrap_or_default();

        let plan = build_pack_plan_for_pack(pack_id, pack, pack_candidates, resolver, config)?;
        plans.push(plan);
    }

    Ok(plans)
}

/// Build a pack plan for a single pack and its candidates.
///
/// # Preconditions
/// - `pack_id` must index `pack` in PNAM order.
/// - `candidates` must all refer to `pack_id`.
///
/// # Effects
/// - Expands delta bases up to `config.max_delta_depth`.
/// - Deduplicates candidate offsets into `need_offsets`.
///
/// # Errors
/// - Candidate offsets that are out of range return `CandidateOffsetOutOfRange`.
/// - Pack corruption or resolver failures return `PackPlanError`.
///
/// # Complexity
/// - `O((N + E) log(N + E))` where `N` is unique candidate offsets and `E`
///   is newly discovered pack-local base offsets. The final sort of all
///   `N + E` offsets dominates; binary-search lookups during base expansion
///   contribute an additional `O(E log N)` term that is subsumed.
pub(crate) fn build_pack_plan_for_pack<'a, R: OidResolver>(
    pack_id: u16,
    pack: &PackView<'a>,
    candidates: Vec<PackCandidate>,
    resolver: &R,
    config: &PackPlanConfig,
) -> Result<PackPlan, PackPlanError> {
    let mut candidate_offsets = Vec::with_capacity(candidates.len());
    for (idx, cand) in candidates.iter().enumerate() {
        candidate_offsets.push(CandidateAtOffset {
            offset: cand.offset,
            cand_idx: idx as u32,
        });
    }
    candidate_offsets.sort_by(|a, b| a.offset.cmp(&b.offset).then(a.cand_idx.cmp(&b.cand_idx)));
    debug_assert!(
        candidate_offsets.windows(2).all(|pair| {
            pair[0].offset < pair[1].offset
                || (pair[0].offset == pair[1].offset && pair[0].cand_idx < pair[1].cand_idx)
        }),
        "candidate_offsets must be sorted by offset then cand_idx"
    );

    let mut unique_candidate_offsets: Vec<u64> =
        candidate_offsets.iter().map(|c| c.offset).collect();
    unique_candidate_offsets.sort_unstable();
    unique_candidate_offsets.dedup();
    debug_assert!(is_sorted_unique(&unique_candidate_offsets));

    let candidate_span = span_from_sorted(&unique_candidate_offsets);

    let mut entry_cache: AHashMap<u64, ParsedEntry> =
        AHashMap::with_capacity(unique_candidate_offsets.len());

    let mut base_lookup_count = 0usize;
    for &offset in &unique_candidate_offsets {
        // Candidate offsets must be in range; base offsets are validated later.
        parse_entry(
            offset,
            pack,
            resolver,
            &mut entry_cache,
            config,
            pack_id,
            true,
            &mut base_lookup_count,
        )?;
    }

    let mut need_count = unique_candidate_offsets.len();
    if need_count > config.max_worklist_entries {
        return Err(PackPlanError::WorklistLimitExceeded {
            limit: config.max_worklist_entries,
            observed: need_count,
        });
    }
    let mut discovered_base_offsets: AHashSet<u64> =
        AHashSet::with_capacity(unique_candidate_offsets.len());

    let mut worklist: VecDeque<WorkItem> = unique_candidate_offsets
        .iter()
        .map(|&offset| WorkItem { offset, depth: 0 })
        .collect();

    while let Some(item) = worklist.pop_front() {
        let entry = parse_entry(
            item.offset,
            pack,
            resolver,
            &mut entry_cache,
            config,
            pack_id,
            false,
            &mut base_lookup_count,
        )?;

        let next_depth = item.depth.saturating_add(1);
        let can_expand = item.depth < config.max_delta_depth;

        match entry {
            ParsedEntry::NonDelta => {}
            ParsedEntry::Ofs { base_offset, .. } => {
                if base_offset == item.offset {
                    return Err(PackPlanError::DeltaCycleDetected {
                        pack_id,
                        offset: base_offset,
                    });
                }
                if can_expand {
                    enqueue_pack_local_base(
                        base_offset,
                        next_depth,
                        &unique_candidate_offsets,
                        &mut discovered_base_offsets,
                        &mut worklist,
                        &mut need_count,
                        config.max_worklist_entries,
                    )?;
                }
            }
            ParsedEntry::Ref { base, .. } => {
                if let Some((base_pack, base_offset)) = base {
                    if base_pack == pack_id && can_expand {
                        enqueue_pack_local_base(
                            base_offset,
                            next_depth,
                            &unique_candidate_offsets,
                            &mut discovered_base_offsets,
                            &mut worklist,
                            &mut need_count,
                            config.max_worklist_entries,
                        )?;
                    }
                }
            }
        }
    }

    let mut need_offsets = unique_candidate_offsets;
    if !discovered_base_offsets.is_empty() {
        need_offsets.extend(discovered_base_offsets);
        need_offsets.sort_unstable();
    }
    debug_assert!(is_sorted_unique(&need_offsets));
    debug_assert!(
        candidate_offsets
            .iter()
            .all(|cand| need_offsets.binary_search(&cand.offset).is_ok()),
        "candidate offset missing from need_offsets"
    );

    let delta_deps = build_delta_deps(&need_offsets, &entry_cache, pack_id);
    let delta_dep_index = build_delta_dep_index(&need_offsets, &delta_deps);
    let exec_result = build_exec_order(&need_offsets, &delta_deps, pack_id)?;
    let exec_order = exec_result.order;

    let external_bases = delta_deps
        .iter()
        .filter(|dep| matches!(dep.base, BaseLoc::External { .. }))
        .count() as u32;
    let forward_deps = delta_deps
        .iter()
        .filter(|dep| matches!(dep.base, BaseLoc::Offset(base) if base > dep.offset))
        .count() as u32;

    let mut stats = PackPlanStats {
        candidate_count: candidates.len() as u32,
        need_count: need_offsets.len() as u32,
        external_bases,
        forward_deps,
        candidate_span,
        ..PackPlanStats::empty()
    };
    crate::perf_stats::set_u32(&mut stats.delta_tree_roots, exec_result.tree_roots);
    crate::perf_stats::set_u32(&mut stats.delta_tree_max_depth, exec_result.max_depth);

    Ok(PackPlan {
        pack_id,
        oid_len: pack.oid_len(),
        max_delta_depth: config.max_delta_depth,
        candidates,
        candidate_offsets,
        need_offsets,
        delta_deps,
        delta_dep_index,
        exec_order,
        stats,
    })
}

/// Bucket pack candidates by pack id and return the active pack ids.
///
/// The returned bucket vector is sized to `pack_count` so callers can index
/// directly by pack id. `pack_ids` contains the unique pack ids that received
/// candidates, sorted ascending for deterministic planning.
///
/// # Errors
/// Returns `PackPlanError::PackIdOutOfRange` if any candidate references a
/// pack id outside `[0, pack_count)`.
pub(crate) fn bucket_pack_candidates<I>(
    candidates: I,
    pack_count: usize,
) -> Result<(Vec<Vec<PackCandidate>>, Vec<u16>), PackPlanError>
where
    I: IntoIterator<Item = PackCandidate>,
{
    let (buckets_sparse, pack_ids) = bucket_pack_candidates_sparse(candidates, pack_count)?;
    let buckets = buckets_sparse
        .into_iter()
        .map(|bucket| bucket.unwrap_or_default())
        .collect();
    Ok((buckets, pack_ids))
}

/// Per-pack sparse bucket: each index corresponds to a pack id and contains
/// `Some(candidates)` only for packs that have at least one candidate.
type SparseBuckets = Vec<Option<Vec<PackCandidate>>>;

/// Sparse variant of [`bucket_pack_candidates`] that only allocates touched buckets.
fn bucket_pack_candidates_sparse<I>(
    candidates: I,
    pack_count: usize,
) -> Result<(SparseBuckets, Vec<u16>), PackPlanError>
where
    I: IntoIterator<Item = PackCandidate>,
{
    let mut buckets: Vec<Option<Vec<PackCandidate>>> = vec![None; pack_count];
    let mut pack_ids: Vec<u16> = Vec::new();

    for cand in candidates {
        let pack_idx = cand.pack_id as usize;
        if pack_idx >= pack_count {
            return Err(PackPlanError::PackIdOutOfRange {
                pack_id: cand.pack_id,
                pack_count,
            });
        }
        let pack_id = cand.pack_id;
        let bucket_opt = &mut buckets[pack_idx];
        if bucket_opt.is_none() {
            pack_ids.push(pack_id);
            *bucket_opt = Some(Vec::new());
        }
        if let Some(bucket) = bucket_opt.as_mut() {
            bucket.push(cand);
        }
    }

    pack_ids.sort_unstable();
    Ok((buckets, pack_ids))
}

/// Parse an entry header at `offset` and cache the result.
///
/// Candidate offsets that are out of range return a dedicated error; base
/// offsets that are out of range are treated as pack corruption.
#[allow(clippy::too_many_arguments)]
fn parse_entry<R: OidResolver>(
    offset: u64,
    pack: &PackView<'_>,
    resolver: &R,
    cache: &mut AHashMap<u64, ParsedEntry>,
    config: &PackPlanConfig,
    pack_id: u16,
    is_candidate: bool,
    base_lookup_count: &mut usize,
) -> Result<ParsedEntry, PackPlanError> {
    if let Some(entry) = cache.get(&offset) {
        return Ok(*entry);
    }

    let header = match pack.entry_header_at(offset, config.max_header_bytes) {
        Ok(header) => header,
        Err(PackParseError::OffsetOutOfRange(_)) if is_candidate => {
            return Err(PackPlanError::CandidateOffsetOutOfRange { pack_id, offset })
        }
        // Base offsets outside the pack are treated as pack corruption.
        Err(err) => return Err(PackPlanError::PackParse(err)),
    };

    let parsed = match header.kind {
        EntryKind::NonDelta { .. } => ParsedEntry::NonDelta,
        EntryKind::OfsDelta { base_offset } => ParsedEntry::Ofs {
            base_offset,
            data_start: header.data_start as u64,
            delta_size: header.size,
        },
        EntryKind::RefDelta { base_oid } => {
            if *base_lookup_count >= config.max_base_lookups {
                return Err(PackPlanError::BaseLookupLimitExceeded {
                    limit: config.max_base_lookups,
                    observed: base_lookup_count.saturating_add(1),
                });
            }
            *base_lookup_count += 1;
            let base = resolver.resolve(&base_oid)?;
            ParsedEntry::Ref {
                base_oid,
                base,
                data_start: header.data_start as u64,
                delta_size: header.size,
            }
        }
    };

    cache.insert(offset, parsed);
    Ok(parsed)
}

/// Build delta dependency descriptors for the current pack.
///
/// Iterates `need_offsets` in ascending order and emits one [`DeltaDep`]
/// per delta entry. The output is therefore sorted by offset, matching
/// the `delta_deps` invariant on [`PackPlan`].
///
/// REF deltas whose base resolves to a different pack (or is unresolved)
/// are recorded as `BaseLoc::External`.
fn build_delta_deps(
    need_offsets: &[u64],
    cache: &AHashMap<u64, ParsedEntry>,
    pack_id: u16,
) -> Vec<DeltaDep> {
    let mut deps = Vec::new();
    for &offset in need_offsets {
        let Some(entry) = cache.get(&offset) else {
            continue;
        };
        match *entry {
            ParsedEntry::NonDelta => {}
            ParsedEntry::Ofs {
                base_offset,
                data_start,
                delta_size,
            } => deps.push(DeltaDep {
                offset,
                kind: DeltaKind::Ofs,
                base: BaseLoc::Offset(base_offset),
                data_start,
                delta_size,
            }),
            ParsedEntry::Ref {
                base_oid,
                base,
                data_start,
                delta_size,
            } => {
                let base_loc = match base {
                    Some((base_pack, base_offset)) if base_pack == pack_id => {
                        BaseLoc::Offset(base_offset)
                    }
                    _ => BaseLoc::External { oid: base_oid },
                };
                deps.push(DeltaDep {
                    offset,
                    kind: DeltaKind::Ref,
                    base: base_loc,
                    data_start,
                    delta_size,
                });
            }
        }
    }
    deps
}

/// Build a dense index from `need_offsets` position to `delta_deps` position.
///
/// Both inputs are sorted by offset, so a single forward-only merge cursor
/// produces the mapping in O(n + m) without hashing. Entries with no
/// matching dependency get [`NONE_U32`].
fn build_delta_dep_index(need_offsets: &[u64], delta_deps: &[DeltaDep]) -> Vec<u32> {
    let mut index = vec![NONE_U32; need_offsets.len()];
    if delta_deps.is_empty() {
        return index;
    }

    let mut dep_idx = 0usize;
    for (need_idx, &offset) in need_offsets.iter().enumerate() {
        while dep_idx < delta_deps.len() && delta_deps[dep_idx].offset < offset {
            dep_idx += 1;
        }
        if dep_idx < delta_deps.len() && delta_deps[dep_idx].offset == offset {
            index[need_idx] = dep_idx as u32;
            dep_idx += 1;
        }
    }

    debug_assert!(
        dep_idx <= delta_deps.len(),
        "delta_dep_index ran past delta_deps"
    );
    index
}

/// Result from `build_exec_order` including diagnostic stats.
#[doc(hidden)]
pub struct ExecOrderResult {
    /// DFS execution order, or `None` when natural order suffices.
    pub(crate) order: Option<Vec<u32>>,
    /// Number of indegree-0 nodes with dependents (delta tree roots).
    pub(crate) tree_roots: u32,
    /// Maximum depth of the dependency DAG.
    pub(crate) max_depth: u32,
}

impl ExecOrderResult {
    /// Returns the DFS execution order, or `None` when natural order suffices.
    #[inline]
    #[must_use]
    pub fn order(&self) -> Option<&[u32]> {
        self.order.as_deref()
    }

    /// Returns the number of indegree-0 nodes with dependents (delta tree roots).
    #[inline]
    #[must_use]
    pub fn tree_roots(&self) -> u32 {
        self.tree_roots
    }

    /// Returns the maximum depth of the dependency DAG.
    #[inline]
    #[must_use]
    pub fn max_depth(&self) -> u32 {
        self.max_depth
    }
}

/// Build a cache-aware DFS execution order for pack delta chains.
///
/// Produces subtree-contiguous ordering: each base is immediately followed by
/// all of its dependents before moving to the next base. This minimizes the
/// number of bases that must survive in cache simultaneously (working set is
/// bounded by tree depth for tree-structured chains; may be slightly higher
/// for DAGs with shared dependents).
///
/// Returns `None` when there are no pack-local delta dependencies, or when
/// the DFS order matches the natural `[0, 1, ..., n-1]` sequence (preserving
/// the fast monotone merge cursor path in the executor).
///
/// # Algorithm
///
/// Returns `None` immediately if no pack-local deps exist (fast path).
/// Otherwise:
///
/// 1. **CSR adjacency**: Build compact forward/reverse CSR edge lists from
///    sorted offsets.
/// 2. **Descendant counts**: BFS from leaves upward to compute subtree sizes.
/// 3. **DFS with LIFO stack**: Thin subtrees first (ascending `desc_count`),
///    pushed in reverse so thinnest lands on top. DAG nodes wait until all
///    parents are emitted (`dag_remaining` counter).
/// 4. **Identity check**: If the result is `[0..n]`, return `None`.
///
/// # Worked example
///
/// ```text
/// need_offsets = [100, 200, 300, 400, 500]   (indices 0..4)
///
/// delta_deps:
///   300 (idx 2) ─base→ 100 (idx 0)     // backward dep
///   400 (idx 3) ─base→ 100 (idx 0)     // backward dep
///   500 (idx 4) ─base→ 400 (idx 3)     // backward dep
///
/// DAG (base → dependent):
///
///        0 (100)         1 (200, independent)
///       / \
///      2   3 (400)
///          |
///          4
///
/// Phase 1 – CSR adjacency:
///   forward[0] = [2, 3]   forward[3] = [4]
///   indegree:  [0, 0, 1, 1, 1]
///   outdegree: [2, 0, 0, 1, 0]
///
/// Phase 2 – Descendant counts (leaf BFS upward):
///   leaves = {1, 2, 4}
///   desc_count[3] += (desc_count[4]+1) = (0+1) → desc_count[3] = 1
///   desc_count[0] += (desc_count[2]+1) = (0+1) → desc_count[0] = 1
///   desc_count[0] += (desc_count[3]+1) = (1+1) → desc_count[0] = 3
///   result: desc_count = [3, 0, 0, 1, 0]
///
/// Phase 3 – DFS (thin subtrees first):
///   Sort children of 0 by desc_count: [2(0), 3(1)] → thin first
///   Roots by descending desc_count: [0(3), 1(0)]
///   Push roots in order → stack [0, 1] (LIFO: 1 on top)
///
///   pop 1 → emit 1, no children          → stack [0]
///   pop 0 → emit 0, push children rev [3, 2] → stack [3, 2]
///   pop 2 → emit 2, no children          → stack [3]
///   pop 3 → emit 3, push child [4]       → stack [4]
///   pop 4 → emit 4, no children          → stack []
///
///   order = [1, 0, 2, 3, 4]
///
/// Phase 4 – Identity check:
///   [1, 0, 2, 3, 4] ≠ [0, 1, 2, 3, 4] → return Some(order)
///
/// Result: bases decoded before dependents, thin subtree {0,2}
/// completes before deep subtree {0,3,4}, minimising live cache
/// entries at any point.
/// ```
#[doc(hidden)]
pub fn build_exec_order(
    need_offsets: &[u64],
    delta_deps: &[DeltaDep],
    pack_id: u16,
) -> Result<ExecOrderResult, PackPlanError> {
    let n = need_offsets.len();
    if n == 0 {
        return Ok(ExecOrderResult {
            order: None,
            tree_roots: 0,
            max_depth: 0,
        });
    }

    // Fast path: skip graph setup when there are no pack-local deps.
    let local_dep_count = delta_deps
        .iter()
        .filter(|dep| matches!(dep.base, BaseLoc::Offset(_)))
        .count();
    if local_dep_count == 0 {
        return Ok(ExecOrderResult {
            order: None,
            tree_roots: 0,
            max_depth: 0,
        });
    }

    // Phase 1 — Local edge extraction and CSR adjacency build.
    //
    // We map both dep and base offsets with binary search against
    // `need_offsets`. This keeps the routine robust even if callers pass
    // `delta_deps` that are not pre-sorted by offset.
    let mut local_edges: Vec<(u32, u32)> = Vec::with_capacity(local_dep_count);
    for dep in delta_deps {
        let BaseLoc::Offset(base_offset) = dep.base else {
            continue;
        };
        let Ok(dep_idx) = need_offsets.binary_search(&dep.offset) else {
            continue;
        };
        let Ok(base_idx) = need_offsets.binary_search(&base_offset) else {
            continue;
        };
        local_edges.push((base_idx as u32, dep_idx as u32));
    }

    if local_edges.is_empty() {
        return Ok(ExecOrderResult {
            order: None,
            tree_roots: 0,
            max_depth: 0,
        });
    }

    let mut indegree = vec![0u32; n];
    let mut outdegree = vec![0u32; n];
    for &(base_idx, dep_idx) in &local_edges {
        outdegree[base_idx as usize] = outdegree[base_idx as usize].saturating_add(1);
        indegree[dep_idx as usize] = indegree[dep_idx as usize].saturating_add(1);
    }

    let forward_starts = build_csr_starts(&outdegree);
    let reverse_starts = build_csr_starts(&indegree);

    let mut forward_edges = vec![0u32; local_edges.len()];
    let mut reverse_edges = vec![0u32; local_edges.len()];
    let mut forward_cursor = forward_starts[..n].to_vec();
    let mut reverse_cursor = reverse_starts[..n].to_vec();
    for &(base_idx, dep_idx) in &local_edges {
        let base = base_idx as usize;
        let dep = dep_idx as usize;

        let f_slot = forward_cursor[base];
        forward_edges[f_slot] = dep_idx;
        forward_cursor[base] += 1;

        let r_slot = reverse_cursor[dep];
        reverse_edges[r_slot] = base_idx;
        reverse_cursor[dep] += 1;
    }

    // Phase 2 — Descendant counts: BFS from leaves upward.
    let mut desc_count = vec![0u32; n];
    let mut leaf_queue: VecDeque<usize> = VecDeque::new();
    let mut remaining_out = outdegree.clone();

    for (idx, &out_degree) in outdegree.iter().enumerate() {
        if out_degree == 0 {
            leaf_queue.push_back(idx);
        }
    }

    while let Some(idx) = leaf_queue.pop_front() {
        let rev_bounds = csr_row_bounds(&reverse_starts, idx);
        for &parent_u32 in &reverse_edges[rev_bounds] {
            let parent = parent_u32 as usize;
            // Propagate: parent gains this node + all its descendants.
            // Keep the inner increment saturating so we never overflow
            // before applying the outer accumulation saturation.
            let child_plus_self = desc_count[idx].saturating_add(1);
            desc_count[parent] = desc_count[parent].saturating_add(child_plus_self);
            debug_assert!(
                remaining_out[parent] > 0,
                "remaining_out underflow at parent {parent}"
            );
            remaining_out[parent] = remaining_out[parent].saturating_sub(1);
            if remaining_out[parent] == 0 {
                leaf_queue.push_back(parent);
            }
        }
    }

    // Compute tree_roots (indegree-0 nodes that have dependents) and max_depth.
    let mut tree_roots = 0u32;
    for idx in 0..n {
        if indegree[idx] == 0 && outdegree[idx] != 0 {
            tree_roots += 1;
        }
    }

    // Phase 3 — DFS with explicit LIFO stack.
    // Sort children by ascending desc_count (thin subtrees first).
    for idx in 0..n {
        let bounds = csr_row_bounds(&forward_starts, idx);
        sort_children_by_desc_count(&mut forward_edges[bounds], &desc_count);
    }

    // Collect roots sorted by descending desc_count (largest subtree pushed
    // first, so it ends up at the bottom of the stack — processed last).
    let mut roots: Vec<usize> = (0..n).filter(|&idx| indegree[idx] == 0).collect();
    roots.sort_unstable_by(|&a, &b| desc_count[b].cmp(&desc_count[a]));

    // dag_remaining tracks how many unresolved parents each node has.
    // A node is only pushed to the stack when dag_remaining hits zero.
    let mut dag_remaining = indegree.clone();

    let mut stack: Vec<u32> = Vec::with_capacity(n);
    for &root in &roots {
        stack.push(root as u32);
    }

    let mut order: Vec<u32> = Vec::with_capacity(n);
    while let Some(idx_u32) = stack.pop() {
        let idx = idx_u32 as usize;
        order.push(idx_u32);
        // Push children in reverse order so the thinnest (first after sort)
        // ends up on top of the stack.
        let bounds = csr_row_bounds(&forward_starts, idx);
        for i in (bounds.start..bounds.end).rev() {
            let child = forward_edges[i] as usize;
            debug_assert!(
                dag_remaining[child] > 0,
                "dag_remaining underflow at child {child}"
            );
            dag_remaining[child] = dag_remaining[child].saturating_sub(1);
            if dag_remaining[child] == 0 {
                stack.push(child as u32);
            }
        }
    }

    // Cycle check.
    if order.len() != n {
        let mut offset = 0u64;
        for (idx, &rem) in dag_remaining.iter().enumerate() {
            if rem != 0 {
                offset = need_offsets[idx];
                break;
            }
        }
        return Err(PackPlanError::DeltaCycleDetected { pack_id, offset });
    }

    // Compute max_depth precisely from the DFS topological order.
    let mut topo_depth = vec![0u32; n];
    let mut max_depth = 0u32;
    for &idx_u32 in &order {
        let idx = idx_u32 as usize;
        let bounds = csr_row_bounds(&forward_starts, idx);
        for &child_u32 in &forward_edges[bounds] {
            let child = child_u32 as usize;
            let child_depth = topo_depth[idx] + 1;
            if child_depth > topo_depth[child] {
                topo_depth[child] = child_depth;
            }
        }
        if topo_depth[idx] > max_depth {
            max_depth = topo_depth[idx];
        }
    }

    // Phase 4 — Identity check: if DFS order is [0, 1, ..., n-1], return None.
    let is_identity = order.iter().enumerate().all(|(i, &v)| v == i as u32);
    let order = if is_identity { None } else { Some(order) };

    Ok(ExecOrderResult {
        order,
        tree_roots,
        max_depth,
    })
}

#[inline(always)]
fn enqueue_pack_local_base(
    base_offset: u64,
    depth: u8,
    unique_candidate_offsets: &[u64],
    discovered_base_offsets: &mut AHashSet<u64>,
    worklist: &mut VecDeque<WorkItem>,
    need_count: &mut usize,
    max_worklist_entries: usize,
) -> Result<(), PackPlanError> {
    // Candidate offsets are already in the initial worklist and need set.
    if unique_candidate_offsets.binary_search(&base_offset).is_ok() {
        return Ok(());
    }
    if discovered_base_offsets.insert(base_offset) {
        *need_count += 1;
        if *need_count > max_worklist_entries {
            return Err(PackPlanError::WorklistLimitExceeded {
                limit: max_worklist_entries,
                observed: *need_count,
            });
        }
        worklist.push_back(WorkItem {
            offset: base_offset,
            depth,
        });
    }
    Ok(())
}

#[inline(always)]
fn build_csr_starts(degree: &[u32]) -> Vec<usize> {
    let mut starts = Vec::with_capacity(degree.len() + 1);
    starts.push(0usize);
    let mut acc = 0usize;
    for &d in degree {
        acc += d as usize;
        starts.push(acc);
    }
    starts
}

#[inline(always)]
fn csr_row_bounds(starts: &[usize], row: usize) -> std::ops::Range<usize> {
    starts[row]..starts[row + 1]
}

#[inline(always)]
fn sort_children_by_desc_count(children: &mut [u32], desc_count: &[u32]) {
    match children.len() {
        0 | 1 => {}
        2 => {
            if desc_count[children[0] as usize] > desc_count[children[1] as usize] {
                children.swap(0, 1);
            }
        }
        3 => {
            if desc_count[children[0] as usize] > desc_count[children[1] as usize] {
                children.swap(0, 1);
            }
            if desc_count[children[1] as usize] > desc_count[children[2] as usize] {
                children.swap(1, 2);
            }
            if desc_count[children[0] as usize] > desc_count[children[1] as usize] {
                children.swap(0, 1);
            }
        }
        _ => {
            children.sort_unstable_by_key(|&child| desc_count[child as usize]);
        }
    }
}

/// Span (last - first) for a sorted offset list.
fn span_from_sorted(offsets: &[u64]) -> u64 {
    if offsets.is_empty() {
        0
    } else {
        offsets[offsets.len() - 1].saturating_sub(offsets[0])
    }
}

/// Returns true if the slice is strictly increasing.
fn is_sorted_unique(offsets: &[u64]) -> bool {
    offsets.windows(2).all(|pair| pair[0] < pair[1])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Shorthand for an OFS_DELTA dependency: `offset` depends on `base`.
    fn ofs_dep(offset: u64, base: u64) -> DeltaDep {
        DeltaDep {
            offset,
            kind: DeltaKind::Ofs,
            base: BaseLoc::Offset(base),
            data_start: 0,
            delta_size: 0,
        }
    }

    /// Shorthand for a REF_DELTA dependency: `offset` depends on `base`.
    fn ref_dep(offset: u64, base: u64) -> DeltaDep {
        DeltaDep {
            offset,
            kind: DeltaKind::Ref,
            base: BaseLoc::Offset(base),
            data_start: 0,
            delta_size: 0,
        }
    }

    /// Helper: verify topological ordering (base before all dependents).
    fn assert_topo_valid(order: &[u32], edges: &[(u32, u32)]) {
        let pos: HashMap<u32, usize> = order.iter().enumerate().map(|(i, &v)| (v, i)).collect();
        for &(base, dep) in edges {
            assert!(
                pos[&base] < pos[&dep],
                "base {base} (pos {}) must precede dep {dep} (pos {})",
                pos[&base],
                pos[&dep],
            );
        }
    }

    /// Helper: check that a set of indices appear contiguously in the order.
    fn assert_contiguous(order: &[u32], group: &[u32]) {
        let pos: Vec<usize> = group
            .iter()
            .map(|v| order.iter().position(|&o| o == *v).unwrap())
            .collect();
        let lo = *pos.iter().min().unwrap();
        let hi = *pos.iter().max().unwrap();
        assert_eq!(
            hi - lo + 1,
            group.len(),
            "group {group:?} not contiguous in order {order:?}"
        );
    }

    #[test]
    fn exec_order_backward_deps_groups_subtrees() {
        // Even with all backward deps, DFS groups subtrees contiguously.
        // Offsets: 10(idx0)→50(idx1), 70(idx2) independent.
        let need_offsets = vec![10, 50, 70];
        let deps = vec![ofs_dep(50, 10)];
        let result = build_exec_order(&need_offsets, &deps, 0).unwrap();
        let order = result.order.expect("DFS reorders even backward deps");
        let pos_base = order.iter().position(|&v| v == 0).unwrap();
        let pos_dep = order.iter().position(|&v| v == 1).unwrap();
        assert!(pos_base < pos_dep, "base must precede dependent");
        assert_eq!(pos_dep - pos_base, 1, "subtree must be contiguous");
    }

    #[test]
    fn exec_order_respects_forward_dep() {
        let need_offsets = vec![10, 50, 70];
        let deps = vec![ref_dep(10, 50)];
        let result = build_exec_order(&need_offsets, &deps, 0).unwrap();
        let order = result.order.expect("exec order");
        let pos = |offset| {
            let idx = need_offsets.iter().position(|&o| o == offset).unwrap();
            order.iter().position(|&o| o == idx as u32).unwrap()
        };
        assert!(pos(50) < pos(10));
    }

    #[test]
    fn delta_dep_index_maps_need_offsets() {
        let need_offsets = vec![10, 20, 30, 40];
        let deps = vec![
            ofs_dep(20, 10),
            DeltaDep {
                offset: 40,
                kind: DeltaKind::Ref,
                base: BaseLoc::External {
                    oid: OidBytes::sha1([0x11; 20]),
                },
                data_start: 0,
                delta_size: 0,
            },
        ];
        let index = build_delta_dep_index(&need_offsets, &deps);
        assert_eq!(index, vec![NONE_U32, 0, NONE_U32, 1]);
    }

    // --- DFS execution order tests ---

    #[test]
    fn dfs_groups_subtrees_contiguously() {
        // base(0)→A(1), base(0)→B(2), base2(3)→C(4)
        let need_offsets = vec![10, 20, 30, 40, 50];
        let deps = vec![ofs_dep(20, 10), ofs_dep(30, 10), ofs_dep(50, 40)];
        let result = build_exec_order(&need_offsets, &deps, 0).unwrap();
        let order = result.order.expect("should produce non-identity order");
        assert_eq!(order.len(), 5);
        assert_topo_valid(&order, &[(0, 1), (0, 2), (3, 4)]);
        assert_contiguous(&order, &[0, 1, 2]);
        assert_contiguous(&order, &[3, 4]);
    }

    #[test]
    fn dfs_thin_subtree_first() {
        // root(0)→big_child(1), root(0)→thin_child(2)
        // big_child(1)→{g1..g5}(3..7), thin_child(2)→leaf(8)
        let need_offsets: Vec<u64> = (0..9).map(|i| (i + 1) * 100).collect();
        let deps = vec![
            ofs_dep(200, 100),
            ofs_dep(300, 100),
            ofs_dep(400, 200),
            ofs_dep(500, 200),
            ofs_dep(600, 200),
            ofs_dep(700, 200),
            ofs_dep(800, 200),
            ofs_dep(900, 300),
        ];
        let result = build_exec_order(&need_offsets, &deps, 0).unwrap();
        let order = result.order.expect("non-identity DFS order");
        assert_topo_valid(
            &order,
            &[
                (0, 1),
                (0, 2),
                (1, 3),
                (1, 4),
                (1, 5),
                (1, 6),
                (1, 7),
                (2, 8),
            ],
        );
        let pos = |idx: u32| order.iter().position(|&v| v == idx).unwrap();
        assert!(
            pos(2) < pos(1),
            "thin child (idx2) should be processed before big child (idx1)"
        );
    }

    #[test]
    fn dfs_linear_chain() {
        let need_offsets = vec![10, 20, 30, 40];
        let deps = vec![ofs_dep(20, 10), ofs_dep(30, 20), ofs_dep(40, 30)];
        let result = build_exec_order(&need_offsets, &deps, 0).unwrap();
        assert!(
            result.order.is_none(),
            "linear natural chain should be identity"
        );
        assert_eq!(result.tree_roots, 1);
        assert_eq!(result.max_depth, 3);
    }

    #[test]
    fn dfs_dag_shared_base() {
        // Node at offset 30 depends on both bases at 10 and 20.
        let need_offsets = vec![10, 20, 30];
        let deps = vec![ofs_dep(30, 10), ref_dep(30, 20)];
        let result = build_exec_order(&need_offsets, &deps, 0).unwrap();
        let order = result.order.expect("DAG reorders");
        assert_eq!(order.len(), 3);
        assert_topo_valid(&order, &[(0, 2), (1, 2)]);
    }

    #[test]
    fn dfs_returns_none_no_deps() {
        let need_offsets = vec![10, 20, 30];
        let deps = vec![];
        let result = build_exec_order(&need_offsets, &deps, 0).unwrap();
        assert!(result.order.is_none());
        assert_eq!(result.tree_roots, 0);
        assert_eq!(result.max_depth, 0);
    }

    #[test]
    fn dfs_returns_none_external_only_deps() {
        let need_offsets = vec![10, 20, 30];
        let deps = vec![DeltaDep {
            offset: 20,
            kind: DeltaKind::Ref,
            base: BaseLoc::External {
                oid: OidBytes::sha1([0xAB; 20]),
            },
            data_start: 0,
            delta_size: 0,
        }];
        let result = build_exec_order(&need_offsets, &deps, 0).unwrap();
        assert!(result.order.is_none());
        assert_eq!(result.tree_roots, 0);
        assert_eq!(result.max_depth, 0);
    }

    #[test]
    fn dfs_returns_none_when_local_base_missing_from_need_offsets() {
        let need_offsets = vec![10, 20];
        let deps = vec![ofs_dep(20, 30)];
        let result = build_exec_order(&need_offsets, &deps, 0).unwrap();
        assert!(result.order.is_none());
        assert_eq!(result.tree_roots, 0);
        assert_eq!(result.max_depth, 0);
    }

    #[test]
    fn dfs_three_children_keeps_largest_subtree_last() {
        // root(0) -> {1,2,3}; child(1) has two descendants.
        let need_offsets = vec![10, 20, 30, 40, 50, 60];
        let deps = vec![
            ofs_dep(20, 10),
            ofs_dep(30, 10),
            ofs_dep(40, 10),
            ofs_dep(50, 20),
            ofs_dep(60, 20),
        ];
        let result = build_exec_order(&need_offsets, &deps, 0).unwrap();
        let order = result.order.expect("non-identity order expected");
        let pos = |idx: u32| order.iter().position(|&v| v == idx).unwrap();
        assert!(pos(2) < pos(1), "thin child idx2 should precede idx1");
        assert!(pos(3) < pos(1), "thin child idx3 should precede idx1");
    }

    #[test]
    fn dfs_returns_none_natural_order() {
        let need_offsets = vec![10, 20, 30];
        let deps = vec![ofs_dep(20, 10), ofs_dep(30, 20)];
        let result = build_exec_order(&need_offsets, &deps, 0).unwrap();
        assert!(result.order.is_none(), "natural chain → identity → None");
    }

    #[test]
    fn dfs_cycle_detected() {
        let need_offsets = vec![10, 20];
        let deps = vec![ofs_dep(20, 10), ofs_dep(10, 20)];
        let result = build_exec_order(&need_offsets, &deps, 0);
        assert!(
            matches!(result, Err(PackPlanError::DeltaCycleDetected { .. })),
            "cycle must be detected"
        );
    }

    #[test]
    fn dfs_worked_example_matches_doc() {
        // Exact graph from the module-level worked example.
        let need_offsets = vec![100, 200, 300, 400, 500];
        let deps = vec![
            ofs_dep(300, 100), // idx 2 depends on idx 0
            ofs_dep(400, 100), // idx 3 depends on idx 0
            ofs_dep(500, 400), // idx 4 depends on idx 3
        ];
        let result = build_exec_order(&need_offsets, &deps, 0).unwrap();
        let order = result.order.expect("non-identity DFS order");

        // Roots sorted by descending desc_count: [0(3), 1(0)]
        // Push order: 0 first, then 1. Stack = [0, 1], LIFO.
        // Pop 1 -> emit 1 (no children)
        // Pop 0 -> emit 0, children [2, 3] sorted asc desc_count: [2(0), 3(1)]
        //   push reversed: [3, 2]. Stack [3, 2].
        // Pop 2 -> emit 2 (no children)
        // Pop 3 -> emit 3, push child [4]. Stack [4].
        // Pop 4 -> emit 4.
        // Order: [1, 0, 2, 3, 4]
        assert_eq!(order, vec![1, 0, 2, 3, 4]);
        assert_topo_valid(&order, &[(0, 2), (0, 3), (3, 4)]);
        assert_contiguous(&order, &[0, 2, 3, 4]);
    }

    #[test]
    fn dfs_duplicate_edges_no_underflow() {
        // Same dependency expressed twice (OFS + REF both point to same base).
        let need_offsets = vec![100, 200, 300];
        let deps = vec![
            ofs_dep(200, 100),
            ref_dep(200, 100), // duplicate edge: same base, different kind
        ];
        // Should succeed without panic; the duplicate edge bumps indegree to 2
        // but both decrements are handled safely.
        let result = build_exec_order(&need_offsets, &deps, 0);
        assert!(
            result.is_ok(),
            "duplicate edges must not cause panic or error"
        );
    }

    #[test]
    fn dfs_desc_count_inner_increment_saturates() {
        // Complete DAG over 34 nodes (edge i -> j for all i < j).
        // This yields desc_count[1] == u32::MAX, so propagating that child
        // into node 0 requires saturating the inner `+ 1`.
        let n = 34u64;
        let need_offsets: Vec<u64> = (0..n).map(|i| (i + 1) * 100).collect();
        let mut deps = Vec::new();
        for base in 0..n {
            for dep in (base + 1)..n {
                deps.push(ofs_dep(
                    need_offsets[dep as usize],
                    need_offsets[base as usize],
                ));
            }
        }

        let result = build_exec_order(&need_offsets, &deps, 0)
            .expect("desc_count propagation should saturate without overflow panic");
        assert!(
            result.order.is_none(),
            "complete DAG follows natural topological order"
        );
        assert_eq!(result.tree_roots, 1);
        assert_eq!(result.max_depth, 33);
    }

    #[test]
    fn dfs_multiple_independent_trees() {
        // Three independent delta trees plus two isolated nodes.
        //   Tree A: 10→20, 10→30
        //   Tree B: 40→50→60
        //   Tree C: 70→80
        //   Isolated: 90, 100
        let need_offsets = vec![10, 20, 30, 40, 50, 60, 70, 80, 90, 100];
        let deps = vec![
            ofs_dep(20, 10),
            ofs_dep(30, 10),
            ofs_dep(50, 40),
            ofs_dep(60, 50),
            ofs_dep(80, 70),
        ];
        let result = build_exec_order(&need_offsets, &deps, 0).unwrap();

        assert_eq!(
            result.tree_roots, 3,
            "should have 3 independent delta tree roots"
        );
        assert_eq!(result.max_depth, 2, "longest chain is 40→50→60 (depth 2)");

        let order = result
            .order
            .expect("non-trivial graph should produce exec_order");
        assert_eq!(order.len(), 10);

        // Each tree's nodes must be contiguous.
        assert_contiguous(&order, &[0, 1, 2]); // Tree A
        assert_contiguous(&order, &[3, 4, 5]); // Tree B
        assert_contiguous(&order, &[6, 7]); // Tree C

        // Topological validity.
        assert_topo_valid(&order, &[(0, 1), (0, 2), (3, 4), (4, 5), (6, 7)]);
    }
}

// ============================================================================
// Kani Bounded Model Checking Proofs
// ============================================================================

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// Maximum graph size for Kani proofs. Small to keep state space manageable.
    const MAX_N: usize = 6;
    /// Maximum edges for Kani proofs.
    const MAX_EDGES: usize = 12;

    /// Proves that `remaining_out` and `dag_remaining` counters in
    /// `build_exec_order` never underflow below 0.
    ///
    /// Constructs symbolic acyclic DAGs (edges only from lower to higher
    /// index) with bounded size, runs `build_exec_order`, and asserts it
    /// completes without panic (the `debug_assert!` guards inside the
    /// function would fire on underflow in debug builds; `saturating_sub`
    /// prevents wrap in release).
    #[kani::proof]
    #[kani::unwind(20)]
    fn dag_remaining_no_underflow() {
        let n: usize = kani::any();
        kani::assume(n >= 1 && n <= MAX_N);

        let need_offsets: Vec<u64> = (0..n as u64).map(|i| (i + 1) * 100).collect();

        let num_edges: usize = kani::any();
        kani::assume(num_edges <= MAX_EDGES);

        let mut deps = Vec::new();
        for _ in 0..num_edges {
            let from: usize = kani::any();
            let to: usize = kani::any();
            kani::assume(from < n && to < n && from != to);
            // Acyclicity: edges only go from lower to higher index.
            let (base_idx, dep_idx) = if from < to { (from, to) } else { (to, from) };
            deps.push(DeltaDep {
                offset: need_offsets[dep_idx],
                kind: DeltaKind::Ofs,
                base: BaseLoc::Offset(need_offsets[base_idx]),
                data_start: 0,
                delta_size: 0,
            });
        }

        // Must not panic — the debug_assert! guards inside build_exec_order
        // catch any underflow.
        let _ = build_exec_order(&need_offsets, &deps, 0);
    }
}

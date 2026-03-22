# Research Synthesis

PB-scale distributed filesystem scanner work partitioning for gossip-rs.

Five independent research agents investigated foundational theory (Agent 1),
production systems (Agent 2), failure modes (Agent 3), Rust ecosystem (Agent 4),
and industry practice (Agent 5). This document cross-references their 64
findings into a single evidence-ranked knowledge base.

---

## 1. Evidence Inventory

### 1.1 Unique Findings (64 total, de-duplicated)

Findings are grouped by topic. Where multiple agents independently surfaced the
same system or paper, corroboration count is noted.

#### Range-Based Partitioning Model

| ID | Finding | ES | Corroborated By | Agents |
|----|---------|----|-----------------| -------|
| F1 | Bigtable tablet model: half-open `[start,end)`, dynamic split at 100-200MB | 5 | F16, F61 | 1,2,5 |
| F11 | FoundationDB shard design: `[begin,end)` byte strings, unbundled architecture | 5 | F48, F58 | 1,4,5 |
| F14 | Consistent hashing destroys locality; incompatible with monotonic cursors | 5 | -- | 1 |
| F48 | FDB tuple layer: `0x00`/`0xFF` boundary bytes, prefix_successor = strinc | 5 | F11 | 4 |

**gossip-rs alignment:** `ShardSpec` already implements half-open `[start, end)` in
lexicographic byte order (`shard_spec.rs`). `key_encoding.rs` implements
`prefix_successor` (FDB strinc) and `byte_midpoint`. This is fully aligned with
the cross-agent consensus.

#### Dynamic Splitting & Size Triggers

| ID | Finding | ES | Corroborated By | Agents |
|----|---------|----|-----------------| -------|
| F16 | Bigtable: workers trigger splits, coordinator notified after. Midpoint of largest SSTable | 5 | F1 | 2 |
| F17 | CockroachDB: dual trigger (64MB size + 2500 QPS load). Reservoir sampling for split key | 5 | F51 | 2,5 |
| F18 | HBase: progressive threshold `Min(R^2 * flushSize, maxFileSize)` | 5 | F57 | 2,5 |
| F22 | Spanner: 10 split points per node. Split at row-tree roots for locality | 5 | F56 | 2,5 |
| F44 | TiKV: size-based accumulation scan, batch split points, approximate mode | 5 | F17 | 4 |
| F51 | CockroachDB auto splitting: size (512MB) + load | 5 | F17 | 5 |
| F55 | Snowflake micro-partitions: 50-500MB, automatic boundaries, 79% pruning via min/max | 5 | -- | 5 |
| F56 | Spanner resharding: split near row-tree root for locality | 5 | F22 | 5 |
| F57 | YugabyteDB: low phase (aggressive splitting), high phase (conservative) | 3 | F18 | 5 |
| F58 | FDB sequential workload: midpoint splitting suboptimal; split at last existing key. split_residual is the correct pattern | 3 | -- | 5 |

**gossip-rs alignment:** `SplitReplacePlan` and `SplitResidualPlan` exist in
`split.rs`. `StreamingSplitEstimator` in `split_estimator.rs` provides
byte-weighted split-key selection. The dual-axis (rank + byte) algorithm maps
to the CockroachDB/TiKV pattern. The `split_residual` operation directly
corresponds to F58's recommendation for sequential workloads.

#### Work-Stealing & Scheduling Theory

| ID | Finding | ES | Corroborated By | Agents |
|----|---------|----|-----------------| -------|
| F2 | Blumofe-Leiserson: expected time T1/P + O(T_inf). Favors dynamic when critical path is small | 4 | -- | 1 |
| F3 | DRQS: directories as work units, idle workers steal half of peer's queue. 7PB LANL test | 4 | F24, F54 | 1,2,5 |
| F6 | Power of Two Choices: least-loaded of 2 random candidates gives exponentially better balance | 4 | -- | 1 |
| F7 | LPT scheduling: sorting by decreasing size gives 4/3 approximation for makespan | 4 | -- | 1 |
| F24 | DRQS maps to gossip-rs split_residual: "send half your queue" = byte_midpoint split | 4 | F3 | 2 |
| F45 | rayon work-stealing: per-thread LIFO deques, random victim. Good in-process; does not extend to distributed | 5 | -- | 4 |
| F54 | DRQS hybrid static + dynamic is best | 4 | F3, F24 | 5 |

**gossip-rs alignment:** `split_residual` is the distributed equivalent of
DRQS "send half your queue." Lease-based claim is the distributed acquisition
mechanism. No explicit work-stealing protocol exists yet -- workers currently
acquire unclaimed shards, not steal from busy peers. The "steal" happens
implicitly when a shard is split and the residual becomes claimable.

#### File System Characteristics

| ID | Finding | ES | Corroborated By | Agents |
|----|---------|----|-----------------| -------|
| F4 | Ceph: migrates entire subtrees based on access patterns | 5 | -- | 1 |
| F5 | BetrFS: path bytes give contiguous ranges under lexicographic ordering. `/a/b/` occupies `["/a/b/", "/a/b0")` | 4 | -- | 1 |
| F8 | Number partitioning is NP-hard; greedy/LPT give constant-factor approximations | 4 | -- | 1 |
| F9 | File size distributions are heavy-tailed (double Pareto) | 4 | -- | 1 |
| F10 | Directory size follows power-law: most <100 files, some have millions. Tree depth 5-15 | 4 | -- | 1 |
| F12 | HDFS NameNode: 150 bytes/file metadata. 10B files = ~1.5TB. Full walk at 100K stat/sec = ~28 hours single-threaded | 3 | -- | 1 |

**gossip-rs alignment:** `PathKey` uses identity bytes (`path.as_bytes()`),
which gives the contiguous-subtree property from F5. Heavy-tailed distributions
(F9) are why `StreamingSplitEstimator` uses byte-weighted splitting rather than
count-balanced.

#### Input Format & Locality

| ID | Finding | ES | Corroborated By | Agents |
|----|---------|----|-----------------| -------|
| F19 | Hadoop FileInputFormat: `goalSize = totalSize / numSplits`, bounded by min/max. 1.1 slop factor | 5 | -- | 2 |
| F20 | Hadoop CombineFileInputFormat: three-tier locality (same-node, same-rack, cross-rack). 3hr to 6min | 5 | -- | 2 |
| F21 | Spark bin-packing: Next-Fit-Decreasing with `openCostInBytes` (4MB default) per file | 5 | -- | 2 |
| F23 | S3 fast-list: prefix-segmented parallel listing. 250x speedup at 1000-way | 3 | -- | 2 |
| F25 | restic serial bottleneck: 4-way directory parallelism gives 2.5x speedup | 2 | -- | 2 |
| F27 | Databricks Auto Loader: directory listing vs event notification | 3 | -- | 2 |

**gossip-rs alignment:** `Budgets` in `connector/common.rs` serves a role
analogous to `openCostInBytes` -- per-page budget limits. The connector
`fill_page` API naturally batches small items into pages. Spark's
per-file overhead model (F21) is relevant for shard sizing decisions.

#### Metadata & Control Plane

| ID | Finding | ES | Corroborated By | Agents |
|----|---------|----|-----------------| -------|
| F13 | Google Slicer: control/data plane separation. 30-180% load imbalance at Google scale | 5 | F52 | 1,5 |
| F38 | etcd metadata ceiling: default 2GB, configurable 8GB. 10M shards at ~KB each exceeds comfort | 5 | -- | 3 |
| F50 | GitHub Blackbird: shards by blob-ID hash. 15.5B docs, 53B files, 1.25PB | 5 | -- | 5 |
| F52 | Slicer: 63% fewer resources than static | 4 | F13 | 5 |
| F53 | Apache Iceberg: two-level manifest hierarchy. O(1) scan planning | 5 | -- | 5 |

**gossip-rs alignment:** The etcd backend already exists
(`gossip-coordination-etcd`). F38 is a hard constraint: shard count must be
bounded. `shard_limits.rs` enforces per-tenant and global ceilings, directly
addressing this. The two-level manifest pattern (F53) maps to
`ManifestRowKey` in `key_encoding.rs`.

#### Failure Modes & Edge Cases

| ID | Finding | ES | Corroborated By | Agents |
|----|---------|----|-----------------| -------|
| F28 | Small-files problem: per-file overhead dominates. 19.7x improvement from aggregation | 5 | -- | 3 |
| F29 | Single-object straggler: one giant file blocks shard completion. 8x slower, 47% duration increase | 5 | -- | 3 |
| F30 | Split storm: many concurrent splits overwhelm coordination. CockroachDB range grew 6MB to 6GB | 4 | -- | 3 |
| F31 | Zombie shard loop: lease expiry + re-split creates up to 1024 progressively smaller residuals | 3 | -- | 3 |
| F32 | Cursor-after-split corruption: split shrinks range, cursor outside. gossip-rs defends well | 4 | -- | 3 |
| F33 | NFS/FUSE readdir stall: 100K-entry NFS dir 218s vs 1.7s local | 5 | -- | 3 |
| F34 | Memory exhaustion during walk: 112 bytes/metadata * 500M = 56GB. BFS materializes frontier | 4 | -- | 3 |
| F35 | PathKey non-canonical paths: Unicode normalization (NFC vs NFD), case-insensitive FS | 3 | -- | 3 |
| F36 | Split-merge race: CockroachDB auto-merge undoes intentional splits | 3 | -- | 3 |
| F37 | Symlink loops and TOCTOU: symlink cycles, path replacement between readdir and open | 4 | -- | 3 |
| F39 | Uncoordinated checkpoint domino: gossip-rs avoids via per-shard independent checkpoints | 4 | -- | 3 |

**gossip-rs alignment:** F32 is defended (`split_residual_validate_cursor_bounds`
in `split_execution.rs`). F31 is bounded by `MAX_SPAWNED_PER_SHARD = 1024`
in `limits.rs`. F39 is solved by per-shard independent checkpoints. F35 is
acknowledged in the `PathKey` design (identity encoding, no normalization).

#### Rust-Specific Ecosystem

| ID | Finding | ES | Corroborated By | Agents |
|----|---------|----|-----------------| -------|
| F40 | ignore crate WalkParallel pathology: flat directories become serial | 3 | -- | 4 |
| F41 | jwalk: parallelizes readdir operations, not subtree traversals | 3 | -- | 4 |
| F42 | ripgrep: WalkParallel + per-thread Searcher cloning. Single-threaded scan, parallel file distribution | 5 | -- | 4 |
| F43 | Noseyparker: Rayon par_bridge + bounded channels. 256-partition BlobIdMap. 20TB | 4 | -- | 4 |
| F46 | tantivy: per-thread independent segments, merged post-ingestion | 3 | -- | 4 |
| F47 | gossip-rs StreamingSplitEstimator: dual-axis (rank + byte) streaming, O(1) observe, O(log n) estimate | 3 | -- | 4 |
| F49 | memcomparable crate: order-preserving key encoding from RisingWave | 3 | -- | 4 |

**gossip-rs alignment:** The codebase already chose single-threaded walk + sort
(F40 confirms this was correct). `StreamingSplitEstimator` (F47) is implemented
and tested. Bounded channels and backpressure are standard in the connector
architecture.

#### Industry / Application-Specific

| ID | Finding | ES | Corroborated By | Agents |
|----|---------|----|-----------------| -------|
| F15 | DynamoDB split-for-heat: dual trigger size (10GB) + load | 5 | F17 | 1 |
| F26 | Robinhood: parallel namespace walk on 700PB Lustre. Uses changelogs for incremental | 3 | -- | 2 |
| F59 | Semgrep: diff-aware caching, monorepo splitting. 1M+ scans/week | 2 | -- | 5 |
| F60 | GitLab Secret Detection: Sidekiq-enqueued refs, Gitleaks under hood | 2 | -- | 5 |
| F61 | Bigtable row key design: avoid monotonic prefixes, pad integers, group related rows | 5 | F1 | 5 |
| F62 | AWS Macie: one job per bucket, sampling for discovery | 2 | -- | 5 |
| F63 | Datadog: Kafka partition per node, decoupled ingestion/indexing | 2 | -- | 5 |
| F64 | Uber: coordinator fragments plan into tasks for workers. 100+PB | 2 | -- | 5 |

---

## 2. Consensus Matrix

### Decision 1: Key-Space Design

| Option | Evidence For | Evidence Against | Verdict |
|--------|-------------|------------------|---------|
| **Range-based `[start, end)` byte intervals** | F1 (ES:5), F11 (ES:5), F48 (ES:5), F22 (ES:5), F17 (ES:5), F44 (ES:5), F55 (ES:5). Unanimous across all 5 agents. All production systems use this. | None found. | **ADOPT. Already implemented.** |
| Consistent hashing | -- | F14 (ES:5): destroys locality, incompatible with monotonic checkpoint cursors. | **REJECT.** |
| Content-addressable (blob-ID hash) | F50 (ES:5): GitHub Blackbird uses this for dedup-oriented workloads. | Incompatible with ordered scan + checkpoint resume. Only viable for hash-based dedup. | **REJECT for scanning. Note for future dedup layer.** |

**Confidence: Very High.** No dissent among any agent.

### Decision 2: Static vs Dynamic Partitioning

| Option | Evidence For | Evidence Against | Verdict |
|--------|-------------|------------------|---------|
| **Hybrid: coarse static + dynamic split** | F54 (ES:4): DRQS hybrid is best. F1 (ES:5), F17 (ES:5), F18 (ES:5), F22 (ES:5): all production systems start coarse and split dynamically. F2 (ES:4): work-stealing theory supports this. | None found. | **ADOPT.** |
| Purely static | F19 (ES:5): Hadoop uses static. | F9 (ES:4), F10 (ES:4): heavy-tailed distributions make static balance impossible. F8 (ES:4): perfect partitioning is NP-hard. F29 (ES:5): stragglers inevitable. | **REJECT as sole strategy.** |
| Purely dynamic (start with 1 shard) | F3 (ES:4): directories as work units dynamically. | Slow ramp-up with few workers. F12 (ES:3): single-threaded full walk takes ~28 hours at PB scale. | **REJECT as sole strategy.** |

**Confidence: Very High.** Unanimous across agents.

### Decision 3: Split Trigger Mechanism

| Option | Evidence For | Evidence Against | Verdict |
|--------|-------------|------------------|---------|
| **Dual trigger: size + load** | F17 (ES:5), F15 (ES:5), F51 (ES:5): CockroachDB, DynamoDB, all use both. | More complex to implement. | **ADOPT.** |
| Size-only | F1 (ES:5), F44 (ES:5): Bigtable, TiKV. Simpler. | F29 (ES:5): does not catch hot spots from slow items within size budget. | **Acceptable as an initial trigger; upgrade to dual later.** |
| Load-only | -- | F28 (ES:5): small files have per-file overhead, load-only misses this. | **REJECT as sole trigger.** |

**Confidence: High.** Size-only is a valid starting point; dual is the end state.

### Decision 4: Split Key Selection

| Option | Evidence For | Evidence Against | Verdict |
|--------|-------------|------------------|---------|
| **Byte-weighted midpoint** | F47 (ES:3): gossip-rs StreamingSplitEstimator already implements this. F21 (ES:5): Spark byte-weight. F17 (ES:5): CockroachDB reservoir sampling for load-balanced point. | More complex than simple midpoint. | **ADOPT. Already implemented.** |
| Simple lexicographic midpoint | F16 (ES:5): Bigtable uses midpoint of largest SSTable. | F9 (ES:4): heavy-tailed file sizes make count-balanced splits waste work. | **Acceptable fallback when no byte stats.** |
| Last-existing-key (for sequential) | F58 (ES:3): FDB recommends this over midpoint for sequential inserts. | Only applies to append-heavy workloads. | **Already implemented as split_residual.** |

**Confidence: High.** Byte-weighted is the correct default; split_residual covers the sequential case.

### Decision 5: Shard Size Target

| Option | Evidence For | Evidence Against | Verdict |
|--------|-------------|------------------|---------|
| **50MB-512MB** | F55 (ES:5): Snowflake 50-500MB. F17 (ES:5): CockroachDB 64MB-512MB. F1 (ES:5): Bigtable 100-200MB. F19 (ES:5): Hadoop configurable. | Not filesystem-specific; may need tuning. | **ADOPT as default range. Make configurable.** |
| Fixed | -- | F18 (ES:5): HBase progressive threshold shows fixed is suboptimal for varying region counts. | **REJECT.** |

**Confidence: Medium.** Range is well-established for KV stores; filesystem walk cost may shift the sweet spot. Configurable thresholds are mandatory.

### Decision 6: Walk Strategy

| Option | Evidence For | Evidence Against | Verdict |
|--------|-------------|------------------|---------|
| **Single-threaded walk per shard + parallel shard distribution** | F42 (ES:5): ripgrep architecture. F40 (ES:3): WalkParallel pathology with flat dirs. F47 (ES:3): gossip-rs already chose this. | Less throughput on wide directory trees within a single shard. | **ADOPT. Already implemented.** |
| In-process parallel walk (rayon/jwalk) | F41 (ES:3): jwalk parallelizes readdir. F45 (ES:5): rayon work-stealing. | F40 (ES:3): pathological for flat dirs. F45 (ES:5): does not extend to distributed. | **REJECT for coordination-level; may use within a shard as optimization.** |

**Confidence: High.** The codebase already made the correct choice.

### Decision 7: Metadata Scalability

| Option | Evidence For | Evidence Against | Verdict |
|--------|-------------|------------------|---------|
| **Bounded shard count with per-tenant + global limits** | F38 (ES:5): etcd 2-8GB ceiling. Already implemented in `shard_limits.rs`. | Limits parallelism at extreme scale. | **ADOPT. Already implemented.** |
| Two-level manifest hierarchy | F53 (ES:5): Iceberg O(1) scan planning. | Additional complexity; not needed until shard counts exceed etcd comfort zone. | **CONSIDER for future if shard count grows beyond etcd limits.** |
| Unlimited shards | -- | F38 (ES:5): exceeds etcd storage. F30 (ES:4): split storms. | **REJECT.** |

**Confidence: High.** Current bounds are correct. Monitor etcd utilization.

### Decision 8: Checkpoint / Resume Model

| Option | Evidence For | Evidence Against | Verdict |
|--------|-------------|------------------|---------|
| **Per-shard independent monotonic cursors** | F39 (ES:4): avoids domino failures. F32 (ES:4): gossip-rs validates cursor-after-split. Already implemented. | No cross-shard dedup coordination. | **ADOPT. Already implemented.** |
| Global checkpoint | -- | F39 (ES:4): domino failure risk. | **REJECT.** |

**Confidence: Very High.** Already implemented and validated.

---

## 3. Evidence-Ranked Techniques

Ranked by `evidence_strength * applicability_to_gossip_rs * corroboration_count`.

| Rank | Technique | Score | Status in gossip-rs | Key Findings |
|------|-----------|-------|--------------------| -------------|
| 1 | Half-open `[start,end)` byte-range shards | 5 * 5 * 5 = 125 | **Implemented** | F1, F11, F48, F17, F22 |
| 2 | Byte-weighted split-key estimation | 5 * 5 * 3 = 75 | **Implemented** (`StreamingSplitEstimator`) | F47, F21, F17 |
| 3 | Dual-trigger split (size + load) | 5 * 5 * 3 = 75 | **Partially implemented at the mechanism layer** (`StreamingSplitEstimator` plus coordination split operations exist, but no automated runtime/orchestrator trigger is wired yet) | F17, F15, F51 |
| 4 | Split-residual for sequential/cursor-based work | 5 * 5 * 3 = 75 | **Implemented** (`SplitResidualPlan`) | F58, F24, F3 |
| 5 | Bounded shard count (etcd ceiling defense) | 5 * 5 * 2 = 50 | **Implemented** (`shard_limits.rs`) | F38, F30 |
| 6 | Progressive split threshold (aggressive early, conservative late) | 5 * 4 * 2 = 40 | **Not implemented** | F18, F57 |
| 7 | Cursor-after-split validation | 4 * 5 * 2 = 40 | **Implemented** (`split_residual_validate_cursor_bounds`) | F32, F39 |
| 8 | Small-file aggregation (batch per-file overhead) | 5 * 4 * 1 = 20 | **Partially implemented** (page-fill batching in connectors) | F28 |
| 9 | Two-level manifest hierarchy for O(1) planning | 5 * 3 * 2 = 30 | **Partially implemented** (`ManifestRowKey`) | F53, F55 |
| 10 | Power of Two Choices for shard acquisition | 4 * 4 * 1 = 16 | **Not implemented** | F6 |
| 11 | Straggler mitigation (intra-object parallelism) | 5 * 4 * 1 = 20 | **Not implemented** | F29 |
| 12 | Locality-aware shard assignment | 5 * 3 * 2 = 30 | **Not implemented** | F20, F4 |

---

## 4. Risk Register

Derived from Agent 3 failure-mode findings and cross-referenced with existing
defenses.

| # | Risk | Severity | Likelihood | Existing Defense | Residual Exposure | Source |
|---|------|----------|------------|------------------|-------------------|--------|
| R1 | **etcd metadata ceiling exceeded** | Critical | Medium | `shard_limits.rs` per-tenant + global caps | Limits must be tuned to etcd's actual DB size. No runtime monitoring of etcd storage utilization exists. | F38 |
| R2 | **Split storm under load** | High | Medium | `MAX_SPLIT_CHILDREN = 256`, `MAX_SPAWNED_PER_SHARD = 1024` | No rate-limiting on split operations across the cluster. A burst of concurrent splits could still overwhelm etcd write throughput. | F30 |
| R3 | **Zombie shard loop** | Medium | Low | `MAX_SPAWNED_PER_SHARD` bounds per-parent spawns | Counter is per-shard, not per-ancestry. Pathological regions can still generate 1024 tiny residuals before the cap fires. No escalation/parking of pathological key ranges. | F31 |
| R4 | **Single-object straggler** | High | High | None | A single enormous file (multi-TB) blocks shard completion. No intra-object parallelism. No mechanism to skip/defer stragglers. At PB scale with heavy-tailed distributions (F9), this is near-certain. | F29 |
| R5 | **NFS/FUSE readdir stall** | High | Medium (if NFS targets exist) | None | A single slow readdir blocks the entire shard walk. No per-operation timeout, no fallback to smaller directory batches. | F33 |
| R6 | **Memory exhaustion during walk** | Medium | Medium | Page-fill batching limits in-flight items | BFS frontier for deep trees could still grow large. No explicit memory budget for the walk frontier itself. | F34 |
| R7 | **PathKey non-canonical paths** | Medium | Low (single-platform) | `PathKey` uses identity bytes, no normalization | Cross-platform scans (macOS NFD vs Linux NFC) would produce different keys for the same file. Case-insensitive filesystems could miss dedup. | F35 |
| R8 | **Cursor-after-split on operator-initiated splits** | Medium | Low | `split_residual_validate_cursor_bounds()` | Defense exists for programmatic splits. Risk surfaces if an operator tool bypasses the validation path. | F32 |
| R9 | **Symlink loops / TOCTOU** | Medium | Low | None explicitly | No symlink cycle detection in walk. Path replacement between readdir and open is a race condition. | F37 |
| R10 | **Cross-shard dedup introduces checkpoint coupling** | Low | Low | Per-shard independent checkpoints | Current design avoids this. Risk emerges only if cross-shard deduplication is added without careful design. | F39 |

### Risk Priority Matrix

```
             Low Likelihood    Medium Likelihood    High Likelihood
            +-----------------+-------------------+------------------+
Critical    |                 | R1 (etcd ceiling) |                  |
            +-----------------+-------------------+------------------+
High        | R8 (operator    | R2 (split storm)  | R4 (straggler)   |
            |  split bypass)  | R5 (NFS stall)    |                  |
            +-----------------+-------------------+------------------+
Medium      | R7 (PathKey)    | R6 (walk memory)  |                  |
            | R9 (symlinks)   | R3 (zombie loop)  |                  |
            | R10 (dedup)     |                   |                  |
            +-----------------+-------------------+------------------+
```

**Top 3 risks requiring action:**
1. **R4 (straggler):** Near-certain at PB scale. Needs design work (timeout +
   re-split, or intra-file parallelism).
2. **R1 (etcd ceiling):** Needs runtime monitoring and alerting.
3. **R2 (split storm):** Needs cluster-wide split rate limiting.

---

## 5. Contradictions & Gaps

### 5.1 Contradictions

**C1: Midpoint split vs last-key split.**
F16 (Bigtable, ES:5) uses midpoint of largest SSTable. F58 (FoundationDB, ES:3)
says midpoint is suboptimal for sequential inserts and recommends splitting at
the last existing key. **Resolution:** These are not contradictory -- they
address different workload patterns. gossip-rs already has both:
`SplitReplacePlan` (midpoint) and `SplitResidualPlan` (cursor-based, analogous
to last-key). The split estimator chooses the byte-weighted midpoint, and
split_residual handles the sequential case. Both are needed.

**C2: In-process parallelism for walks.**
F40 (ES:3) says WalkParallel is pathological for flat directories, supporting
single-threaded walk. F41 (ES:3) says jwalk improves wide-directory readdir
parallelism. F25 (ES:2) says 4-way directory parallelism gives 2.5x speedup.
**Resolution:** These are compatible -- single-threaded walk is correct at the
*coordination* level (one walk per shard claim), but within a single shard's
walk, readdir parallelism on wide directories could be beneficial. The current
design is correct; intra-shard readdir parallelism is a potential optimization.

**C3: Shard size range.**
Production systems vary: Bigtable 100-200MB (F1), CockroachDB 64-512MB (F17),
Snowflake 50-500MB (F55), DynamoDB 10GB (F15). **Resolution:** These systems
have different cost models. Filesystem scanning has high per-shard coordination
cost (walk setup, readdir latency) and variable per-item cost (stat + read).
The 50-500MB range is a reasonable starting point, but the per-shard overhead
from F21 (Spark's openCostInBytes) suggests the lower bound should be tuned
based on measured walk setup cost.

### 5.2 Gaps in Evidence

**G1: Filesystem-specific split threshold tuning.**
All production split-threshold data (F1, F17, F18, F55) comes from KV stores or
columnar storage, not filesystem scanners. No agent found empirical data on
optimal shard size for filesystem walk + scan workloads specifically. The walk
cost (readdir + stat) per shard is fundamentally different from KV range-scan
cost. **Impact:** Shard size defaults will need empirical tuning via benchmarks
on representative filesystems.

**G2: Incremental/differential scanning.**
F26 (Robinhood, ES:3) and F27 (Databricks, ES:3) mention changelog-based
incremental scanning, but no agent explored how incremental scans interact with
the shard model. When a filesystem has barely changed, rescanning the entire
key range is wasteful. **Impact:** Future work should explore how checkpoint
cursors can incorporate filesystem modification timestamps or change journals
to skip unchanged subtrees.

**G3: Network-attached filesystem performance characteristics.**
F33 (NFS readdir stall, ES:5) is the only finding on network filesystem
behavior. No data on CIFS/SMB, HDFS FUSE, S3 FUSE (s3fs/goofys), or cloud
file-system performance profiles. **Impact:** Shard timeout and retry policies
may need filesystem-type-specific tuning.

**G4: Multi-root scanning.**
All findings assume a single root or a single key space. No agent addressed how
to partition work when scanning multiple independent filesystem roots (e.g.,
scanning 1000 NFS mounts simultaneously). **Impact:** The current `PathKey`
identity encoding works within a single root. Multi-root would need a
root-discriminator prefix in the key space.

**G5: Interaction between split decisions and detection engine cost.**
The research focuses on partitioning for enumeration throughput. No findings
address how detection engine cost (regex scanning, entropy analysis per file)
affects the optimal split strategy. If detection cost dominates enumeration,
byte-weighted splitting based on file size alone may still produce imbalanced
shards. **Impact:** The split estimator may need to incorporate estimated
detection cost per item, not just byte size.

**G6: etcd write amplification under split workloads.**
F38 covers etcd storage limits but no agent investigated write amplification.
Each split produces multiple etcd transactions (parent update + child creates).
Under sustained splitting, etcd Raft log growth and compaction behavior are
unknown. **Impact:** Needs benchmarking with the real etcd backend under split-
heavy workloads.

---

## 6. Key Insights

### Insight 1: gossip-rs is architecturally well-aligned with production consensus

The existing `[start, end)` byte-range model, `SplitReplacePlan` /
`SplitResidualPlan`, `StreamingSplitEstimator`, per-shard independent cursors,
and bounded shard counts collectively match the patterns used by Bigtable,
CockroachDB, FoundationDB, and Spanner. This is not accidental -- the
`shard_spec.rs` module header explicitly cites these systems. The foundation is
sound.

*Corroboration: 5/5 agents, 15+ findings at ES:5.*

### Insight 2: Split-residual IS distributed work-stealing

Agent 2 (F24) and Agent 5 (F54) independently identified that `split_residual`
is the distributed equivalent of the DRQS "send half your queue" operation.
This reframing is important: gossip-rs does not need a separate work-stealing
protocol. When a worker falls behind, the coordinator splits its shard and the
residual becomes available for another worker. The mechanism already exists; the
missing piece is the *trigger* -- detecting when a shard should be split due to
falling behind (load-based splitting, the second half of the dual trigger from
F17).

*Corroboration: Agents 1, 2, 5 (F3, F24, F54).*

### Insight 3: The straggler problem is the highest-risk gap

At PB scale with heavy-tailed file size distributions (F9, ES:4), encountering
multi-TB files that block shard completion is near-certain (F29, ES:5). Current
splitting operates at the shard/key-range level -- it cannot help when a single
object within a shard is the bottleneck. No agent found a clean solution in the
Rust ecosystem. Options from the literature: (a) timeout + park the shard and
move on, (b) intra-file range reads for parallelism, (c) speculative execution
on a second worker. This needs design work.

*Corroboration: Agent 3 (F29), Agent 1 (F9).*

### Insight 4: etcd is the binding constraint on shard count

The etcd 2-8GB ceiling (F38, ES:5) means shard metadata must stay bounded.
With `~1KB per shard record`, the hard ceiling is roughly 2-8 million shards.
`shard_limits.rs` provides the enforcement mechanism but the actual limit values
need calibration against real etcd deployments. A two-level metadata hierarchy
(F53, Iceberg-style) would extend this if needed, but adds complexity. Monitor
before optimizing.

*Corroboration: Agent 3 (F38), Agent 5 (F53).*

### Insight 5: Progressive split thresholds prevent both under- and over-splitting

HBase's `Min(R^2 * flushSize, maxFileSize)` formula (F18, ES:5) and
YugabyteDB's two-phase approach (F57, ES:3) solve a real problem: early in a
scan, aggressive splitting gets workers busy quickly; later, conservative
splitting avoids coordination overhead from too many tiny shards. gossip-rs
currently has fixed limits. Adopting a progressive threshold would improve
both ramp-up speed and steady-state efficiency.

*Corroboration: Agents 2, 5 (F18, F57).*

### Insight 6: Per-file overhead must be modeled in shard sizing

Spark's `openCostInBytes` (F21, ES:5) and the small-files problem (F28, ES:5)
both point to the same insight: the cost of *opening* a shard (walk setup,
directory enumeration, readdir latency) is non-trivial and must be factored into
minimum shard size. Creating shards smaller than the walk setup cost is
counterproductive. For filesystem scanning specifically, the readdir + stat cost
per directory entry on network filesystems (F33) can dominate actual file read
cost.

*Corroboration: Agents 2, 3 (F21, F28, F33).*

### Insight 7: The codebase already implements the hardest parts

The conceptually difficult components are already built and tested:
- Byte-order-preserving key encoding with `prefix_successor` and `byte_midpoint`
  (the FoundationDB tuple-layer equivalent)
- Streaming bounded-memory split estimation with dual-axis sampling
- Cursor-after-split validation
- Arena-pooled shard records for allocation-silent hot paths
- Simulation harness for invariant checking

What remains is largely *policy and runtime wiring* -- when to trigger splits,
how to size initial shards, how to handle stragglers, and where automated split
decisions are executed in the runtime. The hard coordination primitives already
exist, but the production worker loop does not yet invoke them automatically.

*Corroboration: Agents 3, 4 (F32, F47, F48).*

### Insight 8: NFS/FUSE is a deployment reality that demands defensive timeouts

F33 (ES:5) documents a 128x slowdown (218s vs 1.7s) for readdir on 100K-entry
NFS directories. At PB scale, network-attached filesystems are common targets.
The current connector architecture has no per-operation timeout for readdir/stat.
A single slow directory can stall a shard indefinitely. This needs a timeout +
park mechanism integrated with the shard lifecycle.

*Corroboration: Agent 3 (F33). Single source but ES:5 with real measurements.*

---

## Appendix A: Finding Cross-Reference Index

Findings referenced by more than one agent (strongest corroboration signals):

| Topic | Findings | Agents |
|-------|----------|--------|
| Bigtable tablet model | F1, F16, F61 | 1, 2, 5 |
| DRQS / work-stealing for FS | F3, F24, F54 | 1, 2, 5 |
| CockroachDB dual-trigger splitting | F17, F51 | 2, 5 |
| FoundationDB key-range design | F11, F48, F58 | 1, 4, 5 |
| Spanner resharding | F22, F56 | 2, 5 |
| Google Slicer control plane | F13, F52 | 1, 5 |
| HBase / YugabyteDB progressive thresholds | F18, F57 | 2, 5 |
| DynamoDB dual trigger | F15, F17 | 1, 2 |

## Appendix B: Source Bibliography

All sources as cited by the research agents (not independently verified):

- Adya et al., "Slicer: Auto-Sharding for Datacenter Applications," OSDI 2016
- Agrawal et al., "A Five-Year Study of File-System Metadata," FAST 2007
- Azar et al., "Balanced Allocations," SIAM J. Computing, 1999
- Blumofe & Leiserson, "Scheduling Multithreaded Computations by Work Stealing," JACM 1999
- Chang et al., "Bigtable: A Distributed Storage System for Structured Data," OSDI 2006
- Corbett et al., "Spanner: Google's Globally Distributed Database," OSDI 2012
- Graham, "Bounds on Multiprocessing Timing Anomalies," SIAM J. Applied Math, 1969
- Jannen et al., "BetrFS: A Right-Optimized Write-Optimized File System," ACM TOS, 2018
- Karger et al., "Consistent Hashing and Random Trees," STOC 1997
- LaFon, Misra, Bringhurst, "On Distributed File Tree Walk of Parallel File Systems," SC'12
- Mertens, "The Easiest Hard Problem: Number Partitioning," arXiv
- Mitzenmacher, "Dynamic Models for File Sizes and Double Pareto Distributions," Internet Mathematics, 2004
- Pan et al., "Facebook's Tectonic Filesystem," FAST 2021
- Shvachko, "HDFS Scalability: The Limits to Growth," USENIX ;login:, 2010
- Weil et al., "Dynamic Metadata Management for Petabyte-Scale File Systems," SC 2004
- Zhou et al., "FoundationDB: A Distributed Unbundled Transactional Key Value Store," SIGMOD 2021
- AWS documentation (DynamoDB, Macie)
- CockroachDB documentation + PR #31413, issues #6400, #37487
- Databricks documentation (Auto Loader)
- Google Cloud documentation (Bigtable, Spanner)
- Hadoop source (FileInputFormat, CombineFileInputFormat)
- MongoDB documentation + SERVER-12638
- Snowflake documentation
- Spark documentation + PR #11646
- restic issue #2275
- GitHub engineering blog (Blackbird)
- Netflix (Iceberg)
- Uber engineering blog

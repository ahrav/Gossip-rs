# Streaming Split Estimation

Split estimation is the mechanism by which connectors propose a key that divides a
shard's key space into two roughly equal halves **by total byte weight**, not by
item count. The `StreamingSplitEstimator` solves this as a bounded-memory streaming
problem: it observes keys one at a time during normal pagination walks, retains a
sparse sketch of representative samples, and produces a byte-weighted midpoint
estimate on demand.

Byte-balanced splitting matters because storage systems have skewed file-size
distributions. A naive count-based midpoint would assign a shard with one 10 GB
file and 10 000 tiny files almost entirely to one child. Byte-weighting ensures
each child inherits roughly half the total I/O cost.

The estimator achieves sub-linear memory (O(sample\_cap) regardless of stream
length), O(1) amortised per-observation cost, and O(log sample\_cap) estimation
via binary search. Compaction fires at most O(log(N / sample\_cap)) times over a
stream of N items, so the total cost of all compactions is O(N) amortised.

---

## 1. Split Estimation in the Scan Pipeline

Where split estimation fits within the larger enumeration and split lifecycle.
During pagination, each connector feeds observed `(key, file_size)` pairs into
the estimator. When the coordination layer decides a shard should split, it calls
`choose_split_point()`, which delegates to `estimate_split_key()`. The resulting
key becomes the split boundary for either a `SplitReplacePlan` (terminal) or
`SplitResidualPlan` (non-terminal).

```mermaid
%% Diagram: split-estimation-pipeline
graph LR
    subgraph B4 Connector ["B4: Connector — Enumeration Walk"]
        EP["enumerate_page()"]
        OBS["estimator.observe(key, size)"]
    end

    subgraph B4 Split ["B4: Connector — Split Selection"]
        CSP["choose_split_point(&shard, &cursor, budgets)"]
        EST["estimator.estimate_split_key()"]
        VAL["is_valid_split_candidate()"]
    end

    subgraph B3 Shard Algebra ["B3: Shard Algebra — Split Plans"]
        SRP["SplitReplacePlan"]
        SRS["SplitResidualPlan"]
    end

    subgraph B2 Coord ["B2: Coordination"]
        SPLIT["split_replace() / split_residual()"]
    end

    EP -->|"each in-range item"| OBS
    CSP --> EST
    EST -->|"Option&lt;split key&gt;"| VAL
    VAL -->|"Some(ItemKey)"| SRP
    VAL -->|"Some(ItemKey)"| SRS
    SRP --> SPLIT
    SRS --> SPLIT

    style EP fill:#FEE2E2,stroke:#991B1B
    style OBS fill:#FEE2E2,stroke:#991B1B
    style CSP fill:#FEE2E2,stroke:#991B1B
    style EST fill:#FEE2E2,stroke:#991B1B
    style VAL fill:#FEE2E2,stroke:#991B1B
    style SRP fill:#FFF7ED,stroke:#9A3412
    style SRS fill:#FFF7ED,stroke:#9A3412
    style SPLIT fill:#DCFCE7,stroke:#166534
```

The filesystem connector feeds the estimator incrementally as each DFS file is
emitted. The git and in-memory connectors hold all entries in memory, so they
bulk-load via `estimate_split_from_sorted()` at split-selection time. Both paths
converge on the same `StreamingSplitEstimator` algorithm — the batch connectors
simply set `sample_cap = entry_count` to avoid compaction and produce exact
results.

> **Cross-reference**: diagram 12 (Split Operations) details the `split_replace`
> and `split_residual` coordination protocol that consumes the split key produced
> here. Diagram 15 (Page Lifecycle) shows where `enumerate_page()` sits in the
> broader scan loop.

---

## 2. Dual-Axis Sampling Algorithm

The `observe()` method uses two independent sampling axes to decide whether an
incoming item should be retained as a sample. This dual-axis approach captures
both ordinal and byte-space coverage, giving the estimator resilience against
skewed file-size distributions.

```mermaid
%% Diagram: observe-dual-axis-sampling
flowchart TD
    START(["observe(key, file_size)"])
    FIRST{"first_observed_key<br/>is None?"}
    SAVE_FIRST["Store key as<br/>first_observed_key"]
    COMPUTE["rank = count<br/>recorded_byte_position = total_bytes<br/>end_bytes = total_bytes + file_size"]

    RANK_CHECK{"rank >= next_rank_sample?"}
    BYTE_CHECK{"file_size > 0 AND<br/>recorded_byte_position <= next_byte_mark<br/>AND next_byte_mark < end_bytes?"}
    EITHER{"sample_rank OR<br/>sample_bytes?"}

    RECORD["Push Sample {<br/>  key: Box&lt;[u8]&gt;,<br/>  rank: u64,<br/>  recorded_byte_position: u64<br/>}"]

    UPDATE["count += 1<br/>total_bytes = end_bytes"]
    CAP_CHECK{"samples.len() ><br/>sample_cap?"}
    COMPACT["grow_strides_and_compact()"]
    ADVANCE_RANK["next_rank_sample += rank_stride"]
    ADVANCE_BYTE["next_byte_mark += byte_stride<br/>(snap forward if file spans<br/>multiple marks)"]
    DONE(["return"])

    START --> FIRST
    FIRST -->|yes| SAVE_FIRST --> COMPUTE
    FIRST -->|no| COMPUTE
    COMPUTE --> RANK_CHECK
    COMPUTE --> BYTE_CHECK
    RANK_CHECK --> EITHER
    BYTE_CHECK --> EITHER
    EITHER -->|yes| RECORD --> UPDATE
    EITHER -->|no| UPDATE
    UPDATE --> CAP_CHECK
    CAP_CHECK -->|yes| COMPACT --> DONE
    CAP_CHECK -->|no| ADVANCE_RANK
    ADVANCE_RANK --> ADVANCE_BYTE --> DONE

    style START fill:#FEE2E2,stroke:#991B1B
    style RECORD fill:#FEE2E2,stroke:#991B1B
    style COMPACT fill:#EF4444,stroke:#991B1B,color:#fff
    style DONE fill:#F3F4F6,stroke:#374151
```

Key properties of the dual-axis trigger:

- **Rank axis** — samples every `rank_stride`-th item (initially 1, doubles on
  compaction). Provides ordinal coverage independent of file sizes.
- **Byte axis** — samples when a file's byte interval straddles `next_byte_mark`
  (initially every 1 byte, doubles on compaction). Provides byte-space fidelity
  for accurate median estimation.
- **At most one sample per `observe()` call** — even if a single large file spans
  multiple byte marks, only one sample is recorded. This guarantees O(1)
  per-observation cost at the expense of byte-axis gaps in regions dominated by
  very large files.
- **Byte-triggered samples record the exact stride mark** as their
  `recorded_byte_position`, giving tighter byte-space interpolation than
  rank-triggered samples (which record the position at the file's start).

---

## 3. Stride-Doubling Compaction

When the sample buffer exceeds `sample_cap`, the estimator runs
`grow_strides_and_compact()`. This halves the buffer and doubles both strides,
maintaining representative coverage as the stream grows. The total number of
compaction events over a stream of N items is at most O(log(N / sample\_cap)).

```mermaid
%% Diagram: stride-doubling-compaction
graph TD
    subgraph Before ["Before Compaction"]
        BUF_FULL["samples.len() > sample_cap<br/>(e.g. 1025 samples, cap = 1024)"]
    end

    subgraph Compaction ["grow_strides_and_compact()"]
        TARGET["target = sample_cap / 2<br/>(e.g. 512)"]
        AXIS{"compaction_axis:<br/>first.byte_pos != last.byte_pos?"}
        BYTE_AXIS["Use byte-position axis"]
        RANK_AXIS["Use rank axis<br/>(degenerate: all-zero-size)"]
        SELECT["selected_sample_indices():<br/>nearest-neighbor interpolation<br/>on chosen axis"]
        PLATEAU["redistribute_plateau_picks():<br/>spread clustered picks across<br/>full plateau rank extent"]
        SWAP["In-place swap: write cursor<br/>walks kept indices forward"]
        TRUNC["samples.truncate(target)"]
    end

    subgraph After ["After Compaction"]
        DOUBLE["rank_stride *= 2<br/>byte_stride *= 2"]
        REALIGN["next_rank_sample = align_to_stride(count, rank_stride)<br/>next_byte_mark = align_to_stride(total_bytes, byte_stride)"]
        BUF_HALF["samples.len() ≈ 512<br/>~half capacity, doubled resolution"]
    end

    BUF_FULL --> TARGET
    TARGET --> AXIS
    AXIS -->|"non-degenerate"| BYTE_AXIS --> SELECT
    AXIS -->|"degenerate"| RANK_AXIS --> SELECT
    SELECT --> PLATEAU
    PLATEAU --> SWAP --> TRUNC
    TRUNC --> DOUBLE --> REALIGN --> BUF_HALF

    style BUF_FULL fill:#FEE2E2,stroke:#991B1B
    style BYTE_AXIS fill:#FEE2E2,stroke:#991B1B
    style RANK_AXIS fill:#FEE2E2,stroke:#991B1B
    style SELECT fill:#EF4444,stroke:#991B1B,color:#fff
    style PLATEAU fill:#EF4444,stroke:#991B1B,color:#fff
    style BUF_HALF fill:#FEE2E2,stroke:#991B1B
    style DOUBLE fill:#FEE2E2,stroke:#991B1B
    style REALIGN fill:#FEE2E2,stroke:#991B1B
```

### Compaction invariants

- **Sample cap**: after each public operation returns, `samples.len() <= sample_cap`.
- **Monotonicity**: retained samples are strictly increasing in rank and
  non-decreasing in byte position, including after compaction.
- **Endpoint preservation**: the first and last samples are always retained,
  preventing boundary drift.
- **Plateau redistribution**: after nearest-neighbor selection, runs of picks that
  share the same axis value are spread evenly across the plateau's rank extent.
  Without this, byte-axis plateaus (e.g. a run of zero-size files after a single
  heavy file) cluster retained samples at the plateau's leading edge, degrading
  rank-axis diversity.

### Memory and convergence

The sketch's memory is bounded at `sample_cap` retained samples regardless of
stream length. Each compaction discards roughly half the samples and doubles the
sampling resolution, so the remaining samples span the entire observed range at
progressively coarser granularity. The `DEFAULT_SAMPLE_CAP` of 1024 achieves <1%
byte-weighted error on the crate's 20 000-key descending-size regression workload.

---

## 4. Split Key Estimation Decision

The `estimate_split_key()` method finds the retained key whose recorded byte
position is closest to the byte-weighted midpoint. Two boundary guards prevent
degenerate splits that would produce empty left or right shards.

```mermaid
%% Diagram: estimate-split-key-decision
flowchart TD
    START(["estimate_split_key()"])
    COUNT_CHECK{"count < 2?"}
    NONE1(["return None<br/>(need >= 2 items)"])

    ZERO_CHECK{"total_bytes == 0?"}
    RANK_FB["nearest_sample(Rank, count / 2)<br/>— all items are zero-size"]

    BYTE_SEARCH["target_weight = total_bytes / 2<br/>nearest_sample(Bytes, target_weight)<br/>— binary search on byte axis"]
    BYTE_MISS{"byte search<br/>returned None?"}
    RANK_SEARCH["nearest_sample(Rank, count / 2)<br/>— rank fallback"]

    FIRST_GUARD{"candidate ==<br/>first_observed_key?"}
    RANK_FB2["nearest_sample(Rank, count / 2)<br/>— avoid empty left shard"]

    LAST_GUARD{"candidate ==<br/>samples.last().key?"}
    RANK_FB3["nearest_sample(Rank, count / 2)<br/>— avoid empty right shard"]

    RETURN(["return Some(candidate)"])

    START --> COUNT_CHECK
    COUNT_CHECK -->|yes| NONE1
    COUNT_CHECK -->|no| ZERO_CHECK
    ZERO_CHECK -->|yes| RANK_FB --> RETURN
    ZERO_CHECK -->|no| BYTE_SEARCH
    BYTE_SEARCH --> BYTE_MISS
    BYTE_MISS -->|yes| RANK_SEARCH --> RETURN
    BYTE_MISS -->|no| FIRST_GUARD
    FIRST_GUARD -->|yes| RANK_FB2 --> RETURN
    FIRST_GUARD -->|no| LAST_GUARD
    LAST_GUARD -->|yes| RANK_FB3 --> RETURN
    LAST_GUARD -->|no| RETURN

    style START fill:#FEE2E2,stroke:#991B1B
    style BYTE_SEARCH fill:#EF4444,stroke:#991B1B,color:#fff
    style RANK_FB fill:#FEE2E2,stroke:#991B1B
    style RANK_FB2 fill:#FEE2E2,stroke:#991B1B
    style RANK_FB3 fill:#FEE2E2,stroke:#991B1B
    style RANK_SEARCH fill:#FEE2E2,stroke:#991B1B
    style RETURN fill:#F3F4F6,stroke:#374151
    style NONE1 fill:#F3F4F6,stroke:#374151
```

### Key design details

- **`nearest_sample` uses `partition_point`** (binary search) on the sample array
  for O(log sample\_cap) lookup. When the target falls between two samples, the
  one with smaller absolute distance wins; ties break to the earlier sample.
- **First-key guard**: the very first key observed is tracked in a separate
  `first_observed_key` field, surviving compaction. When weight is front-loaded
  (one huge file followed by many small files), the byte median can land on
  item 0. The guard falls back to rank midpoint instead, preventing an empty
  left shard.
- **Last-key guard**: the symmetric case for back-loaded weight. Compaction always
  preserves the last sample, so checking `samples.last()` is sufficient.
- **u128 arithmetic**: interpolation uses `u128` intermediate products to avoid
  overflow and floating-point precision loss for byte offsets above 2^53.
- **Key fidelity**: the estimator only returns actually observed keys — it never
  synthesizes or interpolates key bytes.

---

## 5. Integration with Connectors

All three connector implementations use `StreamingSplitEstimator` for split-point
selection, but they differ in how they feed observations into it.

```mermaid
%% Diagram: connector-integration
graph TD
    subgraph FS ["FilesystemConnector — streaming"]
        FS_FIELD["split_estimator: StreamingSplitEstimator<br/>(field, created at construction)"]
        FS_ENUM["enumerate_page_core():<br/>self.split_estimator.observe(key, size)<br/>for each in-range file"]
        FS_SPLIT["choose_split_point_bounds():<br/>self.split_estimator.estimate_split_key()"]
        FS_RESET["rebuild_walk_state():<br/>reset estimator to fresh state"]
    end

    subgraph GIT ["GitConnector — batch"]
        GIT_ENTRIES["entries: Vec&lt;GitEntry&gt;<br/>(all index entries in memory)"]
        GIT_SPLIT["choose_split_point_bounds():<br/>common::estimate_split_from_sorted(<br/>  entries.iter().map(key, size),<br/>  range.len(), cursor, end<br/>)"]
    end

    subgraph MEM ["InMemoryDeterministicConnector — batch"]
        MEM_ITEMS["items: Vec&lt;InMemoryItem&gt;<br/>(all items in memory)"]
        MEM_SPLIT["choose_split_point_bounds():<br/>common::estimate_split_from_sorted(<br/>  items.iter().map(key, size),<br/>  range.len(), cursor, end<br/>)"]
    end

    subgraph Common ["common.rs — shared path"]
        EST_SORTED["estimate_split_from_sorted():<br/>1. StreamingSplitEstimator::from_sorted_entries(count, iter)<br/>2. estimator.estimate_split_key()<br/>3. is_valid_split_candidate(key, cursor, end)<br/>4. ItemKey::try_from_slice(split_key)"]
    end

    FS_ENUM --> FS_FIELD
    FS_SPLIT --> FS_FIELD
    FS_RESET --> FS_FIELD

    GIT_SPLIT --> EST_SORTED
    MEM_SPLIT --> EST_SORTED
    EST_SORTED -->|"from_sorted_entries<br/>sample_cap = entry_count<br/>(no compaction)"| FS_FIELD

    style FS_FIELD fill:#EF4444,stroke:#991B1B,color:#fff
    style FS_ENUM fill:#FEE2E2,stroke:#991B1B
    style FS_SPLIT fill:#FEE2E2,stroke:#991B1B
    style FS_RESET fill:#FEE2E2,stroke:#991B1B
    style GIT_ENTRIES fill:#FEE2E2,stroke:#991B1B
    style GIT_SPLIT fill:#FEE2E2,stroke:#991B1B
    style MEM_ITEMS fill:#FEE2E2,stroke:#991B1B
    style MEM_SPLIT fill:#FEE2E2,stroke:#991B1B
    style EST_SORTED fill:#FEE2E2,stroke:#991B1B
```

### Streaming vs batch loading

| Connector | Estimator Lifetime | Feed Mechanism | Compaction? |
|---|---|---|---|
| `FilesystemConnector` | Persistent field, reset on walk rebuild | `observe()` called per emitted file during `enumerate_page_core()` | Yes — `sample_cap = DEFAULT_SAMPLE_CAP` (1024) |
| `GitConnector` | Ephemeral, built at split-selection time | `from_sorted_entries()` bulk-loads all in-range entries | No — `sample_cap = entry_count` |
| `InMemoryDeterministicConnector` | Ephemeral, built at split-selection time | `from_sorted_entries()` bulk-loads all in-range items | No — `sample_cap = entry_count` |

The filesystem connector benefits from streaming estimation because its DFS walk
is incremental — the estimator accumulates observations across multiple pagination
calls on the same connector instance. The git and in-memory connectors already
hold all entries in memory, so they set `sample_cap = entry_count` to avoid
compaction and produce exact byte-weighted midpoints.

### Post-selection validation

After the estimator produces a candidate key, every connector applies the same
validation via `common::is_valid_split_candidate()`:

1. The candidate must advance past the cursor's last emitted key (no backward
   splits).
2. The candidate must be strictly less than the shard's upper bound (no empty
   right child).

If validation fails, `choose_split_point()` returns `Ok(None)`, signaling that
no usable split is available. The coordination layer handles this by deferring
the split or continuing to scan the shard as-is.

> **Cross-reference**: diagram 12 (Split Operations) shows how the validated
> `ItemKey` flows into `SplitReplacePlan` / `SplitResidualPlan` and through
> the coordination protocol's fencing and coverage validation.

---

## Source Code References

| Symbol | Location | Role |
|---|---|---|
| `StreamingSplitEstimator` | `crates/gossip-connectors/src/split_estimator.rs` | Core estimator struct |
| `Sample` | `crates/gossip-connectors/src/split_estimator.rs` | Retained checkpoint (rank + byte position + key) |
| `SampleAxis` | `crates/gossip-connectors/src/split_estimator.rs` | Rank vs Bytes axis selector |
| `observe()` | `crates/gossip-connectors/src/split_estimator.rs` | Per-item streaming observation |
| `estimate_split_key()` | `crates/gossip-connectors/src/split_estimator.rs` | Byte-weighted midpoint estimation |
| `compact_samples()` | `crates/gossip-connectors/src/split_estimator.rs` | In-place buffer compaction |
| `selected_sample_indices()` | `crates/gossip-connectors/src/split_estimator.rs` | Nearest-neighbor index selection |
| `redistribute_plateau_picks()` | `crates/gossip-connectors/src/split_estimator.rs` | Post-compaction plateau spreading |
| `nearest_by_rank_in_range()` | `crates/gossip-connectors/src/split_estimator.rs` | Binary search for nearest rank in subslice |
| `interpolated_position()` | `crates/gossip-connectors/src/split_estimator.rs` | u128 linear interpolation |
| `from_sorted_entries()` | `crates/gossip-connectors/src/split_estimator.rs` | Bulk-load constructor |
| `estimate_split_from_sorted()` | `crates/gossip-connectors/src/common.rs` | Shared batch-connector split path |
| `is_valid_split_candidate()` | `crates/gossip-connectors/src/common.rs` | Post-selection cursor/bound guard |
| `FilesystemConnector::choose_split_point()` | `crates/gossip-connectors/src/filesystem.rs` | Shard-based split-point entry point (delegates to `choose_split_point_bounds`) |
| `GitConnector::choose_split_point()` | `crates/gossip-connectors/src/git.rs` | Shard-based split-point entry point (delegates to `choose_split_point_bounds`) |
| `InMemoryDeterministicConnector::choose_split_point()` | `crates/gossip-connectors/src/in_memory.rs` | Shard-based split-point entry point (delegates to `choose_split_point_bounds`) |
| `FilesystemConnector::split_estimator` | `crates/gossip-connectors/src/filesystem.rs` | Persistent estimator field |
| `FilesystemConnector::choose_split_point_bounds()` | `crates/gossip-connectors/src/filesystem.rs` | FS split selection entry point |
| `GitConnector::choose_split_point_bounds()` | `crates/gossip-connectors/src/git.rs` | Git split selection entry point |
| `InMemoryDeterministicConnector::choose_split_point_bounds()` | `crates/gossip-connectors/src/in_memory.rs` | In-memory split selection entry point |

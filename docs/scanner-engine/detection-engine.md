# Detection Engine Flow

Multi-stage pattern matching flow within `Engine::scan_chunk_into()`.

```mermaid
flowchart TB
    subgraph Input["Input"]
        Chunk["Chunk Data<br/>(raw bytes)"]
    end

    subgraph AnchorScan["Anchor Scan"]
        VS["Vectorscan<br/>Prefilter Scan"]
        Raw["Raw Anchors"]
        U16LE["UTF-16LE Anchors"]
        U16BE["UTF-16BE Anchors"]
    end

    subgraph WindowBuild["Window Building"]
        HitAcc["HitAccPool<br/>per (rule, variant)"]
        Merge["merge_ranges_with_gap_sorted()<br/>gap=64"]
        Coalesce["coalesce_under_pressure_sorted()<br/>max_windows=16"]
    end

    subgraph SeedConfirm["Seed Confirmation + Expansion"]
        SeedWin["Seed Window<br/>(seed_radius)"]
        Confirm["confirm_any check<br/>memmem search"]
        Expand["Expand to full_radius"]
    end

    subgraph RegexConfirm["Regex Confirmation"]
        MustContain["must_contain check<br/>(optional)"]
        ConfirmAll["confirm_all check<br/>(optional)"]
        Keywords["keyword gate<br/>(optional, any-of memmem)"]
        CharClass["char_class gate<br/>(optional, SIMD byte classify)"]
        Regex["rule.re.find_iter()"]
        UTF16Dec["UTF-16 Decode<br/>(for UTF-16 variants)"]
    end

    subgraph PostMatch["Post-Match Gates"]
        SecretExtract["Secret span extraction"]
        Entropy["Entropy gate<br/>(Shannon + optional min-entropy,<br/>on extracted secret)"]
        ValueSuppressors["Value suppressor gate<br/>(optional, any-of)"]
        LocalCtx["Local context gate<br/>(optional, fail-open)"]
    end

    subgraph EmitPolicy["Emit-Time Policies"]
        Safelist["Root-context safelist check<br/>(root emit paths only)"]
        SecretSafelist["Secret-bytes safelist check<br/>(all findings)"]
        OfflineVal["Offline validation<br/>(structural checks on root-semantic findings)"]
        Cap["Findings cap check<br/>(max_findings_per_chunk)"]
    end

    subgraph Output["Output"]
        FindingRec["FindingRec<br/>{ file_id, rule_id, span, step_id, confidence_score }"]
    end

    Chunk --> VS
    VS --> Raw
    VS --> U16LE
    VS --> U16BE

    Raw --> HitAcc
    U16LE --> HitAcc
    U16BE --> HitAcc

    HitAcc --> Merge
    Merge --> Coalesce

    Coalesce --> |"if two_phase"| SeedWin
    SeedWin --> Confirm
    Confirm --> |"if confirmed"| Expand
    Expand --> RegexConfirm

    Coalesce --> |"if !two_phase"| RegexConfirm

    RegexConfirm --> MustContain
    MustContain --> ConfirmAll
    ConfirmAll --> Keywords
    Keywords --> CharClass
    CharClass --> Regex
    Regex --> |"Raw variant"| SecretExtract
    Regex --> |"UTF-16 variant"| UTF16Dec
    UTF16Dec --> SecretExtract

    SecretExtract --> Entropy
    Entropy --> KeywordEvidence["keyword_local_hit()<br/>(±32 bytes around match)"]
    KeywordEvidence --> ValueSuppressors
    ValueSuppressors --> LocalCtx
    LocalCtx --> Safelist
    Safelist --> SecretSafelist
    SecretSafelist --> OfflineVal
    OfflineVal --> ConfScore["compute_confidence_score()<br/>(additive 0–10 from per-finding evidence)"]
    ConfScore --> MinConf["min_confidence gate<br/>(per-rule threshold)"]
    MinConf --> FindingRec

    style Input fill:#e3f2fd
    style AnchorScan fill:#fff3e0
    style WindowBuild fill:#e8f5e9
    style SeedConfirm fill:#f3e5f5
    style RegexConfirm fill:#ffebee
    style PostMatch fill:#fff8e1
    style EmitPolicy fill:#ede7f6
    style Output fill:#e8eaf6
```

## Stage Details

### Anchor Scan

The engine uses Vectorscan for multi-pattern prefiltering of anchor strings.
Vectorscan scans the buffer and invokes a callback for each anchor match:

```rust
// Vectorscan callback fires for each anchor match in the buffer.
// The callback maps pattern ids to rule targets and accumulates windows.
fn on_match(pid: usize, start: usize, end: usize, ...) {
    let start_idx = pat_offsets[pid] as usize;
    let end_idx = pat_offsets[pid + 1] as usize;
    let targets = &pat_targets[start_idx..end_idx];  // flat Target list

    for &t in targets {
        let rule_id = t.rule_id();
        let variant = t.variant(); // Raw/Utf16Le/Utf16Be
        let rule = &rules[rule_id];
        let radius = compute_radius(rule, variant);
        let window = SpanU32::new(start - radius, end + radius, start);
        let pair = rule_id * 3 + variant.idx();
        hit_acc_pool.push_span(pair, window, &mut touched_pairs);
    }
}
```

Each anchor is stored in three variants:
- **Raw**: Original bytes (e.g., `ghp_`)
- **UTF-16LE**: Little-endian encoding (e.g., `g\0h\0p\0_\0`)
- **UTF-16BE**: Big-endian encoding (e.g., `\0g\0h\0p\0_`)

### Vectorscan Startup Cache

Engine startup can reuse serialized Vectorscan databases for the raw prefilter
and decoded-stream prefilter paths. Cache lookups are keyed by compile mode,
platform fingerprint, Vectorscan version, and exact pattern inputs.

- `SCANNER_VS_DB_CACHE=0|false|off|no` disables cache use.
- `SCANNER_VS_DB_CACHE_DIR=/path` overrides cache location.
- Cache misses/failures fall back to normal compile (no behavior change).

### Window Building

Windows are accumulated per (rule, variant) pair:

```mermaid
graph LR
    subgraph Before["Before Merge"]
        W1["0..100"]
        W2["50..150"]
        W3["200..300"]
        W4["250..350"]
    end

    subgraph After["After Merge (gap=64)"]
        M1["0..150"]
        M2["200..350"]
    end

    W1 --> M1
    W2 --> M1
    W3 --> M2
    W4 --> M2
```

## Git Chunking Adapter

Git blob scanning feeds decoded bytes through a fixed-size ring buffer and
scans overlapping chunks with the core `Engine`. The overlap length is
`Engine::required_overlap()`; after each chunk scan, the adapter calls
`ScanScratch::drop_prefix_findings(new_bytes_start)` where `new_bytes_start`
is the absolute byte offset of the new (non-overlap) region. This guarantees
chunking invariance without re-materializing full blobs in the scanner.

## Unified Event Integration

Detection semantics are unchanged by unified CLI routing. The same engine
outputs are now emitted as structured events:

- Filesystem path: findings are emitted via `EventOutput` from owner-compute
  scheduler workers (`crates/scanner-scheduler/src/scheduler/local_fs_owner.rs`), where each worker
  performs both file I/O and scanning with worker-local scratch.
- Git path: `EngineAdapter` emits `CoreEvent::Finding` during blob scanning.

## Git Tree Diff Streaming

Git tree diffing now uses a streaming entry parser for spill-backed or large
tree payloads. This keeps tree iteration bounded to a fixed-size buffer while
preserving Git tree order before candidates reach the engine adapter.

## Git Path Policy (ODB-Blob)

ODB-blob mode applies path policy during blob introduction, before any blob
bytes are decoded. A blob is emitted with the first non-excluded path observed
by the introducer. If the blob appears only under non-scannable paths (binary
files, lock/pin files), it is skipped. In serial introduction this attribution
is deterministic; in parallel introduction it is race-winner based and may vary
across worker counts. The blob set remains unchanged, avoiding false negatives
when the same blob content shows up under both excluded and non-excluded paths.

## FindingKey Hashing

For each match, the engine computes a normalized hash on the **secret span**
in the final representation (decoded UTF-8 / transformed bytes):

```
norm_hash = BLAKE3(secret_bytes)
```

The hash is stored in a scratch sidecar aligned with `FindingRec` indices and
is used by Git persistence as part of the deterministic finding key
`(start, end, rule_id, norm_hash)`. No raw secret bytes are stored.

## FS Persistence

Filesystem persistence is handled by `crates/scanner-scheduler/src/store.rs` which
defines the `StoreProducer` trait, `FsFindingRecord`, `FsFindingBatch`, and `FsRunLoss`
types. See [fs-persistence-pipeline.md](../scanner-scheduler/fs-persistence-pipeline.md)
for the full pipeline documentation.

Identity chain derivation (norm_hash -> secret_hash -> finding_id -> occurrence_id)
is implemented in `crates/gossip-scanner-runtime/src/commit_sink.rs` via
`DurableCommitSink`. See [gossip-scanner-runtime.md](../gossip-scanner-runtime.md)
for details.

## SQLite Persistence Backend

Filesystem scans have a concrete persistence backend in
`crates/scanner-scheduler/src/store.rs`:

- `store::db::schema` defines a star-schema with dimension tables (`roots`,
  `paths`, `rules`, `secrets`) and fact tables (`runs`, `occurrences`,
  `observations`). Schema migrations are tracked via `PRAGMA user_version`.
- `store::db::writer` runs per-batch `BEGIN IMMEDIATE … COMMIT` transactions
  within a `Mutex`-guarded SQLite connection. WAL mode enables concurrent
  readers without blocking the single writer.
- Dimension rows (`roots`, `rules`, `paths`, `secrets`) are deduplicated via
  `INSERT OR IGNORE` on their natural keys. An in-memory rule cache avoids
  redundant lookups for frequently seen rules.
- Run status (`Complete`, `CompleteWithCoverageLimits`, `Incomplete`) is
  derived from `RunCounters` at `end_run()` time.
- Store root is currently `<scan_root>/.scanner-store/` when
  `--persist-findings` is enabled.

For the full schema documentation, query APIs, and configuration,
see [fs-persistence-pipeline.md](../scanner-scheduler/fs-persistence-pipeline.md).

**Pressure Coalescing**: If windows exceed `max_windows_per_rule_variant` (16), the gap doubles until windows fit, or everything merges into one.

### Emit-Time Policies

Finding policies are enforced when each finding is about to be recorded:

- Evaluate the global safelist for root emit paths using
  `root_hint_start..root_hint_end` rebased to the active context slice.
- Suppressed findings increment `safelist_suppressed` and are not inserted.
- Non-root findings bypass context-window safelist suppression but are still
  checked by the secret-bytes safelist tier (suppressed findings increment
  `secret_bytes_safelist_suppressed`).
- `max_findings_per_chunk` is enforced in `push_finding_with_drop_hint`; excess
  findings increment `dropped_findings`.

### Inline Offline Validation

Offline structural validation (CRC-32, check-digit, charset, etc.) runs inline
at each finding emission site in `window_validate.rs`, **before** the finding
occupies a `max_findings_per_chunk` cap slot or triggers dedup computation.
For each root-semantic finding whose rule has an `OfflineValidationSpec` gate,
the extracted secret bytes are validated via
`compute_offline_verdict`. Root-semantic detection uses the
**parent** `step_id` (`STEP_ROOT`), so root-level UTF-16 findings are correctly
identified even though their own `step_id` is a `Utf16Window` decode step.

`Valid` and `Indeterminate` verdicts keep the finding; `Invalid` (with the
spec's `suppresses_on_invalid` flag set) suppresses it. Non-root
(transform-derived) findings are always kept. Suppressed findings increment
`ScanScratch.offline_suppressed`.

### Seed Confirmation + Expansion

For noisy rules (like private keys), two-phase confirmation reduces false positives:

```mermaid
sequenceDiagram
    participant Anchor as Anchor Hit
    participant Seed as Seed Window (256 bytes)
    participant Full as Full Window (16KB)
    participant Regex as Regex Validation

    Anchor->>Seed: Extract seed_radius window
    Seed->>Seed: memmem search for confirm_any
    alt Confirmed
        Seed->>Full: Expand to full_radius
        Full->>Regex: Run regex on expanded window
    else Not Confirmed
        Seed--xRegex: Skip this window
    end
```

Example: Private key detection
- `seed_radius`: 256 bytes (fast check)
- `confirm_any`: ["PRIVATE KEY"]
- `full_radius`: 16KB (for full PEM block)

### Regex Confirmation

For raw variants:
```rust
for rm in rule.re.find_iter(window) {
    scratch.out.push(FindingRec { ... });
}
```

For UTF-16 variants:
```rust
// Decode UTF-16 window to UTF-8
let decoded = decode_utf16le_to_buf(&buf[window], max_out)?;

// Create decode step for provenance
let utf16_step_id = scratch.step_arena.push(
    step_id,
    DecodeStep::Utf16Window { endianness, parent_span: window }
);

// Run regex on decoded bytes
for rm in rule.re.find_iter(&decoded) {
    scratch.out.push(FindingRec { step_id: utf16_step_id, ... });
}
```

## Transform Gating (URL/Base64)

After raw/UTF-16 scanning, the engine may generate derived buffers by decoding
URL-percent or Base64 spans. These transforms are expensive, so they are gated:

- **Decoded-space gate**: stream-decode and check for any anchor in the decoded
  bytes using the decoded gate stream (`vs_gate`) when available. If no anchor
  is found, the transform is skipped.
- **Gate fallback semantics**: if decoded-gate DB setup/scan fails, the engine
  falls back to raw prefilter evidence and may relax gate enforcement when
  UTF-16 anchors are enabled to avoid false negatives.
- **Base64 pre-gate (encoded-space)**: Base64 uses an additional, cheaper prefilter
  that runs on the encoded bytes. It uses YARA-style base64 permutations of the
  anchors to cheaply reject spans that cannot possibly decode to an anchor. The
  decoded-space gate still runs afterward to preserve correctness.

Selection detail:
- UTF-16 decoded-stream anchor scanning for candidate windows is activated
  lazily on the first NUL byte; if the UTF-16 stream DB is unavailable, the
  engine falls back to a post-stream UTF-16 block scan.

See `docs/scanner-engine/transform-chain.md` for diagrams and the gating sequence.

## Keyword + Local Context + Entropy + Value Suppressor Gates

Some rules benefit from additional semantic filters beyond anchors + regex:

- **Keyword gate (any-of)**: at least one keyword must appear inside the same
  validation window as the regex. This is a cheap memmem filter that reduces
  false positives without requiring global context.
- **Entropy gate**: after regex matching and secret extraction, compute Shannon
  entropy and optional min-entropy (NIST SP 800-90B) of the extracted secret
  bytes. Shannon catches overall low-randomness; min-entropy catches skewed
  distributions where one byte dominates even though Shannon looks moderate.
  Both metrics are computed in a single fused 256-bin histogram pass. Low-entropy
  matches are rejected as likely false positives.
- **Value suppressor gate (any-of)**: after regex matching, entropy gating,
  and secret extraction, check if the extracted secret bytes contain any
  configured suppressor pattern. If any pattern matches, the finding is
  discarded. Useful for suppressing known placeholder or example values
  (e.g., `EXAMPLE`, `DUMMY_TOKEN`) that regex and entropy cannot distinguish
  from real secrets. Patterns are case-sensitive and matched via memmem on
  raw secret bytes.
- **Local context gate (rule-selective)**: after regex matching and secret
  extraction, inspect a bounded same-line lookaround slice for micro-context
  such as assignment separators, required key names, and/or matching quotes.
  This gate is fail-open when line boundaries are missing in the window to
  avoid false negatives at chunk edges.
- **Character-class gate (pre-regex)**: before regex matching, SIMD-accelerated
  byte classification counts lowercase/uppercase/digit/special bytes in the
  validation window. If the lowercase proportion exceeds `max_lower_pct`, the
  window is rejected as likely prose or variable names. This gate is auto-enabled
  for entropy-gated rules with `min_bits_per_byte >= 3.0` (defaults:
  `max_lower_pct: 95`, `min_window_len: 32`). Runs on the full window (not
  extracted secret) and fails open on windows shorter than `min_window_len`.

These gates are designed to be **local and bounded**:
- Keywords are checked *before* regex, and for UTF-16 windows the check happens
  **before decoding** to avoid wasting decode budget.
- Entropy (Shannon + min-entropy) runs only on the extracted secret bytes and is
  capped by `max_len` to keep cost predictable.
- Value suppressors run only on confirmed matches after secret extraction, so
  they add minimal cost per finding but do not reduce regex work.
- Local context uses bounded lookaround windows and operates on decoded UTF-8
  bytes for UTF-16 variants, preserving fail-open semantics at boundaries.
- Char-class runs before regex on the full window using 16-byte SIMD throughput;
  cost is O(window_len) and fully amortized when it rejects the window.

## Tuning Parameters

| Parameter                            | Default | Purpose                                                    |
|--------------------------------------|---------|------------------------------------------------------------|
| `merge_gap`                          | 64      | Merge adjacent windows within this byte gap                |
| `max_windows_per_rule_variant`       | 16      | Max windows per (rule, variant) before pressure coalescing |
| `pressure_gap_start`                 | 128     | Starting gap for pressure coalescing                       |
| `max_anchor_hits_per_rule_variant`   | 2048    | Cap on anchor hits before collapsing                       |
| `max_utf16_decoded_bytes_per_window` | 64 KiB  | UTF-16 decode output limit per window                      |
| `max_transform_depth`                | 3       | Max nested decode steps (root + transforms)                |
| `max_total_decode_output_bytes`      | 512 KiB | Global decoded output budget per scan                      |
| `max_work_items`                     | 256     | Cap on queued decode work items per scan                   |
| `max_findings_per_chunk`             | 8192    | Final cap on findings per chunk after suppression          |
| `scan_utf16_variants`                | true    | Enable UTF-16 anchor variants                              |

Derived (non-config) limits used by streaming decode:
- `pending_window_horizon_bytes = (max_window_diameter_bytes / 2) + STREAM_DECODE_CHUNK_BYTES`
- `pending_window_cap = max(16, rules × 3 × max_windows_per_rule_variant)`

## Stream Decode Window Scheduling

During streaming decode (URL/Base64 transforms), the engine uses a **TimingWheel** to
schedule window validation without materializing the full decoded buffer. This enables
efficient incremental scanning where windows are processed exactly when they become
complete.

```mermaid
flowchart TB
    subgraph StreamDecode["Stream Decode Loop"]
        Chunk["Decode chunk"]
        Scan["Vectorscan stream scan"]
        Match["Anchor match at offset"]
        Window["Window (lo, hi)"]
    end

    subgraph TimingWheel["TimingWheel<PendingWindow, 1>"]
        Push["push(hi, window)"]
        Scheduled["Scheduled into bucket"]
        Ready["Ready (already due)"]
    end

    subgraph Advance["advance_and_drain(decoded_offset)"]
        Drain["Drain buckets <= offset"]
        Process["process_window()"]
        Validate["Regex validation"]
    end

    Chunk --> Scan
    Scan --> Match
    Match --> Window
    Window --> Push

    Push --> |"hi >= cursor"| Scheduled
    Push --> |"hi < cursor"| Ready

    Ready --> Process
    Scheduled --> Drain
    Drain --> Process
    Process --> Validate

    style StreamDecode fill:#e3f2fd
    style TimingWheel fill:#fff3e0
    style Advance fill:#e8f5e9
```

### How It Works

1. **Window Discovery**: During streaming decode, Vectorscan reports anchor matches
   at decoded-space offsets. Each match generates a window `[lo, hi)` where `hi`
   is the exclusive right edge (when the window becomes complete).

2. **Scheduling**: Windows are pushed to the timing wheel keyed by `hi`:
   ```rust
   match scratch.pending_windows.push(hi, pending_window) {
       Ok(PushOutcome::Scheduled) => { /* queued for later */ }
       Ok(PushOutcome::Ready(w))  => process_window(w, ...),
       Err(_) => { /* pool exhausted, fallback to full decode */ }
   }
   ```

3. **Draining**: As more bytes are decoded, `advance_and_drain(decoded_offset)`
   fires all windows whose `hi <= decoded_offset`:
   ```rust
   scratch.pending_windows.advance_and_drain(decoded_offset, |win| {
       process_window(win, ...);
   });
   ```

4. **Final Flush**: At end-of-stream, `advance_and_drain(u64::MAX)` drains all
   remaining windows.

### TimingWheel Design

The timing wheel uses **exact scheduling** with `G=1` (granularity = 1 byte):

```
┌─────────────────────────────────────────────────────────────────┐
│  TimingWheel<PendingWindow, 1>                                  │
├─────────────────────────────────────────────────────────────────┤
│  wheel_size: power of 2 >= horizon / G                          │
│  cursor_abs: next bucket to process                             │
│  occ: Bitset2 (two-level bitmap for fast next-slot lookup)      │
├─────────────────────────────────────────────────────────────────┤
│  Node Pool (fixed capacity):                                    │
│  ┌─────┬─────┬─────┬─────┐                                      │
│  │ win │ win │free │free │ ...                                  │
│  └──┬──┴──┬──┴─────┴─────┘                                      │
│     │     │                                                     │
│     └──┬──┘                                                     │
│        v                                                        │
│  Slot FIFO lists (intrusive linked list per bucket)             │
└─────────────────────────────────────────────────────────────────┘
```

**Key properties**:

- **Never fires early**: Windows are guaranteed to not fire before `hi`
- **FIFO within bucket**: Windows at the same offset drain in insertion order
- **Fixed allocation**: Node pool is pre-sized; pool exhaustion triggers fallback
- **O(1) push**: Hash-based slot lookup with FIFO append
- **O(buckets + items) drain**: Bitmap skips empty buckets efficiently

### Fallback on Pool Exhaustion

If the timing wheel's node pool is exhausted or horizon is exceeded, the stream
decode falls back to full buffer materialization:

```rust
Err(PushError::PoolExhausted) | Err(PushError::TooFarInFuture { .. }) => {
    scratch.pending_windows.reset();
    // Fall back to non-streaming full decode path
}
```

This ensures correctness is preserved even under adversarial input that
generates many overlapping windows.

## Finding Output

```rust
FindingRec {
    file_id: FileId(0),
    rule_id: 1,              // Index into Engine.rules_hot / Engine.rules_cold
    span_start: 100,
    span_end: 140,
    root_hint_start: 100,    // Offset in original file
    root_hint_end: 140,
    dedupe_with_span: true,  // Whether span participates in dedupe key
    step_id: StepId(0),      // Decode provenance chain
    confidence_score: 7,     // Additive 0–10 score from per-finding evidence
}
```

## Related Documentation

| Document                                     | Description                                          |
|----------------------------------------------|------------------------------------------------------|
| [Transform Chain](./transform-chain.md)      | URL/Base64 transform gating and decode flow          |
| [Memory Management](../memory-management.md) | Buffer pools, scratch allocation, and memory budgets |

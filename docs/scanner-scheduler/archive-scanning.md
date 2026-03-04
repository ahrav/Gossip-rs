# Archive Scanning Subsystem

The archive scanning subsystem provides streaming archive parsing with deterministic budget enforcement for zip-bomb protection. It handles tar, gzip, bzip2, and zip formats, enforces nesting depth limits, controls decompressed output budgets at entry/archive/root scopes, and constructs virtual paths for files inside archives.

## Module Purpose

`crates/scanner-scheduler/src/archive/` defines the archive scanning contract: configuration, format detection, budget tracking, virtual path construction, outcome taxonomy, and the streaming scan loop. Format-specific handlers live in `archive/formats/` (low-level parsers) and `scheduler/local_fs_*.rs` (blocking-path integration). The io_uring path delegates to `archive/scan.rs` via the `ArchiveEntrySink` trait.

The architecture emphasizes:
- **Streaming only**: archives are parsed sequentially without materializing to disk
- **Deterministic budgets**: every resource cap is enforced without non-determinism (wall-clock deadlines are opt-in)
- **Zero allocation after startup**: all buffers are preallocated and reused via `reset()` / `clear()`
- **Sink-driven decoupling**: the scan core delivers structured events via `ArchiveEntrySink`, allowing different consumers (pipeline, io_uring workers, simulation harness)

## Supported Formats

| Format | Kind | Extension(s) | Access Pattern | Entry Model |
|--------|------|-------------|----------------|-------------|
| gzip | `Gzip` | `.gz` | Sequential `Read` | Single decompressed blob |
| bzip2 | `Bzip2` | `.bz2` | Sequential `Read` | Single decompressed blob |
| tar | `Tar` | `.tar` | Sequential 512-byte blocks | Multiple named entries |
| tar+gzip | `TarGz` | `.tar.gz`, `.tgz` | Sequential gzip → tar | Multiple named entries |
| tar+bzip2 | `TarBz2` | `.tar.bz2`, `.tbz2` | Sequential bzip2 → tar | Multiple named entries |
| zip | `Zip` | `.zip` | Random access via EOCD | Multiple named entries |

### Format Detection

Detection uses a two-phase algorithm (`archive/detect.rs:151`):

1. **Extension-based** (`detect_kind_from_path` / `detect_kind_from_name_bytes`): pure byte-suffix match using case-insensitive ASCII comparison (`| 0x20`). Single-byte dispatch on the last character gives O(1) common-case rejection. Extension detection always takes precedence — this is the only way to distinguish `.tar.gz` from plain `.gz`.

2. **Magic-byte sniffing** (`sniff_kind_from_header`): probes the first bytes when the extension is unrecognized. Probe order: gzip (`1f 8b`) → zip (`PK..`) → bzip2 (`BZh` + digit `1`–`9`) → tar (`ustar` at offset 257 in a 512-byte header). First match wins.

The combined function `detect_kind` tries extension first, then falls back to magic bytes.

### Magic Byte Signatures

| Format | Minimum bytes | Signature |
|--------|--------------|-----------|
| gzip | 2 | `0x1f 0x8b` |
| zip | 4 | `PK` + `(03,04)`, `(01,02)`, `(05,06)`, or `(07,08)` |
| bzip2 | 4 | `BZh` + ASCII digit `'1'`–`'9'` |
| tar (ustar) | 512 | `"ustar"` at offset 257 |

## Architecture

### Integration with the Local FS Scanner

Archive scanning integrates at two levels:

**Blocking path** (`scheduler/local_fs_owner.rs`): the worker thread handles archives inline via `dispatch_archive_scan()` (`scheduler/local_fs_archive_ctx.rs:125`), which routes to format-specific handlers (`local_fs_gzip.rs`, `local_fs_bzip2.rs`, `local_fs_tar.rs`, `local_fs_zip.rs`). Blocking workers process one file at a time, so decompression blocking is acceptable.

**io_uring path** (`scheduler/local_fs_uring.rs`): archives are offloaded to dedicated archive worker threads to avoid stalling the io_uring completion loop. Detection happens at two points:
- Discovery time: files with known archive extensions are routed directly to the archive channel
- First-chunk classification: I/O threads sniff magic bytes after the first read completes

Both paths use the same archive subsystem types (`ArchiveConfig`, `ArchiveBudgets`, `ArchiveScratch`) and produce the same outcomes (`ArchiveEnd`).

### Sink-Driven Entry Interface

The archive scan core (`archive/scan.rs`) drives an `ArchiveEntrySink` trait (`scan.rs:206`) that decouples parsing from downstream processing:

```
on_entry_start(&meta)        // exactly once per entry
  on_entry_chunk(chunk)      // zero or more payload windows
  on_entry_chunk(chunk)
  ...
on_entry_end()               // exactly once, even on truncation
```

The `start`/`end` pair is always balanced. The io_uring path implements `ArchiveEntrySink` via `UringArchiveSink`, which calls `scan_chunk_into → drop_prefix_findings → dedupe → emit`. The blocking path uses `ArchiveScanCtx::scan_and_emit_chunk` (`local_fs_archive_ctx.rs:324`).

## Budget Enforcement

Budget tracking (`archive/budget.rs`) prevents resource exhaustion from zip bombs, deeply nested archives, and adversarial metadata. All accounting is deterministic and reproducible.

### Budget Hierarchy

Three nested scopes, each with independent caps:

```
Root (per-source-file)
 └─ Archive (per-container: zip, tar, tar.gz, …)
     └─ Entry (per-file inside the container)
```

When charging decompressed output, the tightest remaining allowance across all three scopes wins. The binding constraint determines the `BudgetHit` variant, which tells callers whether to skip the entry, mark the archive partial, or stop the entire root.

### Budget Caps

| Cap | Config Field | Default | Scope |
|-----|-------------|---------|-------|
| Nesting depth | `max_archive_depth` | 3 | Per root |
| Entry count | `max_entries_per_archive` | 4096 | Per archive |
| Entry output bytes | `max_uncompressed_bytes_per_entry` | 64 MiB | Per entry |
| Archive output bytes | `max_total_uncompressed_bytes_per_archive` | 256 MiB | Per archive |
| Root output bytes | `max_total_uncompressed_bytes_per_root` | 512 MiB | Per root |
| Metadata bytes | `max_archive_metadata_bytes` | 16 MiB | Per archive |
| Inflation ratio | `max_inflation_ratio` | 128x | Per entry + per archive |
| Wall-clock deadline | `max_wall_clock_secs_per_root` | `None` (opt-in) | Per root |

The nesting invariant `entry <= archive <= root` is enforced by `ArchiveConfig::validate()` (`config.rs:364`).

### Inflation Ratio Enforcement

Ratio tracking runs at both archive and entry scopes to prevent a credit-accumulation attack. Per-entry ratio is tracked independently: `entry_out <= entry_in * R`. This prevents a pattern where many small well-compressed entries build up archive-level headroom that a single malicious entry later exploits (`budget.rs:28–30`).

When compressed input is zero (unknown), the ratio check is skipped to avoid false positives. The `remaining_decompressed_allowance_with_ratio_probe(true)` method applies a conservative 1-byte compressed-input assumption to cap the first read.

### Budget Lifecycle Protocol

```
reset()                        // arm deadline, zero root counters
  enter_archive()              // push frame, enforce depth cap
    note_entry() / begin_entry() // count + open entry scope
      charge_compressed_in(n)   // raw bytes consumed
      charge_decompressed_out(n) // payload bytes delivered
      charge_discarded_out(n)    // payload bytes read but dropped
    end_entry(scanned)          // close entry scope
  exit_archive()               // pop frame
```

`enter_archive`/`exit_archive` and `begin_entry`/`end_entry` must be balanced. The frame stack is preallocated to `max_archive_depth` and never grows — no `Vec` push/pop on hot paths.

### Budget Hit Classification

`BudgetHit` variants are ordered by increasing blast radius (`budget.rs:89`):

| Variant | Scope | Effect |
|---------|-------|--------|
| `SkipEntry` | Current entry only | Archive continues with next entry |
| `SkipArchive` | Entire archive | Discarded (no scan progress yet) |
| `PartialArchive` | Entire archive | Stops; bytes already scanned are kept |
| `StopRoot` | All archives under this root | Everything stops |

`ChargeResult::Clamp { allowed, hit }` tells the caller the exact number of bytes it may still process before the limit takes effect.

### Wall-Clock Deadline

The wall-clock deadline is opt-in (`max_wall_clock_secs_per_root`). When configured:
- `reset()` arms an `Instant`-based deadline (the only place `Instant::now()` is called)
- `is_deadline_expired()` is polled at natural loop boundaries
- The deadline does not affect byte or count accounting
- Maximum allowed value is 86,400 seconds (24 hours), enforced by `MAX_WALL_CLOCK_SECS_PER_ROOT`

In test/sim-harness builds, a deterministic countdown (`set_deadline_check_countdown`) replaces the real clock.

## Key Types

### Configuration

**`ArchiveConfig`** (`config.rs:108`) — shared archive scanning configuration. All limits are hard bounds. Archives are treated as hostile input.

| Field | Type | Purpose |
|-------|------|---------|
| `enabled` | `bool` | Master enable switch |
| `max_archive_depth` | `u8` | Max nested archive depth |
| `max_entries_per_archive` | `u32` | Max entries per container |
| `max_uncompressed_bytes_per_entry` | `u64` | Per-entry decompressed byte cap |
| `max_total_uncompressed_bytes_per_archive` | `u64` | Per-archive decompressed byte cap |
| `max_total_uncompressed_bytes_per_root` | `u64` | Root-level cross-archive byte cap |
| `max_archive_metadata_bytes` | `u64` | Metadata parsing cap (headers, CD) |
| `max_inflation_ratio` | `u32` | Decompressed/compressed ratio cap |
| `max_virtual_path_len_per_entry` | `usize` | Max display path bytes per entry |
| `max_virtual_path_bytes_per_archive` | `usize` | Total path bytes per archive |
| `max_wall_clock_secs_per_root` | `Option<u64>` | Optional CPU-exhaustion deadline |
| `encrypted_policy` | `EncryptedPolicy` | How to handle encrypted content |
| `unsupported_policy` | `UnsupportedPolicy` | How to handle unsupported formats |

**`EncryptedPolicy`** / **`UnsupportedPolicy`** (`config.rs:70`, `config.rs:87`) — escalation ladders from `SkipWithTelemetry` → `FailArchive` → `FailRun`.

### Budget Tracking

**`ArchiveBudgets`** (`budget.rs:140`) — deterministic budget tracker. Holds immutable caps from config and mutable counters. A fixed-size frame stack tracks per-archive state without allocation.

**`ArchiveFrame`** (`budget.rs:204`) — per-archive accounting frame (48 bytes, `#[repr(C)]`). Tracks `entries_seen`, `entries_scanned`, `metadata_bytes`, `compressed_in`, `decompressed_out`, `entry_compressed_in`, and `entry_decompressed_out`. Entry-open state uses a `u64::MAX` sentinel instead of a separate bool to avoid 7 bytes of padding.

**`BudgetHit`** (`budget.rs:90`) — classification of which budget was the binding constraint.

**`ChargeResult`** (`budget.rs:107`) — result of charging a byte quantity: `Ok` (full amount fits) or `Clamp { allowed, hit }` (partial).

### Format Detection

**`ArchiveKind`** (`detect.rs:53`) — `#[repr(u8)]` enum: `Gzip(0)`, `Tar(1)`, `Zip(2)`, `TarGz(3)`, `Bzip2(4)`, `TarBz2(5)`. The `is_container()` method distinguishes multi-entry formats from single-stream formats.

### Scan Core

**`ArchiveEntrySink`** (`scan.rs:206`) — trait decoupling archive parsing from downstream. Methods: `on_entry_start`, `on_entry_chunk`, `on_entry_end`.

**`EntryMeta`** (`scan.rs:143`) — metadata for a single entry: `display_path`, `size_hint`, `flags`.

**`EntryChunk`** (`scan.rs:169`) — one iteration of the sliding-window read loop: `data` (overlap prefix + new bytes), `base_offset`, `new_bytes_start`, `new_bytes_len`.

**`ArchiveScratch<Z>`** (`scan.rs:234`) — reusable scratch state. Contains `EntryPathCanonicalizer`, per-depth `VirtualPathBuilder`s, `ArchiveBudgets`, per-depth `TarCursor`s, `ZipCursor`, gzip header/name buffers, and the `stream_buf`. Preallocated to `max_archive_depth + 2` depth slots.

**`ArchiveScanCtx`** (`scan.rs:356`, crate-private) — borrow-split view that decomposes `ArchiveScratch` into independent mutable borrows for recursive nesting via `split_first_mut`. Not part of the public API.

**`ArchiveEnd`** (`scan.rs:133`) — terminal outcome: `Scanned`, `Skipped(ArchiveSkipReason)`, `Partial(PartialReason)`.

### Outcome Taxonomy

**`ArchiveSkipReason`** (`outcome.rs:58`) — 14 variants for why an entire archive was skipped before any payload bytes were scanned. `#[repr(u8)]` with stable discriminants used as array indices.

**`EntrySkipReason`** (`outcome.rs:132`) — 10 variants for why a specific entry was skipped. Entry skips do not abort the archive.

**`PartialReason`** (`outcome.rs:218`) — 12 variants for why an archive was only partially scanned. Partial outcomes retain results for bytes already processed.

**`ArchiveStats`** (`outcome.rs:498`) — per-worker aggregate with scalar counters, per-reason breakdown arrays, and a bounded sample ring (`ArchiveSampleRing`). All `record_*` methods are gated behind `cfg!(all(feature = "perf-stats", debug_assertions))` for zero production overhead.

### Virtual Paths

**`EntryPathCanonicalizer`** (`path.rs:104`) — sanitizes raw archive entry names into bounded, printable-ASCII display bytes. Resolves `.`/`..`, escapes non-printable bytes as `%HH`, enforces length and component caps.

**`VirtualPathBuilder`** (`path.rs:313`) — joins parent and entry display paths with `::` separator. Truncation appends `~#<16-hex-digit>` FNV-1a hash suffix.

**`CanonicalPath`** (`path.rs:63`) — result of canonicalization: `bytes`, `had_traversal`, `truncated`, `component_cap_exceeded`, `hash64`.

**`VirtualPath`** (`path.rs:82`) — result of virtual path construction: `bytes`, `truncated`, `hash64`.

### Format-Specific Types

**`GzipStream<R>`** (`formats/gzip.rs:101`) — streaming gzip decoder wrapping `flate2::MultiGzDecoder<CountedRead<R>>`. Handles concatenated members. Reports compressed-byte deltas via `take_compressed_delta()`.

**`Bzip2Stream<R>`** (`formats/bzip2.rs:35`) — streaming bzip2 decoder wrapping `bzip2::MultiBzDecoder<CountedRead<R>>`. Same delta-reporting interface as `GzipStream`.

**`CompressedStream`** trait (`formats/mod.rs:23`) — abstracts `GzipStream` and `Bzip2Stream` for generic scanning functions.

**`TarCursor`** (`formats/tar.rs:188`) — stateful tar header parser. Walks 512-byte header blocks, handles GNU longname (`L`) and PAX extended-header (`x`/`g`) records internally, yields `TarEntryMeta`. Zero allocation after startup.

**`TarRead`** trait (`formats/tar.rs:99`) — `Read` + optional `take_compressed_delta()` for compressed-byte accounting.

**`ZipCursor<R>`** (`formats/zip.rs:173`) — streaming cursor over a zip central directory. Parses EOCD, iterates CDFH entries, validates bounds. Supports Zip32 only; Zip64 sentinel values trigger `UnsupportedFeature`.

**`ZipSource`** trait (`formats/zip.rs:39`) — `Read + Seek` source with `len()` and `try_clone()`. Implemented for `File`, `Cursor<Arc<[u8]>>`, `Cursor<Vec<u8>>`.

**`ZipEntryReader`** (`formats/zip.rs:713`) — decompressed entry reader: `Stored(CountedRead<LimitedRead>)` or `Deflate(DeflateDecoder<CountedRead<LimitedRead>>)`.

**`LimitedRead`** (`formats/zip.rs:739`) — bounds reads to a fixed byte count (compressed entry size).

**`CountedRead`** (`util.rs:28`) — `Read` wrapper that counts bytes consumed, driving inflation-ratio enforcement.

## Data Flow

### How an Archive File Is Discovered, Opened, Iterated, and Scanned

```
1. Discovery
   ├─ Extension match (detect_kind_from_path)
   │  └─ Route directly to archive workers (bypass I/O threads)
   └─ First-chunk magic sniff (sniff_kind_from_header)
      └─ I/O thread routes to archive channel

2. Archive Open
   ├─ reset() → arm deadline, zero root counters
   ├─ enter_archive() → push frame, enforce depth cap
   └─ Format-specific init:
      ├─ gzip: GzipStream::new_with_header (parse FNAME)
      ├─ bzip2: Bzip2Stream::new
      ├─ tar: TarCursor::reset
      ├─ tar.gz: GzipStream wrapping → tar iteration
      ├─ tar.bz2: Bzip2Stream wrapping → tar iteration
      └─ zip: ZipCursor::open (EOCD → central directory)

3. Entry Iteration
   For each entry:
   ├─ Canonicalize name (EntryPathCanonicalizer)
   ├─ Build virtual path with locator suffix (@t/@z/@c)
   ├─ Check path budget
   ├─ Skip non-regular entries (dirs, symlinks)
   ├─ Check for nested archive (detect_kind_from_name_bytes)
   │  ├─ If nestable and depth allows → recurse
   │  └─ If zip-in-tar → unsupported (no random access)
   ├─ begin_entry() → open entry budget scope
   └─ Sliding-window read loop:
      ├─ Check deadline
      ├─ Copy overlap carry to buffer front
      ├─ Probe remaining budget allowance
      ├─ Read up to min(chunk_size, allowance, buf capacity)
      ├─ charge_compressed_in() + charge_decompressed_out()
      ├─ Deliver EntryChunk to sink (or scan_and_emit_chunk)
      └─ Update offset/carry; break if budget clamped

4. Entry Close
   ├─ on_entry_end() / end_entry(scanned)
   ├─ Drain unconsumed payload (tar alignment)
   └─ Record entry stats (scanned/skipped/partial)

5. Archive Close
   ├─ exit_archive() → pop frame
   └─ Return ArchiveEnd (Scanned/Skipped/Partial)
```

### Sliding-Window Read Loop

Every entry payload uses the same read pattern:

```
stream_buf layout on each iteration:

  |<-- carry (overlap) -->|<--- new read (up to chunk_size) --->|
  ^                       ^
  buf[0]                  buf[carry]

carry = overlap.min(bytes_emitted_so_far)
```

Before each read, the last `carry` bytes of the previous chunk are copied to the buffer front so downstream pattern matchers see a sliding window with `overlap` bytes of look-behind context. Budget checks happen after the read returns: bytes beyond the budget are truncated and the loop exits.

The upper bound on a single read is `ARCHIVE_STREAM_READ_MAX` (256 KiB), keeping per-iteration work bounded even with large `chunk_size`.

## Format-Specific Details

### Gzip (`scan_gzip_stream` / `process_gzip_file`)

- Uses `flate2::read::MultiGzDecoder` to handle concatenated gzip members as one stream
- Parses the optional gzip FNAME header field for the virtual entry name; falls back to `<gunzip>` when absent
- Header parsing uses a bounded peek buffer (`PeekRead`) that is moved into the decoder and recovered afterward for reuse
- Compressed-byte deltas tracked via `CountedRead` wrapping the raw reader
- Inflation-ratio pre-clamping is always active (`ratio_active = true`)

### Bzip2 (`scan_bzip2_stream` / `process_bzip2_file`)

- Uses `bzip2::read::MultiBzDecoder` to handle concatenated bzip2 members
- Virtual entry name is always `<bunzip2>` (bzip2 has no standard filename field)
- Same `CountedRead` delta reporting as gzip
- **CPU exhaustion note**: bzip2 block decompression can buffer up to 900 KiB internally per `read()` call. The deadline check fires between read iterations, not during a single decompression call, so a single block decode can run uninterrupted. Production deployments should set `max_wall_clock_secs_per_root`.

### Tar (`scan_tar_stream` / `process_tar_file`)

- Sequential 512-byte block parsing via `TarCursor`
- Handles GNU longname (`L`) and PAX extended-header (`x`/`g`) records internally
- PAX `path=` override applies per-file only (global PAX `path` is parsed but not applied to avoid misattribution)
- Name resolution priority: PAX `path` > GNU longname > header `name` (with ustar `prefix/name` joining)
- End-of-archive: two consecutive zero blocks or clean EOF at header boundary
- Size fields parsed as NUL/space-padded ASCII octal; overflow (>21 digits) is rejected
- Entries with tar typeflag `0` (NUL) or `'0'` (ASCII 0x30) are treated as regular files; everything else is skipped
- `is_zero_block` uses word-wide (`u64`) unaligned reads with early exit for fast detection
- After each entry's payload, any unconsumed bytes are drained and tar padding is consumed to maintain 512-byte alignment

### Tar+Gzip (`scan_targz_stream` / `process_targz_file`)

- Wraps the reader in `GzipStream` and delegates to `scan_tar_stream` with `ratio_active = true`
- Inflation-ratio enforcement applies to the decompressed tar payload

### Tar+Bzip2 (`scan_tarbz2_stream` / `process_tarbz2_file`)

- Wraps the reader in `Bzip2Stream` and delegates to `scan_tar_stream` with `ratio_active = true`
- Same inflation-ratio enforcement as tar+gzip

### Zip (`scan_zip_source` / `process_zip_file`)

- Requires random access (`Read + Seek`) via the `ZipSource` trait
- Locates the end-of-central-directory (EOCD) record by scanning backward from the file end (up to 66 KiB window)
- Validates: single-disk only, no Zip64 sentinel values (`0xFFFF`/`0xFFFFFFFF`)
- Iterates central directory file headers (CDFH) sequentially
- For each entry: reads the local file header (LFH) to locate the payload start
- Supported compression methods: stored (method 0) and deflate (method 8)
- Encrypted entries (flag bit 0) are handled per `EncryptedPolicy`
- Compressed-byte deltas tracked manually (cumulative compressed bytes diffed between reads) because the zip reader does not expose per-read deltas like `TarRead`
- Ratio pre-clamping active only for deflate entries; stored entries have 1:1 ratio
- No recursive nesting: zip entries inside tar cannot be descended (no random access), handled per `UnsupportedPolicy`
- Filename storage is bounded; oversized names are truncated with a streaming FNV-1a hash for the suffix

### Nested Archive Handling

Tar entries whose names match a known archive extension are recursively descended up to `max_archive_depth`. The recursion uses `split_first_mut` to peel per-depth scratch slices (vpaths, path_budget_used, tar_cursors) without allocation. Each nesting level gets its own independent state while sharing the budget tracker and stream buffer.

Supported nesting paths:
- tar → gzip, bzip2, tar, tar.gz, tar.bz2 (sequential streams)
- tar → zip: **not supported** (zip requires random access; handled by `UnsupportedPolicy`)

## Virtual Paths

Virtual paths are display-only identifiers for files inside archives. They are **not** filesystem paths and are never used to open files.

### Construction

The full virtual path is assembled as: `<parent_display>::<canonicalized_entry_name><locator_suffix>`

Example: `/tmp/outer.tar::inner.zip::dir/file.txt@t000000000000002a`

The `::` separator is chosen to be visually distinct from filesystem separators.

### Canonicalization (`EntryPathCanonicalizer`)

1. Normalize separators (`\` → `/`) and split into components
2. Drop `.`; resolve `..` via a stack, clamping at root (traversal sets `had_traversal` flag)
3. Emit escaped display bytes: non-printable bytes → `%HH` (uppercase hex)
4. Stream FNV-1a hash over full (unbounded) output while storing only up to `max_len` bytes
5. If truncated, replace tail with `~#<16-hex-digit>` hash suffix (avoids splitting `%HH` escapes at the boundary)
6. Component count capped at `DEFAULT_MAX_COMPONENTS` (256)

### Locator Suffixes

Each virtual path is suffixed with a fixed-length locator for downstream re-seeking:

| Suffix | Format | Value |
|--------|--------|-------|
| `@t<16hex>` | tar | Header block index |
| `@z<16hex>` | zip | Local file header offset (when valid) |
| `@c<16hex>` | zip | CDFH offset (fallback when LFH offset invalid) |

Gzip entries omit the locator because gzip contains exactly one decompressed stream.

### Path Budget

Per-archive path byte usage is tracked in `path_budget_used` to prevent unbounded growth from archives with many entries having long paths. Exceeding `max_virtual_path_bytes_per_archive` triggers `PartialReason::PathBudgetExceeded`.

## Error Handling

### Corrupt or Malformed Archives

- **Truncated headers**: `read_exact_or_eof` returns `UnexpectedEof` with format-labeled messages (e.g., `"tar truncated"`, `"zip truncated"`)
- **Bad magic**: format detection returns `None`; the archive is treated as a regular file
- **Malformed size fields**: tar `parse_tar_size_octal` returns `None` → `PartialReason::MalformedTar`
- **ZIP EOCD not found**: `ZipOpen::Stop(MalformedZip)`
- **ZIP Zip64 sentinels**: `ZipOpen::Skip(UnsupportedFeature)` or `ZipNext::Stop(UnsupportedFeature)`
- **Mid-stream corruption**: compressed stream read errors → `PartialReason::CompressedStreamCorrupt` (gzip/bzip2) or `PartialReason::MalformedTar`/`MalformedZip`

Partial outcomes retain results for bytes already scanned. Skipped outcomes discard nothing (no bytes were scanned).

### I/O Errors

- File open failures → `ArchiveEnd::Skipped(IoError)`
- Read errors during header/payload → `ArchiveEnd::Partial` with the appropriate format reason
- No retry logic: each error is treated as fatal for that archive

### Policy Escalation

`EncryptedPolicy` and `UnsupportedPolicy` provide three levels:
1. `SkipWithTelemetry` — skip and record (default)
2. `FailArchive` — abort the current archive
3. `FailRun` — set `abort_run` flag, abort the entire scan

### Outcome Recording

Every archive encounter records exactly one top-level outcome via `ArchiveStats`:
- `record_archive_scanned()` — fully processed
- `record_archive_skipped(reason, path, sample)` — rejected before payload
- `record_archive_partial(reason, path, sample)` — stopped mid-scan

Entry-level outcomes:
- `record_entry_scanned()` — at least one payload byte scanned
- `record_entry_skipped(reason, path, sample)` — rejected before payload
- `record_entry_partial(reason, path, sample)` — stopped mid-entry (budget/corruption)

The bounded `ArchiveSampleRing` (32 samples, 192-byte path prefix each) captures the first N skip/partial events for diagnostics.

## Constants & Tuning

### Archive Configuration Defaults

| Parameter | Default | Rationale |
|-----------|---------|-----------|
| `max_archive_depth` | 3 | Covers `.tar.gz` containing a `.zip`; deeper nesting is adversarial |
| `max_entries_per_archive` | 4096 | Generous for real archives, bounds CPU in entry-counting loops |
| `max_uncompressed_bytes_per_entry` | 64 MiB | Limits peak memory per entry |
| `max_total_uncompressed_bytes_per_archive` | 256 MiB | Limits total archive output |
| `max_total_uncompressed_bytes_per_root` | 512 MiB | Limits cross-archive output under 1 GiB |
| `max_archive_metadata_bytes` | 16 MiB | Bounds header/CD parsing |
| `max_inflation_ratio` | 128x | Accommodates high-compression formats; catches classic zip bombs |
| `max_virtual_path_len_per_entry` | 1024 bytes | Bounds display path storage |
| `max_virtual_path_bytes_per_archive` | 1 MiB | Bounds total path arena per archive |
| `max_wall_clock_secs_per_root` | `None` | Keeps defaults deterministic; production should opt in (e.g., 30s) |
| `DEFAULT_WALL_CLOCK_SECS_PER_ROOT` | 30s | Suggested production value |
| `MAX_WALL_CLOCK_SECS_PER_ROOT` | 86,400s | Upper bound to prevent `Instant` overflow |

### Internal Constants

| Constant | Value | Location | Purpose |
|----------|-------|----------|---------|
| `ARCHIVE_STREAM_READ_MAX` | 256 KiB | `scan.rs:115` | Upper bound on single decompressed read |
| `LOCATOR_LEN` | 18 bytes | `scan.rs:109` | `@` + kind + 16 hex digits |
| `TAR_BLOCK_LEN` | 512 bytes | `formats/tar.rs:41` | Tar header/data block size |
| `USTAR_MAGIC_OFFSET` | 257 | `formats/tar.rs:44` | Offset of `"ustar"` magic in tar header |
| `EOCD_MIN_LEN` | 22 bytes | `formats/zip.rs:111` | Minimum end-of-central-directory size |
| `EOCD_SEARCH_MAX` | 66 KiB | `formats/zip.rs:112` | Backward search window for EOCD |
| `CDFH_LEN` | 46 bytes | `formats/zip.rs:115` | Central directory fixed header length |
| `LFH_LEN` | 30 bytes | `formats/zip.rs:117` | Local file header fixed length |
| `DEFAULT_MAX_COMPONENTS` | 256 | `path.rs:44` | Max path components during canonicalization |
| `TRUNC_SUFFIX_LEN` | 18 bytes | `path.rs:47` | `~#` + 16 hex digits |
| `ARCHIVE_SAMPLE_MAX` | 32 | `outcome.rs:350` | Max samples in bounded ring |
| `ARCHIVE_SAMPLE_PATH_PREFIX_MAX` | 192 bytes | `outcome.rs:352` | Max path prefix per sample |
| `ENTRY_NOT_OPEN` | `u64::MAX` | `budget.rs:188` | Sentinel for entry-not-open state |
| `VIRTUAL_FILE_ID_BASE` | `0x8000_0000` | `local_fs_archive_ctx.rs:85` | High-bit namespace for virtual IDs |

### Frame Stack Sizing

`ArchiveFrame` is exactly 48 bytes (`2 × u32 + 5 × u64`, `#[repr(C)]`, compile-time asserted). The frame stack is preallocated to `max_archive_depth` elements at construction and never grows.

## Source of Truth

| File | Line(s) | Purpose |
|------|---------|---------|
| `archive/mod.rs` | 1–40 | Module root, re-exports |
| `archive/config.rs` | 108–199 | `ArchiveConfig` struct + defaults (324–347) + validation (364–426) |
| `archive/budget.rs` | 140–172 | `ArchiveBudgets` struct |
| `archive/budget.rs` | 89–99 | `BudgetHit` enum |
| `archive/budget.rs` | 107–116 | `ChargeResult` enum |
| `archive/budget.rs` | 204–221 | `ArchiveFrame` struct |
| `archive/budget.rs` | 409–417 | `enter_archive()` |
| `archive/budget.rs` | 552–671 | `charge_decompressed_out()` — five-cap minimum logic |
| `archive/budget.rs` | 686–775 | `charge_discarded_out()` — bypasses per-entry output cap |
| `archive/detect.rs` | 53–66 | `ArchiveKind` enum |
| `archive/detect.rs` | 90–105 | `detect_kind_from_path()` |
| `archive/detect.rs` | 129–143 | `sniff_kind_from_header()` |
| `archive/detect.rs` | 151–156 | `detect_kind()` — combined detection |
| `archive/detect.rs` | 185–200 | `detect_kind_from_name_bytes()` — byte-level suffix matcher |
| `archive/outcome.rs` | 58–87 | `ArchiveSkipReason` (14 variants) |
| `archive/outcome.rs` | 132–153 | `EntrySkipReason` (10 variants) |
| `archive/outcome.rs` | 218–243 | `PartialReason` (12 variants) |
| `archive/outcome.rs` | 498–523 | `ArchiveStats` struct |
| `archive/outcome.rs` | 409–416 | `ArchiveSampleRing` struct |
| `archive/path.rs` | 104–117 | `EntryPathCanonicalizer` struct |
| `archive/path.rs` | 181–301 | `canonicalize()` method |
| `archive/path.rs` | 313–319 | `VirtualPathBuilder` struct |
| `archive/path.rs` | 355–387 | `build()` method |
| `archive/path.rs` | 546–578 | `apply_hash_suffix_truncation()` |
| `archive/scan.rs` | 133–137 | `ArchiveEnd` enum |
| `archive/scan.rs` | 143–153 | `EntryMeta` struct |
| `archive/scan.rs` | 169–179 | `EntryChunk` struct |
| `archive/scan.rs` | 206–212 | `ArchiveEntrySink` trait |
| `archive/scan.rs` | 234–249 | `ArchiveScratch<Z>` struct |
| `archive/scan.rs` | 356–378 | `ArchiveScanCtx` struct |
| `archive/scan.rs` | 507–594 | `scan_gzip_stream()` |
| `archive/scan.rs` | 620–777 | `scan_compressed_entry_stream()` — shared inner loop |
| `archive/scan.rs` | 782–829 | `scan_bzip2_stream()` |
| `archive/scan.rs` | 852–871 | `scan_tar_stream()` |
| `archive/scan.rs` | 897–1599 | `scan_tar_stream_nested()` — recursive tar iteration |
| `archive/scan.rs` | 1606–1616 | `scan_targz_stream()` |
| `archive/scan.rs` | 1623–1633 | `scan_tarbz2_stream()` |
| `archive/scan.rs` | 1666–2054 | `scan_zip_source()` |
| `archive/util.rs` | 28–57 | `CountedRead` struct |
| `archive/util.rs` | 71–100 | FNV-1a hash functions |
| `archive/util.rs` | 119–124 | `write_u64_hex_lower()` |
| `archive/util.rs` | 152–169 | `read_exact_n()` |
| `archive/util.rs` | 186–213 | `budget_hit_to_partial()` |
| `archive/formats/mod.rs` | 23–28 | `CompressedStream` trait |
| `archive/formats/gzip.rs` | 101–104 | `GzipStream` struct |
| `archive/formats/gzip.rs` | 128–154 | `new_with_header()` — header parsing |
| `archive/formats/bzip2.rs` | 35–38 | `Bzip2Stream` struct |
| `archive/formats/tar.rs` | 99–104 | `TarRead` trait |
| `archive/formats/tar.rs` | 145–159 | `TarEntryMeta` struct |
| `archive/formats/tar.rs` | 169–178 | `TarNext` enum |
| `archive/formats/tar.rs` | 188–221 | `TarCursor` struct |
| `archive/formats/tar.rs` | 304–413 | `next_entry()` — header parsing loop |
| `archive/formats/zip.rs` | 39–51 | `ZipSource` trait |
| `archive/formats/zip.rs` | 137–149 | `ZipEntryMeta` struct |
| `archive/formats/zip.rs` | 173–193 | `ZipCursor` struct |
| `archive/formats/zip.rs` | 265–426 | `open()` — EOCD parsing |
| `archive/formats/zip.rs` | 429–579 | `next_entry()` — CDFH iteration |
| `archive/formats/zip.rs` | 636–707 | `open_entry_reader()` — LFH validation + reader construction |
| `archive/formats/zip.rs` | 713–734 | `ZipEntryReader` enum |
| `archive/formats/zip.rs` | 739–767 | `LimitedRead` struct |
| `scheduler/local_fs_archive_ctx.rs` | 84–92 | `alloc_virtual_file_id()` |
| `scheduler/local_fs_archive_ctx.rs` | 125–138 | `dispatch_archive_scan()` |
| `scheduler/local_fs_archive_ctx.rs` | 148–164 | `ArchiveEnd` (scheduler variant) |
| `scheduler/local_fs_archive_ctx.rs` | 235–262 | `ArchiveScanCtx` (blocking-path variant) |
| `scheduler/local_fs_archive_ctx.rs` | 324–371 | `scan_and_emit_chunk()` |
| `scheduler/local_fs_archive_ctx.rs` | 429–471 | `apply_entry_budget_clamp()` |
| `scheduler/local_fs_archive_ctx.rs` | 481–504 | `discard_remaining_payload()` |
| `scheduler/local_fs_archive_ctx.rs` | 529–664 | `scan_compressed_stream_nested()` |
| `scheduler/local_fs_gzip.rs` | 26–140 | `process_gzip_file()` |
| `scheduler/local_fs_bzip2.rs` | 27–96 | `process_bzip2_file()` |
| `scheduler/local_fs_tar.rs` | 1–774 | `process_tar_file()`, `process_targz_file()`, `process_tarbz2_file()`, recursive tar iteration |
| `scheduler/local_fs_zip.rs` | 28–461 | `process_zip_file()` |
| `scheduler/local_fs_extract.rs` | 35–131 | `extract_and_scan_file()` — binary extraction (non-archive) |

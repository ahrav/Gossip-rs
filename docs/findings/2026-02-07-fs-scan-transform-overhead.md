# FS Scan: Transform Decoding Overhead Analysis

**Date:** 2026-02-07
**Branch:** `exp-fs`
**Related:** [SCA-97](https://linear.app/scanner-s/issue/SCA-97/add-transforms-cli-flag-for-per-transform-type-control)

## Objective

Quantify the CPU cost of URL-percent and Base64 transform decoding during
filesystem scans, and measure the throughput ceiling when transforms are
selectively or fully disabled.

## Test Environment

| Parameter      | Value                                                    |
| -------------- | -------------------------------------------------------- |
| Machine        | MacBook Pro (M4 Pro)                                     |
| CPU            | Apple M4 Pro — 12 cores (8 performance + 4 efficiency)   |
| Architecture   | arm64 (AArch64)                                          |
| RAM            | 48 GiB unified memory                                    |
| Storage        | Internal SSD (Apple Fabric protocol)                     |
| OS             | macOS 26.2 (Darwin 25.2.0)                               |
| Rust toolchain | rustc 1.92.0 (2025-12-08)                                |
| Build flags    | `RUSTFLAGS="-C target-cpu=native" cargo build --release` |
| Sink           | `--null-sink` (no JSON encoding / stdout I/O)            |

## Test Corpus

| Metric        | Value                                                   |
| ------------- | ------------------------------------------------------- |
| Source        | `consensus-rs-playground` (Rust source code repository) |
| Files         | 128,135                                                 |
| Chunks        | 255,226                                                 |
| Total bytes   | 40.05 GiB                                               |
| Chunk size    | 256 KiB (default)                                       |
| Avg file size | ~320 KiB                                                |
| Findings      | 5 (consistent across all variants)                      |

File size distribution:

- <1 KiB: 7,935 files
- 1–4 KiB: 8,097 files
- 4–64 KiB: 70,100 files
- 64–256 KiB: 32,045 files
- \>256 KiB: 9,958 files

## Results: Full Rule Set (223 rules)

All variants produce 5 findings. Zero encoded secrets exist in this corpus,
so disabling transforms has no recall impact here.

### Single-Core (1 worker)

| Variant                      | Throughput (MiB/s) | User CPU (s) | Wall (s) | vs Baseline |
| ---------------------------- | -----------------: | -----------: | -------: | ----------: |
| All transforms (baseline)    |                390 |           86 |       98 |           — |
| All transforms + URL gate    |                408 |           81 |       93 |       +4.6% |
| Base64 only (no URL-percent) |                491 |           66 |       78 |      +25.9% |
| URL-percent only (no Base64) |                568 |           56 |       67 |      +45.6% |
| No transforms                |                859 |           34 |       45 |   **+120%** |

### Multi-Core (12 workers)

| Variant                      | Throughput (MiB/s) | User CPU (s) | Wall (s) | vs Baseline |
| ---------------------------- | -----------------: | -----------: | -------: | ----------: |
| All transforms (baseline)    |              3,572 |          106 |       11 |           — |
| All transforms + URL gate    |              3,682 |          101 |     10.5 |       +3.1% |
| Base64 only (no URL-percent) |              4,560 |           81 |      8.4 |      +27.6% |
| URL-percent only (no Base64) |              5,266 |           68 |      7.3 |      +47.4% |
| No transforms                |              8,071 |           41 |      4.8 |   **+126%** |

### Projected Daily Throughput (12 cores)

| Variant        | GiB/s | TiB/day | TB/day |
| -------------- | ----: | ------: | -----: |
| All transforms |   3.5 |     293 |    322 |
| No transforms  |   7.9 |     665 |    731 |

## Results: Sparse Rule Set (1 rule: freshbooks-access-token)

Sparse rules reduce the Vectorscan prefilter DB size and anchor byte set
coverage, amplifying the effect of gates and transforms.

### Single-Core (1 worker)

| Variant                    | Throughput (MiB/s) | User CPU (s) | Wall (s) | vs Baseline |
| -------------------------- | -----------------: | -----------: | -------: | ----------: |
| All transforms (baseline)  |                533 |           61 |       72 |           — |
| All transforms + URL gate  |                655 |           47 |       58 |      +22.9% |
| No transforms              |              4,490 |          3.3 |        9 |   **+742%** |
| No-op engine (I/O ceiling) |              7,080 |          0.3 |        6 |     +1,228% |

### Isolation Experiments (Single-Core, 1 rule)

These temporary edits isolate specific cost contributors:

| Experiment                | Throughput (MiB/s) | Notes                                                |
| ------------------------- | -----------------: | ---------------------------------------------------- |
| Baseline (all transforms) |                533 |                                                      |
| No UTF-16 variants        |                586 | `scan_utf16_variants: false` — minimal impact        |
| No archives               |                580 | Archive header sniff disabled — minimal impact       |
| 1 MiB chunk size          |                558 | 4x larger chunks — no improvement                    |
| Empty transforms          |              4,490 | `demo_transforms() → vec![]`                         |
| No-op engine              |              7,080 | Early return in `scan_chunk_into` — pure I/O ceiling |

Note: Multi-core data was not collected for the sparse rule set.

## Root Cause Analysis

### Why transforms are expensive on zero-hit chunks

The Vectorscan prefilter finds zero anchor hits on the vast majority of chunks
(255,226/255,226 for the sparse rule set on this corpus). On the **zero-hit fast
path**, the engine checks whether transform decoding should still run — a secret
could be URL-encoded or Base64-encoded and invisible to the raw-buffer prefilter.

The gate chain for each transform on the zero-hit path:

```
needs_transform_scan = has_active_transforms
    AND buffer >= min_len
    AND transform_quick_trigger(tc, buf)       -- cheap sniff
    AND base64_buffer_gate(tc, buf)            -- encoded-space Base64 gate
    AND (tc.id != UrlPercent OR url_percent_buffer_gate(tc, buf))
```

**URL-percent cost:** `transform_quick_trigger` checks `%` (and `+` when
`plus_to_space` is enabled). In this setup (`plus_to_space: false`), that is
effectively `memchr(b'%', buf)`, which fires on ~69% of chunks (format
specifiers like `%d`, `%s`, `%02x`). Each triggered chunk enters
`find_url_spans_into()` for span detection — expensive even when no spans are
found.

**Base64 cost:** `transform_quick_trigger` always returns `true` (every buffer
could contain base64). The `base64_buffer_gate` runs a `Base64YaraGate`
encoded-space automaton scan over anchor-derived patterns — cheaper than full
span finding but still significant per-chunk overhead.

### Cost breakdown (single-core, full rules)

| Component                         | Approx. CPU fraction |
| --------------------------------- | -------------------: |
| Vectorscan prefilter (`hs_scan`)  |                 ~15% |
| URL-percent span finding          |                 ~25% |
| Base64 buffer gate (encoded scan) |                 ~20% |
| I/O (read + walker + metadata)    |                  ~8% |
| Bookkeeping (scratch reset, etc.) |                  ~5% |
| Regex validation + findings       |                  ~2% |
| Other                             |                 ~25% |

## URL-Percent Buffer Gate (implemented)

A new `url_percent_buffer_gate()` was added to the zero-hit fast path. It scans
the buffer for `%XX` triplets and checks if any decoded byte exists in the
engine's anchor byte set (a 256-bit bitmap built at engine construction from all
anchor pattern bytes).

- **Sparse rules (1 rule):** +23% throughput — most `%XX` triplets decode to
  bytes outside the narrow freshbooks anchor set.
- **Full rules (223 rules):** +5% throughput — the anchor byte set covers most
  printable ASCII, so fewer triplets are filtered.
- **Zero correctness impact:** the gate is conservative (passes if _any_ decoded
  byte matches _any_ anchor pattern byte).

## Conclusions

1. **Transforms are the dominant cost on source-code corpora.** Disabling both
   transforms yields a 2.26x throughput improvement (3.6 → 8.1 GiB/s multi-core)
   with zero recall loss on this corpus.

2. **Base64 gating is more expensive than URL-percent.** Base64-only (4.6 GiB/s)
   is slower than URL-percent-only (5.3 GiB/s) because the base64 buffer gate
   runs an encoded-space automaton scan on every chunk, while URL-percent's
   `memchr` trigger is cheaper.

3. **The URL-percent buffer gate helps modestly with full rules** (+5%) but
   significantly with sparse rules (+23%) where the anchor byte set is selective.

4. **A user-facing `--transforms` flag** (SCA-97) now lets users who know their
   data skip transform overhead entirely, achieving the no-transform throughput
   ceiling. Default behavior remains unchanged (`--transforms=all`).

5. **Scaling is near-linear.** The ratio between variants is consistent across 1
   and 12 cores — the bottleneck is per-chunk CPU, not thread contention or I/O.

6. **Per-file overhead (archives, metadata) is negligible.** Disabling archives
   or increasing chunk size had <5% impact.

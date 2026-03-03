# Scanner Comparison: False Positive Gap Analysis

**Date:** 2026-02-11
**Branch:** `chore/cli-cleanup`
**Scanners:** scanner-rs (222 rules at run time; 223 built-in rules as of 2026-02-13), kingfisher (216 matched rules), gitleaks (222 rules)

## Objective

Compare total findings across scanner-rs, kingfisher, and gitleaks on identical
filesystem data to identify which FP-reduction features explain the findings
delta — specifically, whether the gap is purely online validation or whether
kingfisher applies offline filters that scanner-rs lacks.

## Test Environment

| Parameter | Value |
|-----------|-------|
| Machine | MacBook Pro (M1 Pro) |
| CPU | Apple M1 Pro — 10 cores |
| RAM | 32 GiB unified memory |
| OS | macOS (Darwin 25.2.0) |
| scanner-rs | 222 built-in rules at run time (223 as of 2026-02-13), `--anchors=manual --event-format=jsonl --no-archives` |
| kingfisher | 216 matched rules, `--no-validate --no-dedup --no-extract-archives` |
| gitleaks | 222 rules (gitleaks.toml), `--max-archive-depth 0` |
| Data | Clean copies without `.git` (rsync --exclude='.git') |
| Benchmark script | `/Users/ahrav/Projects/kingfisher/benchmark_comparison.sh --matched-rules-only` |

## Results

### Findings Count

| Repository | Files | Size (MB) | Kingfisher | Scanner-rs | Gitleaks |
|------------|------:|----------:|-----------:|-----------:|---------:|
| rocksdb | 2,128 | 41.4 | 0 | 8 | 200 |
| gitleaks | 458 | 22.1 | 176 | 657 | 546 |
| go-git | 543 | 2.6 | 2 | 4 | 15 |
| linux | 92,099 | 1,478.8 | 2 | 2,894 | 2,872 |

### Performance

| Repository | Kingfisher (s) | Scanner-rs (s) | Gitleaks (s) | SR throughput (MB/s) |
|------------|---------------:|---------------:|-------------:|---------------------:|
| rocksdb | 0.89 | 0.49 | 5.04 | 65.2 |
| gitleaks | 0.78 | 0.26 | 2.00 | 4.3 |
| go-git | 0.62 | 0.26 | 0.29 | 10.2 |
| linux | 13.60 | 12.04 | 107.20 | 122.7 |

Scanner-rs is the fastest scanner across all repos. Gitleaks is 5-9x slower than
scanner-rs on large corpora (single-threaded regex vs compiled Vectorscan).

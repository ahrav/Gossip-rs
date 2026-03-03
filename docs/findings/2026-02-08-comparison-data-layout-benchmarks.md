# Comparison Data Layout Benchmarks (2026-02-08)

Issue: `gossip-rs-0zh`  
Epic: `gossip-rs-22c`

## Scope
Executed the follow-up benchmark suite after implementation tasks were closed, then compared against the baseline reference run:
- `scanner_throughput` (default suite: tier1 + tier2 + tier3 + tier4 + workload_comparison + buffer_scaling)
- `rule_scaling`
- `vectorscan_overhead`

## Environment
- Timestamp (UTC): `2026-02-08T07:59:44Z`
- OS: `Darwin 25.2.0 arm64`
- Rust: `rustc 1.93.0 (254b59607 2026-01-19)`
- Build flags: `RUSTFLAGS="-C target-cpu=native"`

## Commands
```bash
mkdir -p .bench/comparison-2026-02-08
RUSTFLAGS="-C target-cpu=native" cargo bench --bench scanner_throughput \
  2>&1 | tee .bench/comparison-2026-02-08/scanner_throughput.log
RUSTFLAGS="-C target-cpu=native" cargo bench --bench rule_scaling \
  2>&1 | tee .bench/comparison-2026-02-08/rule_scaling.log
RUSTFLAGS="-C target-cpu=native" cargo bench --bench vectorscan_overhead \
  2>&1 | tee .bench/comparison-2026-02-08/vectorscan_overhead.log
```

## Key Results (Comparison vs Baseline)

### scanner_throughput (tier2/tier3 focus)
| Benchmark | Baseline (median) | Comparison (median) | Delta |
| --- | --- | --- | --- |
| `tier2_prefilter/sparse_anchors/64KB_interval` | `2.8404 GiB/s` | `2.8885 GiB/s` | `+1.69%` |
| `tier2_prefilter/sparse_anchors/16KB_interval` | `1.8330 GiB/s` | `1.8765 GiB/s` | `+2.37%` |
| `tier2_prefilter/sparse_anchors/4KB_interval` | `1.7386 GiB/s` | `1.7588 GiB/s` | `+1.16%` |
| `tier2_prefilter/sparse_anchors/1KB_interval` | `1.3138 GiB/s` | `1.5071 GiB/s` | `+14.71%` |
| `tier3_validation/aws_keys/sparse_64KB` | `2.8475 GiB/s` | `2.8955 GiB/s` | `+1.69%` |
| `tier3_validation/aws_keys/moderate_16KB` | `2.8408 GiB/s` | `2.8484 GiB/s` | `+0.27%` |
| `tier3_validation/aws_keys/dense_4KB` | `2.7347 GiB/s` | `2.7430 GiB/s` | `+0.30%` |
| `tier3_validation/github_tokens/sparse_64KB` | `2.5427 GiB/s` | `2.5623 GiB/s` | `+0.77%` |
| `tier3_validation/github_tokens/moderate_16KB` | `2.2503 GiB/s` | `2.3115 GiB/s` | `+2.72%` |
| `tier3_validation/github_tokens/dense_4KB` | `1.9436 GiB/s` | `1.9436 GiB/s` | `+0.00%` |

Aggregate medians:
- Tier2 mean: `1.9314 GiB/s` -> `2.0077 GiB/s` (`+3.95%`)
- Tier3 mean: `2.5266 GiB/s` -> `2.5507 GiB/s` (`+0.95%`)

Additional scanner_throughput deltas:
- `tier4_transforms/*` mean delta: `+10.36%` (7 cases)
- `workload_comparison/*` mean delta: `+5.61%` (7 cases)

### rule_scaling (selected)
| Benchmark | Baseline (median) | Comparison (median) | Delta |
| --- | --- | --- | --- |
| `scaling/unique_rules/1` | `45.756 GiB/s` | `44.546 GiB/s` | `-2.64%` |
| `scaling/unique_rules/100` | `45.746 GiB/s` | `44.966 GiB/s` | `-1.71%` |
| `scaling/unique_rules/250` | `45.513 GiB/s` | `42.793 GiB/s` | `-5.98%` |
| `scaling/grouped_vs_unique/100_realistic` | `29.992 GiB/s` | `30.039 GiB/s` | `+0.16%` |
| `scaling/utf16_impact/100_rules_utf16_off` | `29.689 GiB/s` | `30.000 GiB/s` | `+1.05%` |
| `scaling/utf16_impact/100_rules_utf16_on` | `29.867 GiB/s` | `29.975 GiB/s` | `+0.36%` |

Aggregate:
- `rule_scaling` mean delta: `-3.22%` (15 cases)
- Worst regression: `scaling/grouped_vs_unique/100_grouped_5x20` at `-9.65%`

### vectorscan_overhead (selected)
| Benchmark | Baseline (median) | Comparison (median) | Delta |
| --- | --- | --- | --- |
| `layer2_raw_vectorscan/single_pattern_ascii` | `29.200 GiB/s` | `29.650 GiB/s` | `+1.54%` |
| `layer2_raw_vectorscan/10_patterns_ascii` | `21.090 GiB/s` | `21.340 GiB/s` | `+1.19%` |
| `layer3_minimal_engine/10_rules_ascii` | `45.008 GiB/s` | `45.043 GiB/s` | `+0.08%` |
| `layer3_minimal_engine/10_rules_random` | `12.050 GiB/s` | `12.294 GiB/s` | `+2.02%` |
| `layer4_full_engine/full_gitleaks_ascii` | `556.32 MiB/s` | `567.04 MiB/s` | `+1.93%` |
| `layer4_full_engine/full_gitleaks_random` | `163.69 MiB/s` | `171.99 MiB/s` | `+5.07%` |

Aggregate:
- `vectorscan_overhead` mean delta: `+1.59%` (13 cases)

## Decision
- Keep the data-layout changes.
- Rationale:
  - Tier2 throughput improved by `+3.95%`.
  - Tier3 throughput is modestly positive (`+0.95%`) with no regressions in selected core cases.
  - Transform-heavy and full workload cases improved substantially (`+10.36%` and `+5.61%` means).
  - `rule_scaling` synthetic unique/grouped mixes regressed in several cases and should be optimized in follow-up work.

## Notes and Constraints
- Linux `perf stat` counters requested by `0zh` were not collected because this run was executed on macOS (`Darwin`), not Linux.
- Comparison values were computed from median throughput lines in:
  - `.bench/baseline-2026-02-08/*.log`
  - `.bench/comparison-2026-02-08/*.log`

## Artifacts
- `.bench/baseline-2026-02-08/scanner_throughput.log`
- `.bench/baseline-2026-02-08/rule_scaling.log`
- `.bench/baseline-2026-02-08/vectorscan_overhead.log`
- `.bench/comparison-2026-02-08/scanner_throughput.log`
- `.bench/comparison-2026-02-08/rule_scaling.log`
- `.bench/comparison-2026-02-08/vectorscan_overhead.log`
- `.bench/comparison-2026-02-08/parsed/comparison_vs_baseline_all.tsv`

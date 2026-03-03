# Baseline Data Layout Benchmarks (2026-02-08)

Issue: `gossip-rs-y2o`  
Epic: `gossip-rs-22c`

## Scope
Executed the baseline benchmark suite after implementation tasks were closed:
- `scanner_throughput` (includes tier2 + tier3)
- `rule_scaling`
- `vectorscan_overhead`

## Environment
- Timestamp (UTC): `2026-02-08T06:58:37Z`
- OS: `Darwin 25.2.0 arm64`
- Rust: `rustc 1.93.0 (254b59607 2026-01-19)`
- Build flags: `RUSTFLAGS="-C target-cpu=native"`

## Commands
```bash
mkdir -p .bench/baseline-2026-02-08
RUSTFLAGS="-C target-cpu=native" cargo bench --bench scanner_throughput \
  2>&1 | tee .bench/baseline-2026-02-08/scanner_throughput.log
RUSTFLAGS="-C target-cpu=native" cargo bench --bench rule_scaling \
  2>&1 | tee .bench/baseline-2026-02-08/rule_scaling.log
RUSTFLAGS="-C target-cpu=native" cargo bench --bench vectorscan_overhead \
  2>&1 | tee .bench/baseline-2026-02-08/vectorscan_overhead.log
```

## Key Results

### scanner_throughput (tier2/tier3)
| Benchmark | Throughput (median) |
| --- | --- |
| `tier2_prefilter/sparse_anchors/64KB_interval` | `2.8404 GiB/s` |
| `tier2_prefilter/sparse_anchors/16KB_interval` | `1.8330 GiB/s` |
| `tier2_prefilter/sparse_anchors/4KB_interval` | `1.7386 GiB/s` |
| `tier2_prefilter/sparse_anchors/1KB_interval` | `1.3138 GiB/s` |
| `tier3_validation/aws_keys/sparse_64KB` | `2.8475 GiB/s` |
| `tier3_validation/aws_keys/moderate_16KB` | `2.8408 GiB/s` |
| `tier3_validation/aws_keys/dense_4KB` | `2.7347 GiB/s` |
| `tier3_validation/github_tokens/sparse_64KB` | `2.5427 GiB/s` |
| `tier3_validation/github_tokens/moderate_16KB` | `2.2503 GiB/s` |
| `tier3_validation/github_tokens/dense_4KB` | `1.9436 GiB/s` |

Aggregate medians:
- Tier2 mean: `1.9314 GiB/s` (4 cases)
- Tier3 mean: `2.5266 GiB/s` (6 cases)

### rule_scaling (selected)
| Benchmark | Throughput (median) |
| --- | --- |
| `scaling/unique_rules/1` | `45.756 GiB/s` |
| `scaling/unique_rules/100` | `45.746 GiB/s` |
| `scaling/unique_rules/250` | `45.513 GiB/s` |
| `scaling/grouped_vs_unique/100_realistic` | `29.992 GiB/s` |
| `scaling/utf16_impact/100_rules_utf16_off` | `29.689 GiB/s` |
| `scaling/utf16_impact/100_rules_utf16_on` | `29.867 GiB/s` |

### vectorscan_overhead (selected)
| Benchmark | Throughput (median) |
| --- | --- |
| `layer2_raw_vectorscan/single_pattern_ascii` | `29.200 GiB/s` |
| `layer2_raw_vectorscan/10_patterns_ascii` | `21.090 GiB/s` |
| `layer3_minimal_engine/10_rules_ascii` | `45.008 GiB/s` |
| `layer3_minimal_engine/10_rules_random` | `12.050 GiB/s` |
| `layer4_full_engine/full_gitleaks_ascii` | `556.32 MiB/s` |
| `layer4_full_engine/full_gitleaks_random` | `163.69 MiB/s` |

## Notes and Constraints
- The explicit pre-optimization baseline task (`gossip-rs-pp0`) was previously closed as skipped, so this run has no stored "before" baseline deltas.
- Linux `perf stat` counters requested by `y2o` were not collected because this run was executed on macOS (`Darwin`), not Linux.
- This run serves as the baseline reference point for follow-up comparisons.

## Artifacts
- `.bench/baseline-2026-02-08/scanner_throughput.log`
- `.bench/baseline-2026-02-08/rule_scaling.log`
- `.bench/baseline-2026-02-08/vectorscan_overhead.log`

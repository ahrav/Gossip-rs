# Performance Findings

This directory contains performance investigation reports and benchmark findings.
Each report captures a specific investigation with methodology, results, and
conclusions to build an institutional record over time.

## Reports

| Date | Report | Summary |
|------|--------|---------|
| 2026-02-11 | [Scanner comparison FP gap](2026-02-11-scanner-comparison-fp-gap.md) | scanner-rs vs kingfisher vs gitleaks: kingfisher reports 2 findings on linux vs 2,894 for scanner-rs; gap driven by global safe-list (18 rules), pattern requirements, and sparse value suppressor coverage — not online validation |
| 2026-02-08 | [Comparison data layout benchmarks](2026-02-08-comparison-data-layout-benchmarks.md) | Comparison vs baseline: Tier2 mean +3.95%, Tier3 mean +0.95%, transform-heavy cases +10.36%; keep changes and follow up on rule-scaling regressions |
| 2026-02-08 | [Baseline data layout benchmarks](2026-02-08-baseline-data-layout-benchmarks.md) | Baseline reference run across scanner throughput, rule scaling, and vectorscan overhead; no pre-optimization baseline available |
| 2026-02-07 | [FS scan transform overhead](2026-02-07-fs-scan-transform-overhead.md) | Transform decoding accounts for 2.26x overhead on source-code corpora; disabling transforms yields ~8 GiB/s on 12 cores |

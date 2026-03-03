# Cross-Rule Overlap Synthetic Fixture

This fixture exercises cross-rule dedup behavior in synthetic eval mode.

## Scenarios

| Scenario | Description | Expected behavior with `--cross-rule-dedup` |
|---|---|---|
| S1 | Same span, different confidence (`aws-access-key` vs `generic-secret`) | Keep higher confidence winner |
| S2 | Same span, equal confidence (`generic-api-key` vs `github-pat`) | Keep lexicographically smaller rule |
| S3 | Same bytes in a different file (`config.py`) | Dedup is per-file; no cross-file collapse |
| S4 | Non-overlapping standalone finding (`hex-token`) | Unchanged |
| S5 | Same `byte_start`, different `byte_end` on same line (`aws-prefix` vs `aws-extended`) | Both preserved (exact-span keying) |

## Expected Counts

| Mode | Findings | TP | FP | Unlabeled | FN | Precision | Recall |
|---|---:|---:|---:|---:|---:|---:|---:|
| ByRule | 9 | 6 | 3 | 0 | 0 | 0.667 | 1.0 |
| AcrossRules (`--cross-rule-dedup`) | 6 | 6 | 0 | 0 | 0 | 1.000 | 1.0 |

## Expected Winners

- S1 winner: `aws-access-key` (confidence 8 > 3)
- S2 winner: `generic-api-key` (tie-break on lexical order)
- S3 winner in `config.py`: `aws-access-key` independent of `creds.py`
- S4 untouched: `hex-token`
- S5 both preserved due to distinct spans (`[116,136)` and `[116,152)`)

## Why S5 Matters

Cross-rule dedup uses an exact `(path, byte_start, byte_end)` span key. Two findings that overlap but differ in `byte_end` are distinct and must not collapse. This aligns with scanner `dedupe_with_span` behavior.

## CLI Examples

```bash
# ByRule
cargo run -- synthetic \
  --manifest testdata/synthetic/cross_rule_overlap/truth.json \
  --findings testdata/synthetic/cross_rule_overlap/findings_overlap.jsonl \
  --corpus-root testdata/synthetic/cross_rule_overlap/corpus \
  --format json

# AcrossRules
cargo run -- synthetic \
  --manifest testdata/synthetic/cross_rule_overlap/truth.json \
  --findings testdata/synthetic/cross_rule_overlap/findings_overlap.jsonl \
  --corpus-root testdata/synthetic/cross_rule_overlap/corpus \
  --cross-rule-dedup \
  --format json
```

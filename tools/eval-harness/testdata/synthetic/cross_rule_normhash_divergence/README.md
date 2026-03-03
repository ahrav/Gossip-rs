# Cross-Rule `norm_hash` Divergence Fixture

This synthetic fixture models a case where scanner cross-rule dedup and eval-harness
cross-rule dedup produce different outcomes.

## Why This Fixture Exists

Scanner dedup key: `(root_hint, span_projection, norm_hash)`

Eval dedup key: `(path, byte_start, byte_end)`

When two findings share the same byte span but correspond to different normalized
secrets, scanner dedup can keep both (different `norm_hash`), while eval dedup will
collapse them to one (position-only key).

## Scenarios

| Scenario | Description | Expected behavior |
|---|---|---|
| S1 | Same span `[58,74)`, two rules kept in scanner-ON fixture (`aws-access-key`, `generic-secret`) to model distinct `norm_hash` values | Scanner ON + Eval OFF keeps both; Eval ON collapses to winner |
| S2 | Same span `[100,116)`, equal confidence (`generic-api-key` vs `github-pat`) | Tie resolves to lexicographically smaller rule |
| S3 | Standalone positive (`hex-token`) | Unchanged |

## Fixture Files

- `findings_normhash_off.jsonl`: scanner dedup OFF model (contains extra same-span alternatives)
- `findings_normhash_scanner_deduped.jsonl`: scanner dedup ON model

Note: JSONL findings do not include `norm_hash`. The scanner-ON fixture encodes expected
post-scanner behavior for a case where same-span findings differ by secret hash.

## Expected 2x2 Trend

| Cell | Scanner | Eval | Findings | TP | FP | Precision | Recall |
|---|---|---|---:|---:|---:|---:|---:|
| 1 | OFF | OFF | 6 | 3 | 3 | 0.50 | 1.00 |
| 2 | ON | OFF | 4 | 3 | 1 | 0.75 | 1.00 |
| 3 | OFF | ON | 3 | 3 | 0 | 1.00 | 1.00 |
| 4 | ON | ON | 3 | 3 | 0 | 1.00 | 1.00 |

Cell 2 vs Cell 4 is the key divergence signal: eval dedup collapses a scanner-preserved
same-span pair.

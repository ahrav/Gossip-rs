# Eval Harness

Accuracy measurement tool for scanner-rs. Compares scanner findings against labeled ground-truth corpora to compute precision, recall, Average Precision (AP), and related metrics. Designed for regression gating in CI and iterative rule development.

## Motivation

Secret scanners need quantitative accuracy tracking. Without measurement, rule changes might improve detection of one secret type while silently breaking another. The eval harness answers concrete questions:

- **What is the scanner's precision and recall against known corpora?** The position-based pipeline computes these from byte-level overlap between scanner findings and ground-truth annotations.
- **Did this rule change make things worse?** Baseline comparison with CI-gated regression verdicts catches regressions before they ship.
- **Which rules produce the most false positives?** The error book surfaces the top FP/FN by rule for targeted debugging.
- **How confident are we in the AP estimate?** Bootstrap confidence intervals quantify sampling uncertainty.

Use the harness after modifying detection rules, before releases, in CI pipelines, when adding new secret types, or when tuning confidence thresholds.

## Architecture

### Module Map

The harness lives in `tools/eval-harness/` as a standalone crate with its own `Cargo.toml`. It depends on `scanner-rs` for the engine and path normalization utilities.

| Module              | Role                                                                                                   |
|---------------------|--------------------------------------------------------------------------------------------------------|
| `main.rs`           | CLI entry point, subcommand dispatch, pipeline orchestration                                           |
| `types.rs`          | Core domain types: `NormalizedFinding`, `TruthItem`, `TruthLabel`, `ClassifiedFinding`, `FindingClass` |
| `creddata.rs`       | CredData CSV truth loader                                                                              |
| `synthetic.rs`      | Synthetic JSON manifest truth loader                                                                   |
| `leaky_repo.rs`     | LeakyRepo CSV expectations and count-based comparison                                                  |
| `finding_parser.rs` | Scanner JSONL output parser, deduplication                                                             |
| `line_index.rs`     | Byte-offset to line-number conversion (O(log n) binary search)                                         |
| `fs_walk.rs`        | Recursive file collection (internal utility)                                                           |
| `matching.rs`       | Position-based finding-to-truth matching (greedy, confidence-sorted)                                   |
| `metrics.rs`        | Precision, recall, F1, F2, AP, P@R, R@P, bootstrap CI, per-rule breakdown                              |
| `provenance.rs`     | BLAKE3 corpus/binary/ruleset hashing for reproducibility                                               |
| `regression.rs`     | Baseline comparison with CI overlap gating and two-tier verdicts                                       |
| `report.rs`         | Report assembly, JSON/table rendering, error book generation                                           |
| `lib.rs`            | Module re-exports                                                                                      |

### Data Flow

Both pipelines follow a **load-match-measure-report** pattern:

```text
Position-based (creddata / synthetic):
  truth loader ──► TruthItem[]
                               ├─► match_findings ──► ClassifiedFinding[]
  finding source ──► NormalizedFinding[] ──► dedup pipeline (identity, optional cross-rule)
                                                      ├─► compute_metrics ──► EvalMetrics
  corpus files ──► HashMap<path, bytes>               ├─► hash_corpus_snapshot ──► Provenance
                                                      ├─► bootstrap_ap_ci ──► CI
                                                      ├─► check_regression ──► Verdict
                                                      └─► build_error_book [JSON only] ──► ErrorBook
                                                                  └─► EvalReport ──► JSON / table

Count-based (leaky-repo):
  expectations CSV ──► FileExpectation[]
                                   ├─► compare_counts ──► per-file TP/FP/FN
  findings JSONL ──► NormalizedFinding[]                  └─► aggregate ──► EvalMetrics
                                                               └─► EvalReport ──► JSON / table
```

### Key Types

**`NormalizedFinding`** — A scanner finding normalized for comparison. Identity is `(path, byte_start, byte_end, rule)`; confidence is excluded from equality so duplicates at the same location collapse correctly. Byte offsets use half-open `[byte_start, byte_end)` convention.

**`TruthItem`** — A ground-truth annotation using 1-indexed inclusive line numbers (`line_start`, `line_end`). Each item carries a `TruthLabel` (Positive, Negative, or Placeholder) and a rule name.

**`ClassifiedFinding`** — A finding paired with its `FindingClass` (TruePositive, FalsePositive, or Unlabeled). FalseNegative is intentionally not a `FindingClass` variant because false negatives are truth-derived, not finding-derived.

**`EvalMetrics`** — Aggregate metrics: AP, precision, recall, F1, F2, baseline AP, P@R targets, R@P targets, bootstrap CI, per-rule breakdown (`BTreeMap<String, RuleMetrics>`).

**`EvalReport`** — Top-level serializable artifact combining required `EvalMetrics`, `Provenance`, and required `pipeline_config`, plus optional `RegressionResult` and optional `ErrorBook`.

**`EvalPipelineConfig`** — Pipeline semantics used for this run. Currently includes `cross_rule_dedup` (default `false`). Legacy baseline JSON without this field deserializes with `cross_rule_dedup = false`.

### Matching Algorithm

The matching layer uses **confidence-sorted greedy matching**, the same strategy as COCO and PASCAL VOC evaluation protocols:

1. Sort findings by confidence descending (deterministic tiebreak via `NormalizedFinding::Ord`).
2. Group truth items by file path; sort each group by `line_start`.
3. For each finding (highest confidence first):
   - Convert byte range to line range via `LineIndex`.
   - Binary search for overlapping truth items in the same file.
   - Apply label priority: Positive > Negative > Placeholder.
   - Consume matched Positive truths (one-to-one TP counting).
   - Negative truths are **not** consumed (multiple findings at a negative region all classify as FP).
   - Placeholder truths are **not** consumed (multiple findings at an ignore region all classify as Unlabeled).

Greedy matching is required for valid PRC-AUC: it produces nested TP sets across confidence thresholds, ensuring recall is monotonically non-decreasing.

### Metrics Computed

| Metric                 | Description                                                                                                       |
|------------------------|-------------------------------------------------------------------------------------------------------------------|
| Average Precision (AP) | Step-function AP with tie collapsing (matches sklearn's `average_precision_score`)                                |
| Precision              | TP / (TP + FP)                                                                                                    |
| Recall                 | TP / (TP + FN)                                                                                                    |
| F1                     | Harmonic mean of precision and recall                                                                             |
| F2                     | Recall-weighted F-score (β=2); weights recall 4x more than precision                                              |
| Baseline AP            | Class prevalence among scored items (`tp / (tp + fp)`); the expected AP of a random ranker                        |
| P@R                    | Precision at fixed recall targets (default: 0.80, 0.90, 0.95)                                                     |
| R@P                    | Recall at fixed precision targets (default: 0.95)                                                                 |
| Bootstrap CI           | Percentile-based confidence interval for AP via stratified resampling (default: 1000 iterations, α=0.05, seed=42) |
| Per-rule breakdown     | TP, FP, and precision per detection rule                                                                          |

## CLI Usage

### Subcommands

The harness provides three subcommands, each targeting a different corpus format:

#### `creddata` — Position-based evaluation against CredData

```
eval-harness creddata \
  --meta-dir <DIR>       \   # CredData CSV directory with ground-truth annotations
  --corpus-root <DIR>    \   # Path normalization root (stripped from finding/truth paths)
  --findings <JSONL>     \   # Pre-computed findings JSONL file   ─┐ mutually
  --scan-corpus <DIR>    \   # OR: directory to live-scan          ─┘ exclusive
  --cross-rule-dedup     \   # Optional: collapse same-span findings across rules
  --format <json|table>  \   # Output format (default: json)
  --output <PATH>        \   # Write JSON to file instead of stdout
  --baseline <JSON>          # Baseline report for regression comparison
```

#### `synthetic` — Position-based evaluation against synthetic manifests

```
eval-harness synthetic \
  --manifest <JSON>      \   # Synthetic corpus JSON manifest
  --corpus-root <DIR>    \   # Path normalization root
  --findings <JSONL>     \   # Pre-computed findings JSONL file   ─┐ mutually
  --scan-corpus <DIR>    \   # OR: directory to live-scan          ─┘ exclusive
  --cross-rule-dedup     \   # Optional: collapse same-span findings across rules
  --format <json|table>  \   # Output format (default: json)
  --output <PATH>        \   # Write JSON to file instead of stdout
  --baseline <JSON>          # Baseline report for regression comparison
```

#### `leaky-repo` — Count-based evaluation against LeakyRepo

```
eval-harness leaky-repo \
  --secrets-csv <CSV>    \   # LeakyRepo secrets CSV (per-file expected counts)
  --findings <JSONL>     \   # Pre-computed findings JSONL file
  --corpus-root <DIR>    \   # Path normalization root
  --format <json|table>  \   # Output format (default: json)
  --output <PATH>            # Write JSON to file instead of stdout
```

### Finding Input Modes

Position-based subcommands (`creddata`, `synthetic`) accept findings from two mutually exclusive sources:

- **`--findings <path>`** — Pre-computed JSONL from a previous scanner run. Finding lines use scanner wire fields: `type: "finding"`, `path`, `start`, `end`, `rule`, and optional `confidence_score`.
- **`--scan-corpus <dir>`** — Live-scan a directory using the embedded `scanner_rs::demo_engine()` with the default ruleset. Findings are collected via an in-memory event sink and re-parsed through the same JSONL path. Intended for quick iteration during rule development on small-to-medium corpora.

The `leaky-repo` subcommand only supports `--findings` (no live scan).

When `--cross-rule-dedup` is enabled, the harness keeps one finding per
`(path, start, end)` span across all rules before matching. Winner selection
is deterministic: highest confidence wins, and equal-confidence ties resolve to
the lexicographically smaller rule name.

### Output Formats

- **`--format json`** (default) — Machine-readable pretty-printed JSON. Supports `--output <path>` for file persistence. This is the format used for baseline comparison.
- **`--format table`** — Fixed-width ASCII table for terminal display. Shows aggregate metrics, per-rule breakdown, and regression verdict. Cannot be combined with `--output` (rejected at validation time).

### Exit Codes

| Code | Meaning                                                          |
|------|------------------------------------------------------------------|
| 0    | Pass or Warn — metrics meet thresholds (or no baseline provided) |
| 1    | Block — regression detected against `--baseline` report          |
| 2    | Argument or runtime error                                        |

## Choosing a Dataset

| Dataset        | Granularity                   | Best For                                                                         | Corpus Size                            |
|----------------|-------------------------------|----------------------------------------------------------------------------------|-----------------------------------------|
| **CredData**   | Position-based (file + lines) | Comprehensive accuracy measurement, release benchmarks, cross-scanner comparison | 73,842 annotations from 297 real repos |
| **Synthetic**  | Position-based (file + lines) | Rule development iteration, CI regression gates for specific secret types        | Hand-crafted, typically 10–100 items   |
| **LeakyRepo**  | Count-based (file + total)    | Corpora with count-only annotations, no positional ground truth available        | Varies                                 |

- **CredData** is the standard benchmark for secret scanners. Use it for measuring overall scanner quality and comparing against published results from other tools. Large and real-world, but requires downloading source files (~11,000 files from GitHub).
- **Synthetic** manifests give precise control over what's tested. Each item specifies an exact file, line range, label, and rule. Use for fast, deterministic regression detection on specific rules during development.
- **LeakyRepo** uses per-file expected counts rather than line positions. Coarser than the position-based pipelines (no confidence-aware metrics, no error book), but useful when positional ground truth is unavailable.

## Quick Start

Minimal examples for each subcommand. See [Dataset Guides](#dataset-guides) for full setup instructions.

```bash
# CredData — position-based evaluation with live scan
eval-harness creddata \
  --meta-dir /path/to/CredData/meta \
  --corpus-root /path/to/CredData \
  --scan-corpus /path/to/CredData/data

# Synthetic — position-based evaluation with live scan
eval-harness synthetic \
  --manifest tests/synthetic/manifest.json \
  --corpus-root tests/synthetic/corpus \
  --scan-corpus tests/synthetic/corpus

# LeakyRepo — count-based evaluation with pre-computed findings
eval-harness leaky-repo \
  --secrets-csv /path/to/secrets.csv \
  --findings findings.jsonl \
  --corpus-root /path/to/corpus
```

## Dataset Guides

### CredData

[Samsung CredData](https://github.com/Samsung/CredData) is a 73,842-annotation ground-truth corpus drawn from 297 real GitHub repositories. It contains 4,583 true positives (6.2% positive rate) and is the standard benchmark for secret scanners.

#### Obtaining the corpus

The `meta/` directory (332 CSV annotation files) is checked into the CredData git repository. The `data/` directory (~11,000 source files) is **not** in git — it must be generated by downloading pinned repository snapshots.

```bash
git clone https://github.com/Samsung/CredData /path/to/CredData
cd /path/to/CredData
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python download_data.py --data_dir data --jobs $(nproc)
```

Requirements: Python 3.10+. Some source repositories may have been deleted or made private since the snapshot was pinned; partial corpus download is expected and does not prevent evaluation (rows referencing missing files are skipped during matching).

#### Directory structure

```
CredData/
  meta/          # 332 CSV annotation files (ground truth) — in git
  data/          # ~11,000 source files — generated by download_data.py
  snapshot.json  # Pinned repo commits for reproducibility
```

#### CSV format

Each CSV in `meta/` has 13 PascalCase columns. The harness uses 5:

| Column        | Type    | Description                                                                                  |
|---------------|---------|----------------------------------------------------------------------------------------------|
| `FilePath`    | string  | Relative path starting with `data/` (e.g., `data/00408ef6/src/config.py`)                    |
| `LineStart`   | integer | 1-indexed inclusive start line, or -1 for unknown location                                   |
| `LineEnd`     | integer | 1-indexed inclusive end line, or -1 for unknown location                                     |
| `GroundTruth` | string  | `T` (true positive), `F` (false positive), or `X` (excluded from scoring)                    |
| `Category`    | string  | CredSweeper rule name (e.g., `Password`, `Token`, `AWS Multi`); used for per-rule breakdown  |

Rows with `GroundTruth = X` are loaded as `Placeholder` labels and excluded from precision/recall calculation. Rows with `LineStart = -1` or `LineEnd = -1` (unknown location) are skipped during loading.

#### Running the eval

```bash
# Live scan — the harness scans data/ using the embedded demo engine
eval-harness creddata \
  --meta-dir /path/to/CredData/meta \
  --corpus-root /path/to/CredData \
  --scan-corpus /path/to/CredData/data

# Pre-computed findings — supply JSONL from a previous scanner run
eval-harness creddata \
  --meta-dir /path/to/CredData/meta \
  --corpus-root /path/to/CredData \
  --findings findings.jsonl

# Table output for quick terminal review
eval-harness creddata \
  --meta-dir /path/to/CredData/meta \
  --corpus-root /path/to/CredData \
  --scan-corpus /path/to/CredData/data \
  --format table
```

#### Why `--corpus-root` is the CredData repo root (not `data/`)

CSV `FilePath` values start with the `data/` prefix (e.g., `data/00408ef6/src/config.py`). The harness normalizes both finding paths and truth paths by stripping the `--corpus-root` prefix. When `--corpus-root` points to the CredData repo root:

- Truth path `data/00408ef6/src/config.py` stays as-is (already relative to repo root).
- Finding path `/path/to/CredData/data/00408ef6/src/config.py` is stripped to `data/00408ef6/src/config.py`.

Both resolve to the same key, enabling correct matching. If `--corpus-root` pointed to `data/` instead, truth paths would retain the `data/` prefix while finding paths would not, causing zero matches.

#### Baseline regression

```bash
# Save a baseline report
eval-harness creddata \
  --meta-dir /path/to/CredData/meta \
  --corpus-root /path/to/CredData \
  --findings baseline-findings.jsonl \
  --output baseline.json

# Compare a new run against the baseline
eval-harness creddata \
  --meta-dir /path/to/CredData/meta \
  --corpus-root /path/to/CredData \
  --findings new-findings.jsonl \
  --baseline baseline.json

# Exit code 0 = pass/warn, 1 = block (regression detected)
echo "Exit code: $?"
```

If current and baseline pipeline configs differ (for example one run enabled
`--cross-rule-dedup` and the other did not), the harness emits a warning and
also records machine-readable comparability metadata in the regression JSON.

#### Published benchmark reference

Samsung published cross-scanner benchmarks on CredData (results may vary by CredData version and scanner configuration):

| Scanner            | Precision | Recall |
|--------------------|-----------|--------|
| CredSweeper (ML)   | 91.7%     | 80.8%  |
| Gitleaks           | 52.6%     | 24.4%  |
| truffleHog (v2)    | 25.0%     | 0.9%   |
| truffleHog3 (v3)   | 15.0%     | 54.7%  |
| detect-secrets     | 14.2%     | 38.1%  |

CredSweeper's numbers include ML-based filtering and were evaluated on combined training and test data, so its metrics reflect partial evaluation on its own training set. Other scanners primarily use pattern-based detection (regex and entropy). scanner-rs results will depend on the current ruleset.

#### Caveats

- **Obfuscated values**: CredData replaces real credential values with synthetic substitutes. Rules that rely on high-entropy detection may behave differently than on live repositories.
- **Category names**: The `Category` column uses CredSweeper rule names (e.g., `Password`, `Token`, `AWS Multi`), which do not match scanner-rs rule names. This is expected — the harness does not require rule name matching for TP/FP classification (matching is position-based). Category names appear in the per-rule breakdown for analysis.
- **Partial downloads**: Some pinned repositories may be unavailable. The harness handles this gracefully — truth rows referencing files that do not exist on disk produce no findings to match (counted as FN).

### Synthetic Corpus

A synthetic corpus is a hand-crafted JSON manifest paired with a directory of source files. Each manifest entry specifies an exact file, line range, label, and rule. Synthetic corpora are ideal for testing specific rules and catching regressions on known secret patterns.

#### Manifest format

The manifest is a JSON array of objects:

```json
[
  {
    "path": "src/config.py",
    "line_start": 12,
    "line_end": 12,
    "label": "positive",
    "rule": "generic-api-key"
  },
  {
    "path": "src/config.py",
    "line_start": 20,
    "line_end": 21,
    "label": "negative",
    "rule": "generic-api-key"
  }
]
```

| Field        | Type    | Required | Description                                                 |
|--------------|---------|----------|-------------------------------------------------------------|
| `path`       | string  | yes      | File path relative to `--corpus-root`                       |
| `line_start` | integer | yes      | 1-indexed inclusive start line                              |
| `line_end`   | integer | yes      | 1-indexed inclusive end line                                |
| `label`      | string  | yes      | `"positive"`, `"negative"`, or `"placeholder"`              |
| `rule`       | string  | yes*     | Rule name for per-rule breakdown                            |
| `category`   | string  | no       | Alias for `rule` (if both present, `rule` takes precedence) |

Validation is fail-fast: the first invalid entry halts loading with an error that identifies the entry index and reason. Manifests must be under 16 MB.

#### Running the eval

```bash
# Live scan — harness scans the corpus directory
eval-harness synthetic \
  --manifest tests/synthetic/manifest.json \
  --corpus-root tests/synthetic/corpus \
  --scan-corpus tests/synthetic/corpus \
  --cross-rule-dedup

# Pre-computed findings
eval-harness synthetic \
  --manifest tests/synthetic/manifest.json \
  --corpus-root tests/synthetic/corpus \
  --findings findings.jsonl

# With baseline regression check
eval-harness synthetic \
  --manifest tests/synthetic/manifest.json \
  --corpus-root tests/synthetic/corpus \
  --scan-corpus tests/synthetic/corpus \
  --cross-rule-dedup \
  --baseline baseline.json
```

#### When to use

- **Rule development**: After modifying a detection rule, run the synthetic eval to verify the rule still detects its target patterns and does not fire on known negatives.
- **CI regression gates**: Commit a synthetic manifest alongside rule changes. The harness exits with code 1 if a `--baseline` comparison detects regression.
- **Targeted testing**: Unlike CredData (broad coverage, many categories), synthetic manifests test exactly the patterns you specify. Use them to cover edge cases that may not appear in real-world corpora.

### LeakyRepo

LeakyRepo uses count-based evaluation: each entry specifies a file path and the expected number of secrets, without line-level positions. This is coarser than position-based evaluation but useful when positional ground truth is unavailable.

#### CSV format

Three columns, no header row. Lines starting with `#` are comments.

```
# file_path,num_risk,num_informative
.bash_profile,6,5
.bashrc,3,3
.docker/.dockercfg,2,2
src/app/config.py,1,0
```

| Column          | Type    | Description                                                              |
|-----------------|---------|--------------------------------------------------------------------------|
| file path       | string  | Relative to `--corpus-root`; may contain commas (parsed via right-split) |
| num_risk        | integer | Count of high-risk secrets                                               |
| num_informative | integer | Count of informative secrets                                             |

The expected count per file is `num_risk + num_informative`. Duplicate paths are rejected (fail-fast). The parser handles UTF-8 BOM and CRLF line endings.

#### Running the eval

```bash
eval-harness leaky-repo \
  --secrets-csv /path/to/secrets.csv \
  --findings findings.jsonl \
  --corpus-root /path/to/corpus
```

LeakyRepo only accepts `--findings` (no `--scan-corpus` support) and does not support `--baseline` regression comparison. The evaluation verdict exit code is always 0 (no regression gate); argument or runtime errors still produce exit code 2 (see [Exit Codes](#exit-codes)).

#### Comparison logic

For each file in the expectations CSV:

- **TP** = `min(expected, actual)` (correctly detected secrets)
- **FP** = `max(0, actual - expected)` (excess findings beyond expectation)
- **FN** = `max(0, expected - actual)` (missing secrets)

Findings for files not listed in the CSV are emitted with `expected = 0` (all counted as FP).

#### Limitations

- No confidence-aware metrics: AP is set to precision as a stand-in since count-based comparison cannot produce a ranked precision-recall curve.
- No error book: without positional annotations, individual FP/FN cannot be identified.
- No regression checking: the `--baseline` flag is not available.

## Interpreting Results

### Reading AP Scores

Average Precision (AP) is the primary ranking-quality metric. It measures how well the scanner's confidence scores separate true secrets from false positives:

- **AP = 1.0** — Perfect ranking: all true positives are ranked above all false positives.
- **AP = baseline_ap** — Confidence scores add no value; ranking is equivalent to random.
- **AP < baseline_ap** — Confidence scores are anti-correlated with truth (unusual in practice).

For secret scanning, AP above 0.90 is generally strong. Compare AP against `baseline_ap` to gauge whether confidence ranking adds value beyond the raw detection rate.

### Precision vs Recall Trade-offs

Secret scanning typically prioritizes recall (missed secrets are dangerous) over precision (false positives are annoying but not dangerous). The F2 score reflects this: it weights recall 4x more than precision.

- **High precision, low recall** — The scanner is conservative: it reports few false positives but misses real secrets. Consider lowering confidence thresholds or relaxing rule patterns.
- **Low precision, high recall** — The scanner is aggressive: it catches most secrets but generates noise. Consider tightening rule patterns or raising confidence thresholds.
- **P@R and R@P targets** — Check `precision_at_recall` to see what precision is achievable at 80%/90%/95% recall. Check `recall_at_precision` to see what recall is achievable at 95% precision.

### Regression Verdicts

When a `--baseline` is provided, the harness compares current metrics against the baseline:

| Verdict   | Meaning                                  | Default Threshold                             |
|-----------|------------------------------------------|-----------------------------------------------|
| **Pass**  | No meaningful regression detected        | AP drop < 0.5pp AND precision drop < 0.5pp    |
| **Warn**  | Small regression detected (non-blocking) | AP drop 0.5pp–2pp OR precision drop 0.5pp–2pp |
| **Block** | Significant regression detected          | AP drop ≥ 2pp OR precision drop ≥ 2pp         |

The **CI overlap gate** (enabled by default) provides a safety valve: if the baseline AP falls within the current run's bootstrap confidence interval, the drop is attributable to sampling noise and the check returns Pass regardless of the raw delta.

### Error Book

In JSON output mode, the `error_book` field lists the top false positives and false negatives grouped by rule, sorted by frequency descending. Each FP entry may include a context window around the detection span (optionally BLAKE3-redacted). With the current CLI defaults, `redacted_context` is usually `null` unless context output is explicitly enabled. Use this to identify:

- **Recurring FP patterns** — Rules that consistently fire on non-secrets (e.g., placeholder tokens, test fixtures).
- **Missing detections** — Truth items that no finding matched, indicating gaps in rule coverage.

### Bootstrap Confidence Intervals

The bootstrap CI quantifies uncertainty in the AP estimate from finite-sample effects. A wide CI (e.g., `[0.82, 0.96]`) means the AP estimate is unstable — small changes to the corpus could shift it substantially. A narrow CI (e.g., `[0.93, 0.95]`) means the estimate is reliable.

When comparing runs, check whether the CIs overlap. Overlapping CIs suggest the difference may not be statistically meaningful, which is why the regression gate uses CI overlap as a safety valve.

Default configuration: 1000 iterations, α=0.05 (95% CI), seed=42 (deterministic). For publication-quality intervals, increase iterations to 10,000.

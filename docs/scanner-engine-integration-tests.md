# Scanner Engine Integration Tests

Workspace integration tests for `scanner-engine`, `scanner-scheduler`, and
`scanner-git`. Exercises cross-crate boundaries, property-based invariants,
deterministic simulation replay, and regression corpora.

## Crate Structure

```
crates/scanner-engine-integration-tests/
  Cargo.toml
  src/lib.rs                          # Marker crate (no library code)
  tests/
    chunked_file_scans.rs             # Standalone: overlap + transform provenance
    integration/                      # ~162 tests: cross-crate integration
    property/                         # ~100 tests + ~30 proptest cases
    simulation/                       # ~41 tests: deterministic sim replay
    diagnostic/                       # 2 tests: anchor derivation diagnostics
    smoke/                            # Deferred (awaiting CLI binary name)
    corpus/                           # JSON replay artifacts + fixture files
      scanner/                        # Scanner case files
      scanner_mutation/               # Mutation testing corpus
      git_scan/                       # Git scan case files
      real_rules/                     # Real-rules baseline fixtures
      scheduler/                      # Scheduler case files
    regression/                       # Git pack regression corpus
    proptest-regressions/             # Saved proptest regression seeds
```

## Test Binaries

Each category is a separate test binary gated behind a Cargo feature:

| Binary          | Path                       | Feature Gate         | Tests |
| --------------- | -------------------------- | -------------------- | ----: |
| `integration`   | `tests/integration/main.rs`| `integration-tests`  |  ~162 |
| `property`      | `tests/property/main.rs`   | `property-tests`     |  ~130 |
| `simulation`    | `tests/simulation/main.rs` | various (see below)  |   ~41 |
| `diagnostic`    | `tests/diagnostic/main.rs` | `diagnostic-tests`   |     2 |
| `smoke`         | `tests/smoke/main.rs`      | `smoke-tests`        |     0 |
| *(standalone)*  | `tests/chunked_file_scans.rs` | *(none)*          |     2 |

## Feature Gates

| Feature              | Enables                                                     |
| -------------------- | ----------------------------------------------------------- |
| `integration-tests`  | Integration test binary                                     |
| `property-tests`     | Property test binary (implies `sim-harness`)                |
| `sim-harness`        | Scanner + git scan simulation tests                         |
| `scheduler-sim`      | Scheduler-only simulation tests                             |
| `real-rules-harness` | Real-ruleset baseline snapshot tests                        |
| `diagnostic-tests`   | Diagnostic test binary                                      |
| `smoke-tests`        | Smoke test binary (all tests currently deferred)            |
| `aegis-pure-rust`    | Pure-Rust AEGIS crypto backend (combinable with any above)  |

## Running Tests

```bash
# Integration tests
cargo test --features integration-tests --test integration

# Property-based tests
cargo test --features property-tests --test property

# Simulation: scheduler-only
cargo test --features scheduler-sim --test simulation

# Simulation: scanner + git scan
cargo test --features sim-harness --test simulation

# Simulation: real rules baseline
cargo test --features real-rules-harness --test simulation -- scanner_real_rules

# Simulation: all features combined
cargo test --features scheduler-sim,sim-harness --test simulation

# Diagnostic tests (most are #[ignore] by default)
cargo test --features diagnostic-tests --test diagnostic -- --ignored --nocapture

# Standalone chunked scan tests (no feature gate)
cargo test --test chunked_file_scans

# Update real rules golden file
cargo test --features real-rules-harness --test simulation -- \
    scanner_real_rules::update_baseline --ignored --nocapture

# Stress simulation with more seeds (env vars)
SCHEDULER_SIM_STRESS_SEEDS=1000 \
SCHEDULER_SIM_STRESS_MAX_STEPS=200 \
cargo test --features scheduler-sim --test simulation -- scheduler_sim_stress_smoke
```

## Integration Tests (`integration`)

Cross-crate integration tests exercising scanner-engine, scanner-scheduler, and
scanner-git boundaries.

| Module                     | Tests | Focus                                              |
| -------------------------- | ----: | -------------------------------------------------- |
| `anchor_optimization`      |    14 | Anchor derivation and optimization                 |
| `archive_scanning`         |    49 | Archive expansion, virtual paths, budget limits    |
| `bench_guards`             |     0 | Guards against benchmark execution without the benchmark feature gate (no active tests) |
| `binary_awareness`         |    10 | Binary file detection                              |
| `finding_json`             |     4 | JSONL finding parsing helpers used by integration assertions |
| `git_commit_walk`          |     6 | Commit graph traversal                             |
| `git_engine_adapter`       |     1 | Git-to-engine adapter                              |
| `git_inmem_artifacts`      |    13 | In-memory git artifact handling                    |
| `git_mapping_bridge`       |     3 | MIDX mapping bridge                                |
| `git_pack_exec`            |     1 | Pack execution                                     |
| `git_pack_inflate`         |     4 | Pack inflation/decompression                       |
| `git_pack_inflate_corpus`  |     5 | Pathological zlib regression corpus                |
| `git_pack_plan`            |    14 | Pack plan computation                              |
| `git_persist`              |     3 | Git persistence                                    |
| `git_preflight`            |     4 | Git preflight checks                               |
| `git_repo_open`            |     4 | Repository opening                                 |
| `git_run_format`           |     1 | Run format validation                              |
| `git_scan_validation`      |    10 | Git scan validation                                |
| `git_seen_unique`          |     2 | Deduplication of seen objects                      |
| `git_snapshot`             |     1 | Snapshot testing                                   |
| `git_tree_diff`            |    10 | Tree diff computation                              |
| `manual_anchors`           |     3 | Manual anchor specification                        |

## Property Tests (`property`)

Property-based tests using `proptest` for invariant checking. Each module
contains both deterministic `#[test]` assertions and `proptest!` fuzz runs.

| Module                               | Tests | Proptest | Focus                                 |
| ------------------------------------ | ----: | -------: | ------------------------------------- |
| `archive_entry_ratio`                |     3 |        2 | Archive entry ratio enforcement       |
| `archive_path_canonicalization`      |     5 |        1 | Archive path normalization            |
| `archive_sliding_window`             |     2 |        1 | Sliding window correctness            |
| `binary_classification`              |     5 |        2 | Binary vs. text classification        |
| `counterexample_determinism`         |     3 |        3 | Mutation counterexample determinism   |
| `counterexample_family_soundness`    |     5 |        4 | Family-constrained mutation soundness |
| `counterexample_shrinker`            |    10 |        1 | Custom MutationPlan shrinking         |
| `entropy_threshold_soundness`        |     9 |        1 | Entropy threshold boundaries          |
| `git_commit_walk`                    |     2 |        1 | Commit walk properties                |
| `git_engine_adapter`                 |     1 |        1 | Adapter correctness                   |
| `git_pack_delta`                     |     8 |        1 | Pack delta application                |
| `git_pack_plan`                      |     5 |        1 | Pack plan computation                 |
| `git_spill_dedupe`                   |     3 |        2 | Spill deduplication                   |
| `git_tree_diff`                      |     2 |        2 | Tree diff properties                  |
| `path_policy_soundness`              |     4 |        1 | Path allow/deny soundness             |
| `proptest_support`                   |     2 |        0 | Shared proptest helpers and shrinker guards |
| `regex2anchor_soundness`             |    26 |        2 | Regex-to-anchor derivation soundness  |
| `secret_bytes_safelist_soundness`    |     3 |        1 | Safelist soundness                    |
| `value_suppressor_soundness`         |     2 |        1 | Value suppression soundness           |

## Simulation Tests (`simulation`)

Deterministic simulation replay using the scanner, git, and scheduler sim
harnesses. Tests are feature-gated per subsystem.

| Module                      | Feature              | Tests | Focus                              |
| --------------------------- | -------------------- | ----: | ---------------------------------- |
| `scheduler_sim`             | `scheduler-sim`      |     3 | Scheduler determinism, corpus, stress |
| `scanner_random`            | `sim-harness`        |     1 | Random scanner scenario generation |
| `scanner_corpus`            | `sim-harness`        |     1 | Replay scanner corpus cases        |
| `scanner_archive_corpus`    | `sim-harness`        |    25 | Deterministic archive simulation   |
| `scanner_archive_random`    | `sim-harness`        |     1 | Random archive simulation          |
| `scanner_discovery`         | `sim-harness`        |     1 | Discovery simulation               |
| `scanner_max_file_size`     | `sim-harness`        |     1 | File size limit enforcement        |
| `scanner_budget_invariance` | `sim-harness`        |     1 | Budget invariance                  |
| `git_scan_corpus`           | `sim-harness`        |     1 | Git scan corpus replay             |
| `git_scan_random`           | `sim-harness`        |     1 | Random git scan simulation         |
| `git_scan_shallow_limits`   | `sim-harness`        |     1 | Shallow clone limits               |
| `scanner_mutation_random`   | `sim-harness`        |     1 | Random mutation testing             |
| `scanner_mutation_corpus`   | `sim-harness`        |     1 | Mutation corpus replay             |
| `scanner_real_rules`        | `real-rules-harness` |     2 | Real-ruleset baseline snapshot     |

## Corpus Layout

### Scanner Corpus (`tests/corpus/scanner/`)

71 `*.case.json` files, each a complete `ReproArtifact` containing:
- `scenario.fs.nodes` — virtual filesystem definition
- `scenario.rule_suite.rules` — detection rules with regex, anchors, name
- `scenario.expected` — ground-truth findings (path, rule_id, root_span, repr)
- `run_config` — chunk_size, overlap, workers
- `fault_plan` — injected faults for simulation
- `schedule_seed` — deterministic RNG seed

### Git Scan Corpus (`tests/corpus/git_scan/`)

11 `*.case.json` files, each a `GitReproArtifact` covering merge commits,
force pushes, gitlinks, watermarks, and SHA-256 repos.

### Scheduler Simulation Corpus (`tests/simulation/corpus/`)

8 JSON artifacts with `exec_cfg`, `programs`, `tasks`, `driver_choices`, and
`expected_trace_hash` (64-bit SHA-256 prefix for deterministic replay
verification).

### Real Rules Corpus (`tests/corpus/real_rules/`)

30 fixture files across 13 categories (boundary, doc, encoding, env, infra, ini,
json, logs, multiline, noise, source, toml, yaml) with a golden
`expected/findings.json` baseline. All tokens are synthetic.

### Git Pack Regression (`tests/regression/git_packs/`)

10 synthetic `.pack` files covering pack parsing edge cases: corrupt headers,
truncated zlib, deep delta chains. Regenerate with
`python3 scripts/gen_git_pack_corpus.py`.

## Dependencies

All dependencies are dev-only (this crate has no library code):

| Crate              | Purpose                                        |
| ------------------ | ---------------------------------------------- |
| `scanner-engine`   | Primary system under test (`test-support` feat) |
| `scanner-scheduler`| Pipeline and simulation harness                |
| `scanner-git`      | Git scanning subsystem                         |
| `gossip-stdx`      | Shared data structures                         |
| `proptest`         | Property-based testing framework               |
| `base64`           | Transform test support                         |
| `flate2`           | Gzip compression for archive tests             |
| `zip`              | ZIP archive creation (deflate only)            |
| `crc32fast`        | CRC32 for synthetic ZIP archives               |
| `tempfile`         | Temporary files for integration tests          |
| `serde` / `serde_json` | Corpus JSON parsing                       |

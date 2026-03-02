# Counterexample Testing Unification

## Purpose

This document inventories every testing approach in the repository, maps
overlap between encoding/mutation and infrastructure, records keep/merge/migrate
decisions for each component, defines a deterministic contract for a shared
mutation core, and lays out a phased rollout plan. It is the Phase 0
deliverable of the Counterexample Testing Unification epic (`scratch-gs8l`).

---

## 1. Existing Coverage Inventory

| #   | Area                    | Location                                   | LOC     | Feature Gate         | Tests What                                                  |
|-----|-------------------------|--------------------------------------------|---------|----------------------|-------------------------------------------------------------|
| 1   | Property tests          | `tests/property/` (19 files)               | ~5,032  | `property-tests`     | Mathematical invariants (soundness, determinism, roundtrip) |
| 2   | Simulation tests        | `tests/simulation/` (13 `.rs` files)       | ~3,059  | `sim-harness` etc.   | System-level behavior (scheduling, chunking, faults)        |
| 3   | Corpus replay — scanner | `tests/corpus/scanner/` (71 `.case.json`)  | N/A     | `sim-harness`        | Deterministic regression replay                             |
| 4   | Corpus replay — git     | `tests/corpus/git_scan/` (11 `.case.json`) | N/A     | `sim-harness`        | Git deterministic regression replay                         |
| 5   | Scanner sim module      | `src/sim_scanner/` (7 files)               | ~3,550  | `sim-harness`        | Scenario generation, runner, oracles                        |
| 6   | Git sim module          | `src/sim_git_scan/` (18 files)             | ~4,171  | `sim-harness`        | Git repo model generation, stage pipeline                   |
| 7   | Shared sim infra        | `src/sim/` (9 files)                       | ~1,745  | `sim-harness`        | RNG, fault injection, minimization, executor                |
| 8   | Offline validators      | `src/engine/offline_validate.rs`           | 1,877   | None                 | Structural token validation                                 |
| 9   | YAML unit tests         | `src/rules/yaml_unit_tests.rs`             | 2,262   | None                 | Rule parsing/scanning roundtrip                             |
| 10  | Integration tests       | `tests/integration/` (26 files)            | ~10,276 | `integration-tests`  | Handcrafted regression tests                                |
| 11  | Fuzz targets            | `fuzz/fuzz_targets/` (19 targets)          | Varies  | Nightly              | Coverage-guided mutation                                    |
| 12  | Real-rules harness      | `tests/simulation/scanner_real_rules.rs`   | 278     | `real-rules-harness` | Golden baseline comparison                                  |
| 13  | Smoke tests             | `tests/smoke/` (3 files)                   | Small   | `smoke-tests`        | End-to-end sanity                                           |
| 14  | Diagnostic tests        | `tests/diagnostic/` (4 files)              | Small   | `diagnostic-tests`   | Allocation and runtime diagnostics                          |

### 1.1 Property Tests

Nineteen files in `tests/property/` exercise component-level mathematical
invariants using `proptest`. Each file targets a specific subsystem: anchor
soundness (`regex2anchor_soundness.rs`), entropy thresholds
(`entropy_threshold_soundness.rs`), binary classification
(`binary_classification.rs`), git pack delta application (`git_pack_delta.rs`),
path policy (`path_policy_soundness.rs`), and others. Gated behind
`property-tests` and `stdx-proptest`. Run as `cargo test --features
property-tests,stdx-proptest --test property`. No mutation/encoding logic —
these verify mathematical properties of pure functions.

### 1.2 Simulation Tests

Thirteen test files in `tests/simulation/` drive the scanner and git simulation
harnesses. Scanner variants include random stress (`scanner_random.rs`), corpus
replay (`scanner_corpus.rs`), archive-specific random and corpus tests, budget
invariance, discovery, and max-file-size. Git variants include random stress
(`git_scan_random.rs`), corpus replay (`git_scan_corpus.rs`), and shallow
limits. A scheduler simulation (`scheduler_sim.rs`) tests scheduling logic in
isolation. All simulation tests use deterministic seeded RNG and are gated
behind `sim-harness`.

### 1.3 Corpus Replay

Seventy-one scanner `.case.json` files and eleven git-scan `.case.json` files
in `tests/corpus/`. Each case is a serialized scenario + fault plan + schedule
seed that deterministically replays in milliseconds. New failures discovered by
random simulation are minimized and added here. This is the fastest regression
gate.

### 1.4 Scanner Sim Module

Seven source files in `src/sim_scanner/`. The generator (`generator.rs`, 605
lines) builds deterministic in-memory filesystems with embedded secrets. The
runner (`runner.rs`, 2,412 lines) implements the chunked-scanning event loop
with seven oracles: termination, monotonic progress, overlap dedup, duplicate
suppression, in-flight budget, ground-truth, and differential. Scenario types,
replay, and virtual path tables round out the module.

### 1.5 Git Sim Module

Eighteen source files in `src/sim_git_scan/`. The generator builds synthetic
git repository models (commit graphs, tree entries, pack files). The runner
(`runner.rs`, 1,506 lines) executes a five-stage pipeline (`RepoOpen →
CommitWalk → TreeDiff → PackExec → Finalize`) and validates output shape
(sorted/disjoint OID sets) and stability across schedule seeds. Additional
modules handle pack byte serialization, commit-graph construction, fault
injection, and persistence.

### 1.6 Shared Sim Infra

Nine files in `src/sim/`: `rng.rs` (deterministic xorshift64*), `fault.rs`
(path-keyed fault plans), `fs.rs` (in-memory filesystem), `executor.rs`
(deterministic task scheduler), `trace.rs` (bounded ring trace), `clock.rs`
(simulated clock), `artifact.rs` (reproduction artifacts), and `minimize.rs`
(scanner-side deterministic minimizer with greedy shrink passes).

### 1.7 Offline Validators

`src/engine/offline_validate.rs` (1,877 lines) provides structural token
validation: length checks, charset constraints, checksum verification, and
entropy gates. Thirty-nine `#[test]` functions with hand-authored test
vectors. No mutation — vectors are static byte slices.

### 1.8 YAML Unit Tests

`src/rules/yaml_unit_tests.rs` (2,262 lines) tests rule parsing and single-rule
scanning via roundtrip assertions. Each test constructs a rule from YAML,
compiles it, and scans a test string. No mutation — inputs are string literals.

### 1.9 Integration Tests

Twenty-six files in `tests/integration/` covering handcrafted regression
scenarios. Each file targets a specific behavior area (chunking, dedup,
transforms, multi-rule interaction). Gated behind `integration-tests`. Inputs
are manually constructed byte sequences. Clear, readable, but labor-intensive to
extend.

### 1.10 Fuzz Targets

Nineteen targets in `fuzz/fuzz_targets/` using `cargo-fuzz`/libFuzzer.
Coverage-guided mutation across anchor soundness, base64 gate ops, pack parsing,
offline validators, SIMD classification, text sanitization, and more. Run on
nightly; not in CI default gate.

### 1.11 Real-Rules Harness

`tests/simulation/scanner_real_rules.rs` (278 lines) scans curated fixtures
at `tests/corpus/real_rules/fixtures/` with production rules from
`default_rules.yaml` and compares findings against a golden baseline at
`tests/corpus/real_rules/expected/findings.json`. Gated behind
`real-rules-harness`. Fixtures are hand-authored; no mutation generation.

### 1.12 Smoke Tests

Three files in `tests/smoke/` providing end-to-end sanity checks for the
scanner and git-scan pipelines. Fast, minimal, gated behind `smoke-tests`.

### 1.13 Diagnostic Tests

Four files in `tests/diagnostic/` checking runtime properties like
post-startup allocation behavior and unfilterable rule analysis. Gated behind
`diagnostic-tests`.

---

## 2. Overlap and Duplication Matrix

### 2.1 Encoding/Mutation Capabilities

| Capability                  | Scanner Sim            | Git Sim  | Property | Real-Rules      | Offline Validators | Fuzz                 |
|-----------------------------|------------------------|----------|----------|-----------------|--------------------|----------------------|
| Base64 encode               | `generator.rs:536-564` | —        | —        | Manual fixtures | Static vectors     | `fuzz_b64_gate_*`    |
| URL percent encode          | `generator.rs:525-533` | —        | —        | —               | —                  | —                    |
| UTF-16 LE/BE encode         | `generator.rs:575-589` | —        | —        | —               | —                  | —                    |
| Nested (alternating layers) | `generator.rs:508-522` | —        | —        | —               | —                  | —                    |
| Near-miss mutation          | **NONE**               | **NONE** | **NONE** | **NONE**        | **NONE**           | Coverage-guided only |
| Representation selection    | `generator.rs:494-503` | —        | —        | —               | —                  | —                    |
| Token generation            | `generator.rs:467-476` | —        | —        | —               | —                  | —                    |

**Key finding**: encoding functions in `src/sim_scanner/generator.rs` (lines
494–589) are the ONLY place systematic secret transforms happen. No near-miss
mutation operators exist anywhere in the codebase. Fuzz targets apply
coverage-guided byte mutation but without semantic awareness of token structure.

### 2.2 Infrastructure Components

| Component         | Scanner Sim                                  | Git Sim                                               | Shared?                              |
|-------------------|----------------------------------------------|-------------------------------------------------------|--------------------------------------|
| Deterministic RNG | `sim/rng.rs:SimRng`                          | Same                                                  | **Yes** — already in `src/sim/`      |
| Fault plan        | `sim/fault.rs:FaultPlan` (path-keyed)        | `sim_git_scan/fault.rs:GitFaultPlan` (resource-keyed) | **No** — domain-specific keying      |
| Minimizer         | `sim/minimize.rs` (greedy shrink, 777 lines) | `sim_git_scan/minimize.rs` (graph-aware, 408 lines)   | **No** — different shrink strategies |
| Trace ring        | `sim/trace.rs`                               | `sim_git_scan/trace.rs`                               | **No** — different event types       |
| Executor          | `sim/executor.rs:SimExecutor`                | Same                                                  | **Yes** — already in `src/sim/`      |
| Artifact format   | `sim/artifact.rs:ReproArtifact`              | `sim_git_scan/artifact.rs:GitReproArtifact`           | **No** — different payload shapes    |

Encoding/decoding is domain-independent (byte transforms on secrets). Infrastructure
components are appropriately split: shared when the interface is identical (RNG,
executor), separate when domain constraints differ (fault keying, minimization
strategy, trace event types).

---

## 3. Design Reasoning

### 3.1 Unified Mutation Model, Separate Harnesses

Encoding transforms (base64, URL-percent, UTF-16, nested) are pure byte-to-byte
functions with no dependency on scanner or git domain logic. They belong in a
shared module.

Harnesses are domain-specific and must remain separate:

- **Scanner sim**: chunked I/O with overlap dedup, 7 oracles
  (`runner.rs`:2,412 lines), path-keyed `FaultPlan`, in-memory filesystem.
- **Git sim**: five-stage pipeline (`RepoOpen → CommitWalk → TreeDiff →
  PackExec → Finalize`), output-shape and stability oracles
  (`runner.rs`:1,506 lines), resource-keyed `GitFaultPlan`, commit-graph model.

The harness boundary is where domain-specific scheduling, fault injection, and
oracle verification happen. The mutation boundary is where domain-independent
byte transforms happen. These are cleanly separable.

### 3.2 Complementary Simulation + Property Tests

Property tests and simulation tests operate at different abstraction layers and
are complementary, not redundant:

- **Property tests** verify component-level mathematical invariants:
  regex-to-anchor soundness, entropy threshold monotonicity, base64 gate
  roundtrip, path policy prefix closure. Each test is self-contained and
  exercises a single function's contract.
- **Simulation tests** verify system-level emergent behavior: the interaction of
  chunking + overlap dedup + transform decoding + fault injection + scheduling
  nondeterminism. These properties only emerge when multiple components compose.

Neither subsumes the other. A property test cannot catch a chunking boundary
bug; a simulation cannot efficiently enumerate entropy threshold corner cases.

### 3.3 Deterministic Replay as Primary Gate

The 84 corpus `.case.json` files (72 scanner + 12 git) are the fastest
regression path:

- Each case replays in single-digit milliseconds.
- Cases are deterministic: same input, same schedule seed, same output.
- New failures discovered by random simulation or fuzz targets are minimized
  and added to the corpus, converting expensive discovery into cheap replay.

More expensive tests (random simulation, property tests, fuzz targets) serve as
*discovery* mechanisms. The corpus serves as the *regression gate*. This
two-tier model keeps CI fast while maintaining coverage depth.

### 3.4 LLM Generation — Artifact-Only

CI must be deterministic, fast, and network-independent. If LLM-generated
fixtures are ever introduced:

- LLM output is serialized as static fixture files and committed to the
  repository.
- Fixtures are reviewed like any other code change.
- CI treats LLM-authored fixtures identically to hand-authored ones.
- No LLM calls happen during `cargo test`.
- The generation script (if any) is a developer tool, not a CI dependency.

---

## 4. Keep/Merge/Migrate Mapping

| Current Component       | Location                                    | Purpose                      | Action             | Target                          | Rationale                                              |
|-------------------------|---------------------------------------------|------------------------------|--------------------|---------------------------------|--------------------------------------------------------|
| `encode_secret()`       | `generator.rs:494-503`                      | Dispatch raw→representation  | **Migrate**        | `src/sim/mutation.rs`           | Domain-independent; reusable by git sim and real-rules |
| `base64_encode_std()`   | `generator.rs:536-564`                      | Base64 standard encoding     | **Migrate**        | `src/sim/mutation.rs`           | Pure byte transform                                    |
| `percent_encode_all()`  | `generator.rs:525-533`                      | URL percent encoding         | **Migrate**        | `src/sim/mutation.rs`           | Pure byte transform                                    |
| `encode_utf16()`        | `generator.rs:575-589`                      | UTF-16 LE/BE widening        | **Migrate**        | `src/sim/mutation.rs`           | Pure byte transform                                    |
| `encode_nested()`       | `generator.rs:508-522`                      | Alternating layer nesting    | **Migrate**        | `src/sim/mutation.rs`           | Pure byte transform                                    |
| `hex_nibble()`          | `generator.rs:566-572`                      | Nibble→hex helper            | **Migrate**        | `src/sim/mutation.rs`           | Dependency of `percent_encode_all`                     |
| `SecretRepr`            | `scenario.rs:96-104`                        | Encoding representation enum | **Migrate**        | `src/sim/mutation.rs`           | Domain-independent type                                |
| `make_token()`          | `generator.rs:467-476`                      | Rule prefix + random tail    | **Keep**           | `src/sim_scanner/generator.rs`  | Scanner-specific format (SIM{id}_...)                  |
| `generate_scenario()`   | `sim_scanner/generator.rs`                  | Full scanner scenario        | **Keep**           | `src/sim_scanner/generator.rs`  | Domain-specific orchestration                          |
| `generate_scenario()`   | `sim_git_scan/generator.rs`                 | Full git scenario            | **Keep**           | `src/sim_git_scan/generator.rs` | Domain-specific orchestration                          |
| `SimRng`                | `sim/rng.rs`                                | Deterministic RNG            | **No change**      | Already in `src/sim/`           | Already correct location                               |
| `SimExecutor`           | `sim/executor.rs`                           | Deterministic scheduler      | **No change**      | Already in `src/sim/`           | Already correct location                               |
| `FaultPlan`             | `sim/fault.rs`                              | Scanner fault injection      | **Keep**           | `src/sim/fault.rs`              | Path-keyed, scanner-specific                           |
| `GitFaultPlan`          | `sim_git_scan/fault.rs`                     | Git fault injection          | **Keep**           | `src/sim_git_scan/fault.rs`     | Resource-keyed, git-specific                           |
| Scanner minimizer       | `sim/minimize.rs` (777 lines)               | Greedy shrink passes         | **Keep**           | `src/sim/minimize.rs`           | Domain-specific shrink logic                           |
| Git minimizer           | `sim_git_scan/minimize.rs` (408 lines)      | Graph-aware shrink           | **Keep**           | `src/sim_git_scan/minimize.rs`  | Graph-aware, git-specific                              |
| Scanner corpus          | `tests/corpus/scanner/` (72 cases)          | Regression replay            | **Keep**           | Same                            | Canonical fast gate                                    |
| Git corpus              | `tests/corpus/git_scan/` (12 cases)         | Regression replay            | **Keep**           | Same                            | Canonical fast gate                                    |
| Near-miss operators     | **DO NOT EXIST**                            | —                            | **Create**         | `src/sim/mutation.rs`           | Core new capability                                    |
| Property tests          | `tests/property/` (19 files)                | Math invariants              | **Keep**           | Same                            | Different abstraction layer                            |
| Offline validator tests | `src/engine/offline_validate.rs` (39 tests) | Validator vectors            | **Keep + Augment** | Same + mutation-derived vectors | Add near-miss vectors in Phase 3                       |
| Integration tests       | `tests/integration/` (26 files)             | Handcrafted regression       | **Keep**           | Same                            | Clear, readable, stable                                |
| Real-rules fixtures     | `tests/corpus/real_rules/`                  | Curated corpus               | **Keep + Augment** | Same + near-miss fixtures       | Add near-miss fixtures in Phase 3                      |
| Fuzz targets            | `fuzz/fuzz_targets/` (19 targets)           | Coverage-guided              | **Keep**           | Same                            | Complementary discovery mechanism                      |

---

## 5. Deterministic Contract

The shared mutation core must satisfy a strict deterministic contract.

### 5.1 Interface

```
Inputs:
  family:       TokenFamily       — structural category of the secret
  base_seed:    u64               — seed for deterministic RNG
  op_seq:       Vec<MutationOp>   — ordered mutation/encoding pipeline
  context_wrap: Option<ContextWrap> — surrounding context (e.g. JSON key, YAML value)

Outputs:
  mutated_bytes:    Vec<u8>       — final byte sequence
  expected_outcome: Outcome       — expected detection result
```

### 5.2 Invariants

**DETERMINISM**: Given identical `(family, base_seed, op_seq, context_wrap)`,
the output is byte-for-byte identical across runs, platforms, and Rust
versions. No `HashMap` iteration, no system randomness, no floating point.

**ISOLATION**: Each mutation call is stateless. No global mutable state, no
thread-locals, no ambient configuration.

**SEED STABILITY**: The RNG is `SimRng` (xorshift64\* with multiplier
`0x2545F4914F6CDD1D`, zero-seed remapped to `0x9E3779B97F4A7C15`). The
algorithm and constants are frozen. Any change to the RNG breaks all
corpus artifacts and requires a full re-minimization pass.

Reference implementation (`src/sim/rng.rs:22-29`):
```rust
pub fn next_u64(&mut self) -> u64 {
    let mut x = self.state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    self.state = x;
    x.wrapping_mul(0x2545F4914F6CDD1D)
}
```

**ENCODING PURITY**: Every encoding function is a pure function from
`&[u8] → Vec<u8>`. No side effects, no RNG consumption, no allocation
beyond the output buffer.

**EXPECTED OUTCOME**: Each mutation produces an `Outcome`:
- `MustMatch` — the engine must detect this token (positive case).
- `MustNotMatch` — the engine must NOT detect this token (negative/near-miss).
- `MayMatch` — indeterminate; useful for stress testing but not gated.

**SERIALIZATION**: All types derive `serde::Serialize` and
`serde::Deserialize`. Corpus artifacts round-trip through JSON without loss.

### 5.3 Proposed Types

```rust
/// Token structural family. Determines which mutation operators are valid.
enum TokenFamily {
    GenericAlphanumeric,
    HexEncoded,
    Base62Crc,
    GitHubPat,
    AwsAccessKey,
    // Extend per rule family
}

/// Individual mutation/encoding operation.
enum MutationOp {
    /// Truncate to N bytes.
    Truncate { len: usize },
    /// Replace chars outside target charset with ASCII fallback.
    CharsetDegrade { target_charset: Charset },
    /// Shift a positional boundary by delta bytes.
    BoundaryShift { boundary: Boundary, delta: i32 },
    /// Reduce Shannon entropy below detection threshold.
    EntropyReduce { target_bits: f32 },
    /// Corrupt an embedded checksum.
    ChecksumCorrupt,
    /// Mangle a known prefix (e.g. "ghp_" → "ghx_").
    PrefixMangle,
    /// Apply an encoding transform.
    Encode { repr: SecretRepr },
    /// Apply nested encoding layers.
    Nest { depth: u8 },
}

/// Expected detection outcome.
enum Outcome {
    MustMatch,
    MustNotMatch,
    MayMatch,
}
```

### 5.4 Worked Example: AWS Access Key Near-Miss

An AWS access key has the form `AKIA[A-Z0-9]{16}`. A `CharsetDegrade`
near-miss:

1. Start: `AKIAIOSFODNN7EXAMPLE` (valid, `MustMatch`)
2. Apply `CharsetDegrade { target_charset: Lowercase }`:
   Replace uppercase chars with lowercase → `akiaiosfodnn7example`
3. Result: lowercase string no longer matches `AKIA[A-Z0-9]{16}` → `MustNotMatch`

The mutation is deterministic (no RNG needed for this op), produces a
structurally similar but invalid token, and has a clear expected outcome.

---

## 6. Phase-by-Phase Rollout

### Phase 1: Extract Shared Mutation Core (`scratch-gs8l.2`)

- Create `src/sim/mutation.rs` with migrated encoding functions and the
  `SecretRepr` enum.
- Add near-miss mutation operators: `Truncate`, `CharsetDegrade`,
  `BoundaryShift`, `EntropyReduce`, `ChecksumCorrupt`, `PrefixMangle`.
- Thin shims in `sim_scanner/generator.rs` delegate to the shared module.
- All existing corpus artifacts and tests pass unchanged.
- Acceptance: `cargo test --features sim-harness` passes with zero delta.

### Phase 2: Integrate Near-Miss into Scanner Sim

- Add `near_miss_count: u32` field to `ScenarioGenConfig` (default 0).
- Generator produces `MustNotFind`-disposition secrets using near-miss
  operators when `near_miss_count > 0`.
- Runner validates that near-miss secrets are NOT found (new oracle check).
- New random sim seeds exercise near-miss scenarios.
- Minimized failures added to corpus.

### Phase 3: Augment Real-Rules Fixtures and Offline Validators

- Generate near-miss fixtures for `tests/corpus/real_rules/fixtures/` using
  the mutation core. Commit as static files.
- Add mutation-derived vectors to `offline_validate.rs` tests — particularly
  for charset, length, and checksum boundary conditions.
- Update golden baseline if new fixtures alter expected findings.

### Phase 4 (Optional): Proptest Strategies + Fuzz Target

- Create `proptest` strategies that compose `MutationOp` sequences.
- Property: for any seed and op sequence, the output is deterministic.
- Property: encoding-only op sequences produce `MustMatch` outcomes.
- New fuzz target: `fuzz_mutation_pipeline.rs` for coverage-guided mutation
  op sequence exploration.

### Phase 5 (Optional, Future): LLM Fixture Generation Contract

- Document the format for LLM-generated fixture files.
- Provide a generation script that calls an LLM, serializes output, and
  writes `.fixture.json` files.
- No CI dependency on LLM availability.
- This phase is documentation-only; implementation deferred.

---

## 7. Edge Cases

1. **Chunk-boundary transforms**: A base64-encoded secret may span a chunk
   boundary after encoding but not before (or vice versa). The mutation core
   must compute expected outcome based on the *encoded* byte length, not the
   raw length. The scanner sim's overlap-dedup oracle already handles
   cross-chunk findings; near-miss tests must exercise this boundary.

2. **Non-root findings and `SCANNER_SIM_STRICT_NON_ROOT`**: Transform-decoded
   findings are non-root. The differential oracle only compares non-root
   findings when `SCANNER_SIM_STRICT_NON_ROOT=1`. Near-miss mutations on
   encoded secrets must respect this flag — a `MustNotMatch` near-miss inside
   a base64 layer should not cause a failure when strict non-root is off.

3. **UTF-16/nested depth interaction**: `encode_utf16` doubles byte length;
   `encode_nested` alternates base64 and percent-encoding. Composing both
   can produce very large outputs. The mutation contract should cap maximum
   output size (e.g., 64 KiB) and return `MayMatch` for capped results.

4. **Tokens valid only after encoding**: Some mutation + encoding sequences
   might accidentally produce a valid token for a *different* rule. The
   `expected_outcome` must be computed against the specific rule under test.
   Cross-rule false positives are `MayMatch`, not `MustNotMatch`.

5. **Conservative indeterminate for unknown families**: For `TokenFamily`
   variants where we lack structural knowledge, near-miss operators that
   depend on structure (e.g., `ChecksumCorrupt`) should return `MayMatch`
   rather than `MustNotMatch`.

6. **Archive corruption interaction**: Scanner sim injects archive corruption
   faults. If a near-miss secret is inside an archive entry and the archive is
   corrupted, the entry may not be extracted at all. The expected outcome
   depends on whether the entry was successfully inflated — use the existing
   `ExpectedDisposition` machinery to handle this.

7. **Entropy gate interaction**: The `EntropyReduce` operator intentionally
   lowers Shannon entropy. If the engine's entropy gate rejects the token
   before rule matching, the outcome is `MustNotMatch`. But the threshold is
   rule-specific. The operator must consult the `TokenFamily`'s entropy
   floor to produce correct expectations.

---

## 8. Risk/Rollback Strategy

| Risk                          | Likelihood | Impact                      | Mitigation                                                                                                                                                      |
|-------------------------------|------------|-----------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Serde compatibility break     | Low        | High (all corpus artifacts) | Variant names for `SecretRepr` unchanged during migration. `MutationOp` is new, no existing artifacts to break. Add serde roundtrip test in Phase 1.            |
| False failures from near-miss | Medium     | Medium (CI noise)           | `near_miss_count` defaults to 0; existing tests unaffected. Near-miss tests are additive. New failures are always minimized before corpus addition.             |
| Kitchen-sink module           | Medium     | Low (maintenance)           | 500-line split threshold: if `mutation.rs` exceeds 500 lines, factor encoding and near-miss ops into submodules (`mutation/encode.rs`, `mutation/nearmiss.rs`). |

**Rollback**: Each phase is independently revertible.

- Phase 1: revert `src/sim/mutation.rs` creation, restore inline functions in
  `generator.rs`. No corpus changes.
- Phase 2: remove `near_miss_count` from config, remove new oracle check.
  Corpus additions are additive and can be deleted.
- Phase 3: delete generated fixtures, revert baseline. Offline validator
  vector additions are additive.

---

## 9. Validation Commands

### Phase 0 Validation (This Document)

Verify that all existing test suites pass before any code changes:

```bash
# Property tests
cargo test --features property-tests,stdx-proptest --test property

# Scanner corpus replay
cargo test --features sim-harness --test simulation scanner_corpus

# Git corpus replay
cargo test --features sim-harness --test simulation git_scan_corpus

# Scanner random simulation (single seed)
cargo test --features sim-harness --test simulation scanner_random

# Integration tests
cargo test --features integration-tests --test integration

# Offline validator tests
cargo test --lib offline_validate

# YAML unit tests
cargo test --lib yaml_unit_tests
```

Record pass counts as the baseline for Phase 1 regression checks.

### Phase 0 Results

Property tests (2025-02-25, branch `feature/test-unification-doc`):
```
test result: ok. 81 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

Scanner corpus replay (2025-02-25):
```
test result: FAILED. 0 passed; 1 failed; 0 ignored
  — b64_internal_newline.case.json: "overlap (512) must not exceed chunk_size (64)"
  — Pre-existing failure; not introduced by this document.
```

---

## 10. References

### Source Files

| File                                     | Relevance                                                            |
|------------------------------------------|----------------------------------------------------------------------|
| `src/sim_scanner/generator.rs`           | Encoding functions (lines 494–589), token generation (lines 467–476) |
| `src/sim_scanner/scenario.rs`            | `SecretRepr` enum (lines 96–104), `ExpectedDisposition`              |
| `src/sim_scanner/runner.rs`              | Scanner oracles (7), chunked scanning event loop                     |
| `src/sim_git_scan/runner.rs`             | Git stage pipeline, output-shape validation                          |
| `src/sim_git_scan/fault.rs`              | `GitFaultPlan`, `GitResourceId` (resource-keyed)                     |
| `src/sim/rng.rs`                         | `SimRng` xorshift64* implementation                                  |
| `src/sim/fault.rs`                       | `FaultPlan` (path-keyed)                                             |
| `src/sim/minimize.rs`                    | Scanner minimizer (greedy shrink passes)                             |
| `src/sim_git_scan/minimize.rs`           | Git minimizer (graph-aware shrink)                                   |
| `src/sim/executor.rs`                    | `SimExecutor` deterministic scheduler                                |
| `src/engine/offline_validate.rs`         | Structural token validators                                          |
| `src/rules/yaml_unit_tests.rs`           | Rule parsing/scanning roundtrip                                      |
| `tests/simulation/scanner_real_rules.rs` | Real-rules golden baseline harness                                   |

### Documentation

| Document                               | Relevance                                        |
|----------------------------------------|--------------------------------------------------|
| `docs/scanner_harness_modes.md`        | Synthetic vs real-rules mode comparison          |
| `docs/scanner_test_harness_guide.md`   | Synthetic harness usage guide                    |
| `docs/git_simulation_harness_guide.md` | Git simulation harness guide                     |
| `docs/detection-engine.md`             | Engine architecture (transform pipeline context) |
| `docs/engine-transforms.md`            | Transform chain design (encoding context)        |
| `docs/kani-verification.md`            | Formal verification approach                     |

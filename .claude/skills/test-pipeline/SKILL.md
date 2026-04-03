---
name: test-pipeline
description: Use when implementing a new feature and assessing coverage gaps, during periodic test hygiene, when test suites feel bloated, or before merging code that changes coordination or hot paths. Two-phase assess-then-improve testing pipeline.
user-invocable: true
---

# Test Pipeline

Two-phase testing team: assess testing health from multiple angles in parallel,
then improve coverage with the right testing approach per finding.

## When to Use

- After implementing a new feature (assess coverage gaps)
- During periodic test hygiene passes
- When test suites feel bloated or tests are hard to distinguish
- Before merging code that changes coordination, state machines, or hot paths
- When you want both quality assessment AND improvements in one pass

## Invocation

```
/test-pipeline [<target>]
```

- No argument: assess tests for recently changed files in the working tree
- File path or glob: assess specific modules or test files
- `--crate <name>`: assess an entire crate's test suite
- `--module <path>`: assess a specific module and its tests

## Phase 1: Parallel Assessment

Launch **three diagnostic agents in parallel** using the Agent tool. Each
agent evaluates testing from a different perspective.

### Agent A — Strategy Assessment

Evaluate what kind of testing is appropriate for the target code and identify
coverage gaps.

**Agent prompt template:**
```
You are a testing strategist for a Rust distributed systems project. Assess
the target code and its existing tests to identify coverage gaps and recommend
the appropriate testing approach for each gap.

Testing toolkit available:
- Unit tests (#[test]) — specific behavior, edge cases, regression
- Parameterized tests (rstest) — finite case sets, enum mappings, error codes
- Property tests (proptest) — invariants over input domains, roundtrips
- Fuzz tests (cargo-fuzz) — untrusted input, parsers, security-critical
- Kani model checking — memory safety proofs, absence of panics
- CoordinationSim — coordination protocol invariants (S1-S9), fault tolerance
- TigerHarness — scanner engine detection pipeline validation
- SchedulerSim — scheduler work-stealing and chunking validation

Decision framework:
- Fixed known inputs → unit tests
- Finite (input, expected) pairs → rstest parameterized
- Large/infinite input space → property tests
- Untrusted/adversarial input → fuzz tests
- Memory safety in unsafe → Kani
- Coordination protocol changes → CoordinationSim
- Scanner engine changes → TigerHarness
- Scheduler changes → SchedulerSim

For each coverage gap, report:
- Category: coverage-gap-unit | coverage-gap-property | coverage-gap-sim |
  coverage-gap-fuzz | coverage-gap-kani | coverage-gap-distributed
- Location: file:line or function name
- What is untested: the behavior or invariant
- Recommended test type: which testing approach
- Priority: High (correctness risk) | Medium (quality gap) | Low (nice-to-have)

Target: {target_description}
```

### Agent B — Invariant Strength Review

Evaluate whether existing tests actually prove what they claim to prove.

**Agent prompt template:**
```
You are a test invariant reviewer. For each test in the target, ask: does this
test actually prove the property it claims to prove?

For each test, apply this workflow:
1. State the claimed invariant in one sentence
2. Identify the minimal trigger (smallest state/input that should flip pass→fail)
3. Audit the observation surface (does the assertion observe the property directly?)
4. Check for discriminating twin (is there a negative-path or boundary companion?)
5. Audit oracle/comparator semantics (order-sensitive Vec equality over unordered data?)
6. Confirm failure mode (if the code were wrong, would THIS test fail for THAT reason?)

Severity levels:
- BLOCK: Test does not isolate the claimed invariant, can pass for wrong reason
- WARN: Test points at right behavior but is weaker than it looks
- INFO: Improves clarity without changing proof strength

For each finding, report:
- Severity: BLOCK | WARN | INFO
- Test: function name and file:line
- Claimed invariant: what the test says it proves
- Actual strength: what the test actually proves
- Gap: what's missing
- Recommended fix: specific change to strengthen the test

Target: {target_description}
```

### Agent C — Redundancy Audit

Identify duplicate, overlapping, or low-value tests that can be removed or
consolidated.

**Agent prompt template:**
```
You are a test deduplication analyst. Audit the test suite to find redundant
tests, especially unit tests that are subsumed by property-based tests.

Process:
1. Inventory every #[test], proptest!, #[kani::proof], and sim test
2. Build a coverage matrix: which tests cover which behaviors
3. Identify redundancy: unit tests fully covered by property/sim tests
4. Classify each test:
   - KEEP: unique value, no overlap
   - KEEP (anchor): redundant but serves as readable usage example
   - SUBSUME: fully covered by property/kani/sim test, remove it
   - MERGE: multiple unit tests checking variations, consolidate into one property test
   - UPGRADE: unit test that should be rewritten as property test

A unit test is NOT redundant if:
- It tests a boundary/edge case the property generator excludes
- It's a regression test with a bug reference
- It's the only readable API usage example
- It tests error paths distinct from property test happy-path
- Property tests are feature-gated and this provides ungated baseline

For each finding, report:
- Verdict: SUBSUME | MERGE | UPGRADE
- Test(s): function name(s) and file:line
- Subsumed by: which property/sim/kani test covers this
- Confidence: High (clearly redundant) | Medium (likely redundant) | Low (borderline)

Target: {target_description}
```

## Synthesis & Classification

After all three agents complete, merge and classify findings:

1. **Merge overlapping findings**: If Agent A identifies a coverage gap and
   Agent B identifies a weak test for the same behavior, combine them
2. **Classify each finding** into one of these categories:

| Category | Phase 2 Action | Description |
|----------|---------------|-------------|
| `coverage-gap-property` | Write property tests or invoke `/test-consolidate` | Replace verbose units with property tests |
| `coverage-gap-sim` | Invoke `/sim-scaffold` then `/sim-run` | Coordination code needs DST coverage |
| `coverage-gap-distributed` | Invoke `/jepsen-test` | Cluster-level correctness validation |
| `coverage-gap-fuzz` | Write fuzz targets | Untrusted input parsing needs fuzz coverage |
| `coverage-gap-unit` | Write unit tests | Simple specific behavior needs a test |
| `weak-invariant` | Rewrite test per invariant-review findings | Test doesn't prove what it claims |
| `redundant-tests` | Invoke `/test-dedup` methodology to remove | Tests subsumed by property/sim tests |
| `verbose-suite` | Invoke `/test-consolidate` to consolidate | Many similar tests → parameterized or property |

3. **Tag dependency order**:
   - `/sim-scaffold` must run before `/sim-run`
   - Redundancy removal should run after new tests are written (to avoid removing tests before replacements exist)
   - Coverage gaps and weak invariants can run in parallel

## Human Gate

Present findings to the user:

```
## Test Pipeline — Phase 1 Complete

Found {N} testing findings across {M} files.

### Coverage Gaps

| #  | Priority | Location                | Gap                              | Recommended Test Type | Phase 2        |
|----|----------|-------------------------|----------------------------------|-----------------------|----------------|
| 1  | High     | src/engine/merge.rs:42  | No test for concurrent merge     | CoordinationSim       | /sim-scaffold  |
| 2  | High     | src/shard/split.rs:15   | Split coverage invariant untested| Property test         | /test-consolidate |
| 3  | Medium   | src/parser/pack.rs:88   | Pack parsing lacks fuzz target   | Fuzz test             | Write fuzz     |

### Weak Tests

| #  | Severity | Test                        | Issue                                    | Phase 2        |
|----|----------|-----------------------------|------------------------------------------|----------------|
| 4  | BLOCK    | test_lease_expiry           | Asserts success, not the expiry behavior | Rewrite        |
| 5  | WARN     | test_shard_split_coverage   | Order-sensitive comparison on unordered   | Fix comparator |

### Redundant Tests

| #  | Verdict | Test(s)                     | Subsumed By              | Phase 2           |
|----|---------|-----------------------------|--------------------------|--------------------|
| 6  | SUBSUME | test_encode_basic, _empty   | prop_roundtrip           | /test-dedup       |
| 7  | MERGE   | test_bounds_1..5            | (create property test)   | /test-consolidate |

Approve all? Enter numbers to select:
```

## Phase 2: Targeted Execution

### Dispatch Order

Respect dependency ordering:

```
Phase 2a (parallel):
  ├── Coverage gap agents (write new tests)
  ├── Weak invariant agents (rewrite tests)
  └── Sim scaffold agent (if sim gaps found)

Phase 2b (after 2a):
  ├── /sim-run (after scaffold completes)
  └── Redundancy removal agents (after new tests exist)
```

### Agent Dispatch

For each approved finding, launch an Agent with the appropriate methodology:

**Coverage gap agents:**
```
You are writing tests for a Rust distributed systems project. Write the
minimum tests needed to cover the identified gap.

Finding:
- Gap: {description}
- Location: {file:line}
- Recommended test type: {type}
- Priority: {priority}

Project conventions:
- Tests go in #[cfg(test)] mod tests inside the file under test
- proptest is a direct dev-dependency (no feature gate)
- rstest is workspace dep "0.25" — add rstest.workspace = true to [dev-dependencies]
- Simulation tests go in crates/gossip-coordination/src/sim/
- Fuzz targets go in crates/<crate>/fuzz/fuzz_targets/

{Test type-specific guidance inlined from /test-strategy}

Files you own: {file list}

After writing tests, run:
  cargo fmt --all && cargo test --all-features -- {test_name}
```

**Weak invariant agents:**
```
You are strengthening a test that does not adequately prove its claimed
invariant. Apply the minimum change to make the test prove what it claims.

Finding:
- Test: {test_name} at {file:line}
- Claimed invariant: {invariant}
- Current weakness: {weakness}
- Recommended fix: {fix}

Apply these invariant-test-review principles:
- State the exact invariant the test must prove
- Remove vestigial setup that doesn't participate in the assertion
- Add discriminating twin (negative-path or boundary companion)
- Normalize unordered state before comparisons
- Assert the property directly, not a proxy

Files you own: {file list}

After changes, run:
  cargo fmt --all && cargo test --all-features -- {test_name}
```

**Redundancy removal agents:**
```
You are removing redundant tests. For each SUBSUME verdict, verify the
subsuming test truly covers the same input space, then delete the redundant
test. For each MERGE group, write one proptest that generalizes all merged
tests, then delete the originals.

Findings:
{list of SUBSUME and MERGE verdicts}

Rules:
- Never remove the last ungated test for a public function
- Keep regression tests that cite specific bugs
- Keep one readable usage example per public API
- After deletion, verify remaining tests still pass

Files you own: {file list}

After changes, run:
  cargo fmt --all && cargo test --all-features
```

### Parallel vs Sequential

- Coverage gap agents on non-overlapping files → **in parallel**
- Weak invariant agents on non-overlapping test files → **in parallel**
- Redundancy removal → **after** all new tests are written and passing
- Sim scaffold → sim run: **sequential**

## Completion

```
## Test Pipeline — Complete

### Results

| Finding | Phase 2 Action     | Status    | Result                                |
|---------|--------------------|-----------|---------------------------------------|
| #1      | /sim-scaffold      | Created   | New sim scenario in mega_sim_tests.rs |
| #2      | /test-consolidate  | Written   | prop_split_coverage property test     |
| #3      | Write fuzz         | Created   | fuzz/fuzz_targets/fuzz_pack_parse.rs  |
| #4      | Rewrite            | Fixed     | Now asserts expiry state explicitly   |
| #5      | Fix comparator     | Fixed     | Added BTreeSet normalization          |
| #6      | /test-dedup        | Removed   | 2 tests deleted, subsumed by proptest |
| #7      | /test-consolidate  | Merged    | 5 unit tests → 1 proptest            |

### Net Change

- Tests added: {N}
- Tests removed: {M}
- Tests rewritten: {K}
- Coverage impact: {assessment}

### Verification

Run to confirm:
  cargo fmt --all && cargo check && cargo clippy --all-targets --all-features -- -D warnings
  cargo test --all-features
```

## Error Handling

- If a Phase 1 agent fails, proceed with the other agents' findings
- If a new test fails on first run, report it — may indicate a real bug
- If redundancy removal breaks other tests, revert and report
- If sim-scaffold fails, skip sim-run and report

## Related Skills

- `/test-strategy` — Phase 1 methodology (strategy assessment)
- `/invariant-test-review` — Phase 1 methodology (invariant strength)
- `/test-dedup` — Phase 1 + Phase 2 methodology (redundancy)
- `/test-consolidate` — Phase 2 (verbose suite consolidation)
- `/sim-scaffold` `/sim-run` — Phase 2 (simulation testing)
- `/jepsen-test` — Phase 2 (distributed correctness)
- `/review-pipeline` — Code quality team pipeline
- `/perf-pipeline` — Performance team pipeline

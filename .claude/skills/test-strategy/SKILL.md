---
name: test-strategy
description: Assess and recommend the appropriate testing strategy for Rust code - unit tests, parameterized tests (rstest), property-based tests, fuzz tests, Kani model checking, or simulation testing
---

# Test Strategy Assessment

Analyze code and recommend the optimal testing approach from this project's testing toolkit.

## Testing Toolkit Available

| Type | Tool | Feature Flag | Best For |
|------|------|--------------|----------|
| **Unit Tests** | `#[test]` | None | Specific behavior, edge cases, regression tests |
| **Parameterized Tests** | rstest | Dev-dep | Finite case sets with specific expected outputs, enum variants, error codes |
| **Property Tests** | proptest | Dev-dep (some crates use `test-support` for `Arbitrary` impls) | Invariants over input domains, mathematical properties |
| **Fuzz Tests** | cargo-fuzz | External | Security-critical parsing, untrusted input handling |
| **Model Checking** | Kani | `kani` | Memory safety proofs, absence of panics, formal verification |
| **Simulation Tests** | CoordinationSim | `test-support` | Coordination protocol invariants, fault tolerance, state machine correctness |

### Simulation Harness

This project has a deterministic simulation harness for the coordination subsystem. **Always consider whether new or changed code should be covered by simulation tests.**

| Harness | Location | Feature | Scope | When to Add Cases |
|---------|----------|---------|-------|-------------------|
| **CoordinationSim** | `crates/gossip-coordination/src/sim/` | `test-support` | Coordination protocol invariants (S1–S9), lease management, shard lifecycle, fault injection (SunnyDay/Stormy/Radioactive), deterministic replay | Any change to coordination logic, shard state machines, lease acquisition, run lifecycle, or split handling |
| **TigerHarness** | `crates/scanner-engine/src/tiger_harness.rs` | `tiger-harness` | Scanner engine deterministic test harness for detection pipeline validation | Any change to detection rules, transform pipeline, or scanner engine core |
| **SchedulerSim** | `crates/scanner-scheduler/src/scheduler/sim.rs` | `scheduler-sim` | Scheduler simulation for work-stealing, chunking, and I/O orchestration validation | Any change to scheduler logic, parallel scan, task graph, or affinity |

**Architecture**: The sim module has five layers:
- **`mod.rs`** — `SimContext` (seeded PRNG + logical clock) and `FaultConfig`/`FaultLevel`
- **`worker`** — `SimWorker` per-worker bookkeeping (lease claims, op-ID generation, cursor progress)
- **`invariants`** — `InvariantChecker` verifying 9 safety properties (S1–S9) externally against coordinator ground truth
- **`overload`** — Scripted overload scenarios for targeted stress validation
- **`harness`** — `CoordinationSim` top-level driver (zombie preamble + safety phase + liveness phase)

**Additional simulation-adjacent tests** in `crates/gossip-coordination/src/sim/`:
- `proptest_state_machine_tests.rs` — Proptest state machine model checking
- `mega_sim_tests.rs` — Large-scale simulation runs
- `sim_behavioral_tests.rs` — Behavioral scenario tests
- `overload_tests.rs` — Overload scenario validation

## Decision Framework

### Use Unit Tests When:
- Testing specific, known edge cases
- Verifying exact output for exact input
- Regression tests for fixed bugs
- Simple function behavior verification
- Fast feedback during development

```rust
#[cfg(test)]
mod tests {
    #[test]
    fn specific_edge_case() {
        assert_eq!(function(edge_input), expected_output);
    }
}
```

### Use Parameterized Tests (rstest) When:
- You have a finite, known set of (input, expected output) pairs
- Each case has a specific expected value — no general invariant exists
- Multiple test functions share identical structure, differing only in values
- Testing enum variant mappings, error code tables, or configuration defaults
- You want each case to appear as a separately named sub-test in `cargo test` output
- Adding a new case should be one line, not a new function

```rust
use rstest::rstest;

#[rstest]
#[case("5s", Duration::from_secs(5))]
#[case("3m", Duration::from_secs(180))]
#[case("2h", Duration::from_secs(7200))]
#[case("0s", Duration::ZERO)]
fn parse_duration_valid(#[case] input: &str, #[case] expected: Duration) {
    assert_eq!(parse_duration(input).unwrap(), expected);
}

#[rstest]
#[case("5x", ParseError::InvalidUnit)]
#[case("", ParseError::Empty)]
#[case("-1s", ParseError::Negative)]
fn parse_duration_errors(#[case] input: &str, #[case] expected: ParseError) {
    assert_eq!(parse_duration(input).unwrap_err(), expected);
}
```

**Dependency**: rstest is declared in workspace `[workspace.dependencies]` as `rstest = "0.25"`. Add `rstest.workspace = true` to crate-level `[dev-dependencies]`.

#### rstest Advanced Features

**Fixtures** — shared setup across tests without boilerplate:

```rust
use rstest::*;

#[fixture]
fn config() -> Config {
    Config::builder().timeout(Duration::from_secs(30)).build()
}

#[rstest]
fn test_with_default_config(config: Config) {
    assert!(config.timeout().as_secs() > 0);
}
```

**Matrix testing** — combinatorial cases via multiple `#[values]` parameters:

```rust
#[rstest]
fn protocol_version_compat(
    #[values(ProtocolVersion::V1, ProtocolVersion::V2)] version: ProtocolVersion,
    #[values(true, false)] compressed: bool,
    #[values(0, 1, 100)] payload_size: usize,
) {
    let msg = Message::new(version, compressed, payload_size);
    assert!(msg.is_valid());
}
// Generates 2 × 2 × 3 = 12 individual test cases
```

### Use Property-Based Tests (proptest) When:
- Function should satisfy invariants for ALL valid inputs
- Testing mathematical properties (commutativity, associativity, idempotence)
- Round-trip properties (encode/decode, serialize/deserialize)
- Relationship between functions (e.g., `parse` and `format` are inverses)
- Exploring large input spaces systematically

```rust
#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn roundtrip_property(input in any::<ValidInput>()) {
            let encoded = encode(&input);
            let decoded = decode(&encoded).unwrap();
            prop_assert_eq!(input, decoded);
        }
    }
}
```

**Note**: proptest is a direct dev-dependency — no feature gate needed for tests.
Some crates gate `Arbitrary` impls behind the `test-support` feature for use by
downstream test code (e.g., `gossip-contracts` exposes `Arbitrary` impls via
`features = ["test-support"]`).

### Use Fuzz Tests When:
- Parsing untrusted or external input (files, network data)
- Security-critical code paths
- Looking for crashes, panics, or undefined behavior
- Complex state machines with many paths
- Finding inputs that cause pathological performance

```rust
// In fuzz/fuzz_targets/
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = parse_untrusted(data);
});
```

**Run with**: `cargo +nightly fuzz run <target>`

### Use Kani Model Checking When:
- Proving absence of panics/undefined behavior
- Verifying memory safety in unsafe code
- Proving loop bounds and termination
- Exhaustive verification of small input spaces
- Critical algorithms where bugs are unacceptable

```rust
#[cfg(kani)]
mod verification {
    use super::*;

    #[kani::proof]
    fn verify_no_panic() {
        let x: u32 = kani::any();
        kani::assume(x < 1000);
        let result = critical_function(x);
        // Kani proves this never panics
    }

    #[kani::proof]
    #[kani::unwind(10)]
    fn verify_loop_bounds() {
        let arr: [u8; 8] = kani::any();
        process_array(&arr); // Prove no out-of-bounds
    }
}
```

**Run with**: `cargo kani --features kani`

### Use Simulation Tests When:
- Testing coordination protocol behavior under fault injection
- Verifying invariants (S1–S9) under many possible interleavings
- Changes touch shard lifecycle, lease management, run state machines, or split handling
- You need deterministic replay of failure cases (seed-based reproducibility)
- Testing fault tolerance (lease expiry, clock jumps, worker pauses)
- Verifying mutual exclusion, fence monotonicity, terminal irreversibility

**When to add simulation coverage:**

```
Does it change coordination logic (acquire, complete, checkpoint, split)?
  → Add CoordinationSim test or extend existing mega_sim_tests

Does it change shard state transitions or lifecycle?
  → Ensure invariant checker (S1–S9) covers the new states

Does it change lease handling or fence epochs?
  → Test under Stormy/Radioactive fault levels

Does it change run lifecycle or session management?
  → Add behavioral scenario in sim_behavioral_tests
```

**Adding a simulation test:**
```rust
// In crates/gossip-coordination/src/sim/mega_sim_tests.rs or a new *_tests.rs
use crate::sim::{CoordinationSim, FaultLevel};

#[test]
fn my_new_coordination_scenario() {
    let report = CoordinationSim::new(42, FaultLevel::Stormy)
        .with_workers_and_shards(3, 5)
        .run(500, 200);
    assert!(report.violations.is_empty(), "{report:#?}");
}
```

**Adding a proptest state machine test:**
```rust
// In crates/gossip-coordination/src/sim/proptest_state_machine_tests.rs
// Use proptest to generate random operation sequences and verify invariants
```

**Run with**:
```bash
cargo test -p gossip-coordination --features test-support  # All coordination tests incl. sim
cargo test -p gossip-coordination sim                       # Just sim-related tests
```

## Assessment Checklist

When analyzing code for test strategy, consider:

1. **Input Domain**
   - [ ] Fixed, known inputs → Unit tests
   - [ ] Finite set of (input, expected) pairs → Parameterized tests (rstest)
   - [ ] Combinatorial inputs (multiple parameters × multiple values) → rstest `#[values]` matrix
   - [ ] Large/infinite input space → Property tests
   - [ ] Untrusted/adversarial input → Fuzz tests
   - [ ] Small but critical input space → Kani
   - [ ] Interleaving-sensitive behavior → Simulation tests

2. **Properties to Verify**
   - [ ] Specific behavior → Unit tests
   - [ ] Same assertion, many concrete cases → Parameterized tests (rstest)
   - [ ] Invariants over all inputs → Property tests
   - [ ] "Never crashes" → Fuzz tests + Kani
   - [ ] Memory safety → Kani (especially for unsafe)
   - [ ] System-level invariants (no leaks, monotonic progress, ground truth) → Simulation tests

3. **Code Characteristics**
   - [ ] Pure functions → Property tests
   - [ ] Enum variant mappings / lookup tables → rstest `#[case]`
   - [ ] Functions with shared setup across tests → rstest `#[fixture]`
   - [ ] Parsers/decoders → Fuzz tests
   - [ ] Unsafe blocks → Kani proofs
   - [ ] State machines → Property tests + Fuzz
   - [ ] Coordination protocol logic → CoordinationSim + proptest state machine
   - [ ] Shard lifecycle / lease management → CoordinationSim under fault injection
   - [ ] Identity types / derivation chains → Fuzz tests (see `gossip-contracts/fuzz/`)
   - [ ] Data structures (ByteSlab, InlineVec, RingBuffer) → Fuzz + Property tests

4. **Simulation Harness Checklist** (always evaluate for coordination changes)
   - [ ] Does this change affect shard state transitions (Active, Done, Split, Parked)? → CoordinationSim
   - [ ] Does this change affect lease acquisition, renewal, or expiry? → CoordinationSim with Stormy/Radioactive
   - [ ] Does this change affect fence epochs or monotonicity guarantees? → Invariant checker S2
   - [ ] Does this change affect run lifecycle or session management? → sim_behavioral_tests
   - [ ] Does this change affect split handling or coverage? → Invariant checker S7
   - [ ] Can a seed-based replay reproduce the scenario deterministically? → Add test to `sim/mega_sim_tests.rs`

5. **Existing Patterns in This Codebase**
   - Unit tests: `#[cfg(test)] mod tests` inline, or sibling `*_tests.rs` files
   - Parameterized tests: rstest `#[rstest]` with `#[case]` (workspace dep `rstest = "0.25"`)
   - Property tests: proptest as dev-dep; `Arbitrary` impls gated behind `test-support` feature in gossip-contracts
   - Kani proofs: `#[cfg(kani)]` blocks in gossip-stdx
   - Fuzz targets: `crates/gossip-contracts/fuzz/` and `crates/gossip-stdx/fuzz/`
    - Simulation tests: `crates/gossip-coordination/src/sim/` (CoordinationSim, proptest state machine, behavioral, overload)
    - Scanner sim harnesses: `crates/scanner-engine/src/tiger_harness.rs` (`tiger-harness` feature), `crates/scanner-scheduler/src/scheduler/sim.rs` (`scheduler-sim` feature)
    - Scanner integration tests: `crates/scanner-engine-integration-tests/tests/`
   - Benchmarks: Criterion benchmarks in `crates/*/benches/`
   - Integration tests: `crates/*/tests/identity_smoke.rs` pattern

## Example Assessment Output

```markdown
## Test Strategy for `InlineVec<T, N>`

### Recommended Approach: Property Tests + Kani + Fuzz

**Rationale:**
- Generic data structure with large input space (push/pop/insert/remove sequences)
- Has invariants: length <= capacity, no out-of-bounds access
- Contains unsafe code for stack-allocated storage
- Already has fuzz targets in `crates/gossip-stdx/fuzz/`

**Specific Tests:**

1. **Property Test**: Collection invariants
   - Property: `vec.len() <= N` after any sequence of operations
   - Property: push-then-pop roundtrip preserves values
   - Property: iteration yields exactly `len()` elements

2. **Kani Proof**: Memory safety of unsafe storage
   - Prove: No out-of-bounds access in `unsafe` array ops
   - Bound: Unwind factor based on max capacity N

3. **Fuzz Test**: Extend existing `fuzz_inline_vec` target
   - Random operation sequences (push, pop, insert, remove, clear)

4. **Unit Tests**: Known edge cases
   - Empty vec operations
   - Full capacity behavior
   - Single-element edge cases
```

```markdown
## Test Strategy for `ShardSpec` Validation

### Recommended Approach: Parameterized Tests (rstest) + Property Tests

**Rationale:**
- Finite set of valid/invalid shard spec configurations
- Validation rules have specific expected error variants
- Split logic has mathematical properties (coverage, non-overlap)

**Specific Tests:**

1. **rstest Parameterized**: Known valid/invalid configurations
   ```rust
   #[rstest]
   #[case::valid_basic(spec(1, 100), true)]
   #[case::zero_range(spec(0, 0), false)]
   #[case::inverted_range(spec(100, 1), false)]
   fn spec_validity(#[case] spec: ShardSpec, #[case] valid: bool) {
       assert_eq!(spec.validate().is_ok(), valid);
   }
   ```

2. **Property Test**: Split coverage invariant
   - Property: splitting a spec always produces children that cover the parent's range
3. **Unit Test**: Regression test for specific bug (if applicable)
```

```markdown
## Test Strategy for `LeaseManager` Changes

### Recommended Approach: CoordinationSim + Property Tests

**Rationale:**
- Lease behavior emerges from coordination protocol interactions
- Safety invariants (S1 mutual exclusion, S2 fence monotonicity) require external checking
- Must hold under fault injection (lease expiry, clock jumps)

**Specific Tests:**

1. **CoordinationSim**: Run under all fault levels
   - SunnyDay: basic correctness
   - Stormy: moderate fault tolerance
   - Radioactive: aggressive fault tolerance
2. **Property Test**: Fence epoch monotonicity for random operation sequences
3. **Unit Tests**: Specific lease edge cases (expiry at exact boundary, zero-duration lease)
```

## Quick Reference

| Scenario | Primary | Secondary |
|----------|---------|-----------|
| New data structure | Property tests | Unit tests for edges |
| Enum/status mappings | rstest `#[case]` | Unit tests for edge cases |
| State transition tables | rstest `#[case]` | Property tests if transitions have invariants |
| Error code/message mapping | rstest `#[case]` | — |
| Config defaults/lookups | rstest `#[case]` | — |
| Combinatorial input validation | rstest `#[values]` matrix | Property tests for general invariants |
| Shared test fixtures | rstest `#[fixture]` | — |
| Parser/decoder | Fuzz tests | Property tests for roundtrip |
| Unsafe code | Kani proofs | Property tests for API |
| Algorithm correctness | Property tests | Unit tests for examples |
| Bug fix | Unit test (regression) | Sim test if coordination-related |
| Performance-critical loop | Kani (bounds) | Property tests |
| Coordination protocol change | CoordinationSim | Proptest state machine |
| Scanner engine / detection rules | TigerHarness + unit tests | Integration tests |
| Scheduler / parallel scan logic | SchedulerSim | Unit tests for edge cases |
| Git pack parsing / delta decode | Fuzz + Property tests | Unit tests |
| Shard lifecycle / state machine | CoordinationSim (all fault levels) | Unit tests for edge cases |
| Lease management | CoordinationSim (Stormy+) | Property tests for monotonicity |
| Identity types / derivation | Fuzz tests | Property tests for roundtrip |
| Data structures (stdx) | Fuzz + Property tests | Kani for unsafe |
| Connector / persistence | Conformance tests | Unit tests for edge cases |

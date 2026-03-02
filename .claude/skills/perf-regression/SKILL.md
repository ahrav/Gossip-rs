---
name: perf-regression
description: Performance regression testing workflow for hot path changes
user-invocable: false
---

# Performance Regression Workflow

**IMPORTANT**: Follow this workflow before merging any feature that touches hot paths in the gossip-rs workspace.

## When This Applies

Invoke this skill when modifying:
- Data structures in `crates/gossip-stdx/src/` (InlineVec, RingBuffer, ByteSlab)
- Coordination protocol in `crates/gossip-coordination/src/`
- Contract types in `crates/gossip-contracts/src/`
- Scanner engine in `crates/scanner-engine/src/`
- Scanner runtime in `crates/gossip-scanner-runtime/src/`
- Scanner scheduler in `crates/scanner-scheduler/src/`
- Git scan pipeline in `crates/scanner-git/src/`

## Workflow Steps

### 1. Stash Changes and Build Baseline

```bash
git stash push -m "feature-name"
RUSTFLAGS="-C target-cpu=native" cargo build --release
```

### 2. Run Baseline Benchmarks

Save baselines for all relevant benchmark suites:

```bash
# Run all workspace benchmarks
cargo bench --workspace -- --save-baseline before

# Or target specific crates:
cargo bench -p gossip-stdx -- --save-baseline before
cargo bench -p gossip-contracts -- --save-baseline before
cargo bench -p gossip-coordination -- --save-baseline before
```

### 3. Restore Changes and Rebuild

```bash
git stash pop
RUSTFLAGS="-C target-cpu=native" cargo build --release
```

### 4. Run Comparison Benchmarks

```bash
# Compare against baseline (all workspace benchmarks)
cargo bench --workspace -- --baseline before

# Or target specific crates:
cargo bench -p gossip-stdx -- --baseline before
cargo bench -p gossip-contracts -- --baseline before
cargo bench -p gossip-coordination -- --baseline before
```

### 5. Analyze Results

Look for these patterns in Criterion output:
- `Performance has improved` — Optimization successful
- `Performance has regressed` — Changes hurt performance
- `No change in performance` — Within noise threshold

## Available Benchmarks

| Crate | Bench File | Measures |
|-------|-----------|----------|
| `gossip-contracts` | `identity.rs` | Identity type construction and derivation |
| `gossip-coordination` | `coordination.rs` | Shard coordination operations |
| `gossip-coordination` | `sim.rs` | Simulation harness benchmarks |
| `gossip-stdx` | `byte_slab.rs` | Byte slab pool allocation |
| `gossip-stdx` | `inline_vec.rs` | InlineVec operations |
| `gossip-stdx` | `ring_buffer.rs` | RingBuffer throughput |

## Acceptance Criteria

| Regression Level | Action |
|------------------|--------|
| None (<2%) | Ship as-is |
| Minor (2-5%) | Document reason, acceptable for correctness |
| Moderate (5-10%) | Requires compelling justification |
| Major (>10%) | Must investigate and optimize |

## PR Documentation

Include in PR description:
- Criterion benchmark comparison summary
- Which crates/benchmarks were affected
- Justification for any regression >2%

## Output Format

Report results as:

```markdown
## Performance Regression Results

### Criterion Benchmarks

| Crate | Benchmark | Baseline | After | Delta |
|-------|-----------|----------|-------|-------|
| gossip-stdx | inline_vec/push | X ns | Y ns | +/-Z% |
| gossip-stdx | ring_buffer/enqueue | X ns | Y ns | +/-Z% |
| gossip-stdx | byte_slab/alloc | X ns | Y ns | +/-Z% |
| gossip-contracts | identity/derive | X ns | Y ns | +/-Z% |
| gossip-coordination | coordination/acquire | X ns | Y ns | +/-Z% |

### Verdict

[None/Minor/Moderate/Major] regression - [justification if >2%]
```

## Related Skills

- `/bench-compare` — Quick before/after benchmark comparison
- `/asm-forge` — Assembly-guided optimization for hot functions
- `/linux-perf-profile` — Hardware counter analysis for deeper investigation
- `/performance-analyzer` — Static hotspot analysis for this project's patterns

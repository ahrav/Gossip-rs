---
name: bench-compare
description: Run Criterion benchmarks with baseline comparison for performance optimization work
---

# Benchmark Comparison Workflow

Compare benchmark results against a baseline to measure optimization impact.

## Usage

Invoke with optional benchmark filter:
- `/bench-compare` - Run all benchmarks
- `/bench-compare scan` - Run only scan-related benchmarks
- `/bench-compare throughput` - Run throughput benchmarks

## Workflow

### 1. Establish Baseline

Before making changes, save current benchmark results:

```bash
cargo bench --bench <name> -- --save-baseline before
```

Or for all benchmarks:
```bash
cargo bench -- --save-baseline before
```

### 2. Apply Changes

Make the optimization changes to the codebase.

### 3. Compare Results

Run benchmarks against the saved baseline:

```bash
cargo bench --bench <name> -- --baseline before
```

### 4. Analyze Output

Look for these patterns in Criterion output:
- `Performance has improved` - Optimization successful
- `Performance has regressed` - Changes hurt performance
- `No change in performance` - Within noise threshold

### 5. Report Summary

Provide a summary table:

| Benchmark | Before | After | Change |
|-----------|--------|-------|--------|
| name      | X ns   | Y ns  | -Z%    |

## Available Benchmarks

Benchmarks are distributed across crates in `crates/*/benches/`:
- `gossip-contracts`: `identity.rs` — Identity type construction and derivation
- `gossip-coordination`: `coordination.rs` — Shard coordination operations
- `gossip-coordination`: `sim.rs` — Simulation harness benchmarks
- `gossip-stdx`: `byte_slab.rs` — Byte slab pool allocation
- `gossip-stdx`: `inline_vec.rs` — InlineVec operations
- `gossip-stdx`: `ring_buffer.rs` — RingBuffer throughput

## Tips

- Use `-p <crate> --bench <name>` to run specific benchmarks: `cargo bench -p gossip-stdx --bench inline_vec`
- Run all benchmarks: `cargo bench --workspace`
- Compare multiple runs to account for variance

# gossip-contracts

Shared contract types, encodings, and invariants for the gossip-rs distributed
secret scanner. This crate defines the boundary-oriented API surface that all
runtime crates depend on.

## Modules

| Module          | Purpose                                                         |
|-----------------|-----------------------------------------------------------------|
| `identity`      | Canonical encoding, domain-separated hashing, ID newtypes       |
| `coordination`  | Shard lifecycle, lease management, `CoordinationBackend` trait   |
| `shard`         | Key encoding schemas, range arithmetic, split computation       |
| `connector`     | Enumeration/read traits and connector registration              |
| `persistence`   | Done-ledger/findings-sink traits and commit protocol typestate  |
| `sim`           | Deterministic simulation harness (behind `test-support` feature)|

## Feature Flags

| Flag             | Default | Purpose                                              |
|------------------|---------|------------------------------------------------------|
| `test-support`   | off     | Enables `sim` module, test doubles, and helpers      |

## Testing

Run all tests (including simulation):

```bash
cargo test --all-features -p gossip-contracts
```

Run only simulation tests:

```bash
cargo test --all-features -p gossip-contracts -- sim
```

Run benchmarks:

```bash
cargo bench --all-features -p gossip-contracts
```

### Reproducing a Failing Seed

The simulation is fully deterministic. If a test reports a failing seed:

```rust
use gossip_contracts::sim::{CoordinationSim, FaultLevel};

let report = CoordinationSim::new(FAILING_SEED, FaultLevel::Stormy)
    .with_workers_and_shards(3, 5)
    .run(500, 200);
assert!(report.violations.is_empty());
```

Same seed + same parameters = identical results on any platform.

## Quick Simulation Example

```rust,ignore
use gossip_contracts::sim::{CoordinationSim, FaultLevel};

// Run 500 safety ops under moderate faults, then 200 liveness ops.
let report = CoordinationSim::new(42, FaultLevel::Stormy)
    .with_workers_and_shards(3, 5)
    .run(500, 200);

assert!(report.violations.is_empty(), "invariant violations: {:?}", report.violations);
assert!(report.converged, "not all shards converged");
println!("Executed {} ops, seed {}", report.ops_executed, report.seed);
```

## Design Principles

1. **No unsafe code.** Pure computation -- no FFI, no raw pointers.
2. **Minimal dependencies.** Only `blake3` at runtime.
3. **Boundary isolation.** Modules mirror the five-boundary decomposition
   with acyclic dependency direction:
   `identity -> coordination -> shard -> connector -> persistence`.

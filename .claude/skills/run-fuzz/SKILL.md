---
name: run-fuzz
description: Use when testing gossip-contracts or gossip-stdx data structures for crashes, when verifying new Arbitrary impls, or when reproducing a fuzz crash artifact. Runs cargo-fuzz targets with nightly toolchain.
disable-model-invocation: true
---

# Run Fuzz Target

Run fuzz tests against gossip-rs data structures and contract types.

## Usage

- `/run-fuzz <target>` - Run specific fuzz target (default 10,000 runs)
- `/run-fuzz <target> <runs>` - Run with custom iteration count
- `/run-fuzz all` - Run all targets briefly (1,000 runs each)
- `/run-fuzz list` - List available targets

## Available Targets

Fuzz targets are distributed across crates:

### gossip-contracts (`crates/gossip-contracts/fuzz/`)

| Target | Tests |
|--------|-------|
| `fuzz_derivation_chain` | Derivation chain construction and validation |
| `fuzz_item_identity_key` | ItemIdentityKey creation and hashing |

### gossip-stdx (`crates/gossip-stdx/fuzz/`)

| Target | Tests |
|--------|-------|
| `fuzz_byte_slab` | ByteSlab pool allocation, slot lifecycle |
| `fuzz_inline_vec` | InlineVec push/pop/access with arbitrary inputs |
| `fuzz_ring_buffer` | RingBuffer enqueue/dequeue under arbitrary sequences |

## Workflow

### Run Single Target

```bash
cd crates/<crate> && cargo +nightly fuzz run <target> -- -runs=10000
```

Examples:

```bash
cd crates/gossip-stdx && cargo +nightly fuzz run fuzz_byte_slab -- -runs=10000
cd crates/gossip-contracts && cargo +nightly fuzz run fuzz_derivation_chain -- -runs=10000
```

### Run All Targets

```bash
# gossip-contracts targets
cd crates/gossip-contracts
for target in fuzz_derivation_chain fuzz_item_identity_key; do
  echo "Running $target..."
  cargo +nightly fuzz run $target -- -runs=1000
done

# gossip-stdx targets
cd ../gossip-stdx
for target in fuzz_byte_slab fuzz_inline_vec fuzz_ring_buffer; do
  echo "Running $target..."
  cargo +nightly fuzz run $target -- -runs=1000
done
```

### Check for Crashes

Crashes are saved to `fuzz/artifacts/<target>/` within each crate. To reproduce:

```bash
cd crates/<crate>
cargo +nightly fuzz run <target> fuzz/artifacts/<target>/<crash-file>
```

## Prerequisites

- Nightly Rust toolchain: `rustup install nightly`
- cargo-fuzz: `cargo install cargo-fuzz`

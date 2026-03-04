# Kani Model Checking

Formal verification of unsafe code and critical invariants using
[Kani](https://model-checking.github.io/kani/), a Rust model checker
backed by CBMC.

## Overview

80 proof harnesses across 4 workspace crates verify memory safety,
bounds correctness, and algorithmic invariants for the most
safety-critical data structures. All proofs are gated behind
`#[cfg(kani)]` and add zero overhead outside verification.

## Proof Distribution

| Crate               | Proofs | Files | Properties Verified                                                                                   |
| ------------------- | ------ | ----- | ----------------------------------------------------------------------------------------------------- |
| `gossip-stdx`       | 54     | 6     | Bitset invariants, timing wheel safety, SPSC ring bounds, inline vec bounds, atomic dedup correctness |
| `scanner-engine`    | 15     | 3     | Node pool allocation safety, hit pool lifecycle, scratch memory bounds                                |
| `scanner-scheduler` | 9      | 4     | Archive format detection, runtime chunk arithmetic, budget stack depth, tar zero-block detection      |
| `scanner-git`       | 2      | 2     | DAG counter underflow, shard partitioning invariants                                                  |

### gossip-stdx (54 proofs)

| File                                               | Proofs | What is verified                                                                                                                            |
| -------------------------------------------------- | ------ | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `crates/gossip-stdx/src/timing_wheel_tests.rs`     | 14     | Never-fires-early, pool coherence, horizon enforcement, slot occupancy, FIFO ordering, monotonicity, reset correctness, Bitset2 consistency |
| `crates/gossip-stdx/src/bitset_tests.rs`           | 12     | Set/unset roundtrips, padding invariant preservation, count correctness, clear semantics, iterator consistency                              |
| `crates/gossip-stdx/src/inline_vec.rs`             | 9      | Push/pop/truncate/extend/drain bounds, `get_unchecked` equivalence, `MaybeUninit` array validity                                            |
| `crates/gossip-stdx/src/spsc.rs`                   | 8      | Ring capacity, index wrapping, push/pop safety, producer/consumer non-interference, empty/full detection                                    |
| `crates/gossip-stdx/src/atomic_bitset_tests.rs`    | 6      | `test_and_set` idempotency, bit independence, count bounds, clear correctness                                                               |
| `crates/gossip-stdx/src/atomic_seen_sets_tests.rs` | 5      | `mark`/`is_seen` roundtrips, cross-set independence, clear-all                                                                              |

### scanner-engine (15 proofs)

| File                                           | Proofs | What is verified                                                                                     |
| ---------------------------------------------- | ------ | ---------------------------------------------------------------------------------------------------- |
| `crates/scanner-engine/src/scratch_memory.rs`  | 6      | `ScratchVec` push/truncate/pop/extend/drain bounds, `get_unchecked` safety                           |
| `crates/scanner-engine/src/pool/node_pool.rs`  | 5      | In-bounds acquire, non-overlapping nodes, release/reacquire, free-count tracking, alignment          |
| `crates/scanner-engine/src/engine/hit_pool.rs` | 4      | `push_span` OOB safety, coalesce path correctness, `take_into` bounds, `reset_touched` bitset bounds |

### scanner-scheduler (9 proofs)

| File                                                  | Proofs | What is verified                                                                                               |
| ----------------------------------------------------- | ------ | -------------------------------------------------------------------------------------------------------------- |
| `crates/scanner-scheduler/src/archive/detect.rs`      | 5      | `detect_kind_from_name_bytes` panic-freedom, suffix detection functions (`_z`, `_r`, `_p`, `_2`) panic-freedom |
| `crates/scanner-scheduler/src/runtime.rs`             | 2      | Chunk view arithmetic bounds, file chunk copy window fitting                                                   |
| `crates/scanner-scheduler/src/archive/budget.rs`      | 1      | Budget stack `depth - 1` index validity for any enter/exit sequence                                            |
| `crates/scanner-scheduler/src/archive/formats/tar.rs` | 1      | Zero-block detection `ptr.add(i + j)` stays within `[0, 512)`                                                  |

### scanner-git (2 proofs)

| File                                    | Proofs | What is verified                                                             |
| --------------------------------------- | ------ | ---------------------------------------------------------------------------- |
| `crates/scanner-git/src/runner_exec.rs` | 1      | `shard_id_for_exec_position` produces valid, complete, balanced partitioning |
| `crates/scanner-git/src/pack_plan.rs`   | 1      | DAG `remaining_out` / `dag_remaining` counters never underflow               |

## Running Locally

```bash
# Verify a single crate
cargo kani --package gossip-stdx --features kani

# Verify all crates (run sequentially — each crate is independent)
cargo kani --package gossip-stdx --features kani
cargo kani --package scanner-engine --features kani
cargo kani --package scanner-scheduler --features kani
cargo kani --package scanner-git --features kani
```

## CI

Kani runs on the **nightly schedule** (02:00 UTC) and can be triggered
manually via `workflow_dispatch`. Each crate runs as a separate step
so failures are isolated. See `.github/workflows/ci.yml`, job `kani`.

## Adding New Proofs

1. Add the proof in the relevant source file under a `#[cfg(kani)]` module.
2. Annotate with `#[kani::proof]` and `#[kani::unwind(N)]` where `N`
   bounds loop iterations (keep small to avoid solver timeouts).
3. Ensure the crate's `Cargo.toml` has `kani = []` under `[features]`
   and `'cfg(kani)'` in the `check-cfg` lint allowlist.
4. Run `cargo kani --package <crate> --features kani` locally to verify.

## Related Verification Infrastructure

| Tool     | Scope                                      | CI Job | Schedule |
| -------- | ------------------------------------------ | ------ | -------- |
| **Kani** | Bounded model checking (80 proofs)         | `kani` | Nightly  |
| **Miri** | Undefined behavior detection               | `miri` | Nightly  |
| **Loom** | Exhaustive concurrency testing (8 models)  | `loom` | Nightly  |
| **ASAN** | Address sanitizer for SIMD/unsafe paths    | `asan` | Nightly  |

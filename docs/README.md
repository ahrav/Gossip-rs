# gossip-rs Documentation

Documentation index for the gossip-rs workspace. This guide covers the distributed
coordination layer, scanner engine, scheduler, and supporting infrastructure.

## Quick Start

| Audience            | Start here                                                                                                                                                  |
| ------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| New contributor     | [architecture-overview.md](architecture-overview.md) → [architecture.md](architecture.md)                                                                   |
| Scanner engine work | [detection-engine.md](scanner-engine/detection-engine.md) → [detection-rules.md](scanner-engine/detection-rules.md)                                         |
| Coordination work   | [boundary-2-coordination.md](gossip-coordination/boundary-2-coordination.md) → [coordination-testing.md](gossip-coordination/coordination-testing.md)       |
| Scheduler work      | [scheduler-engine-abstraction.md](scanner-scheduler/scheduler-engine-abstraction.md) → [scheduler-task-graph.md](scanner-scheduler/scheduler-task-graph.md) |
| Runtime / CLI work  | [gossip-scanner-runtime.md](gossip-scanner-runtime.md) → [gossip-scan-driver.md](gossip-scan-driver.md)                                                     |
| Worker binary       | [gossip-worker.md](gossip-worker.md)                                                                                                                         |
| CLI binary          | [scanner-rs-cli.md](scanner-rs-cli.md)                                                                                                                       |
| Shard algebra       | [shard-algebra.md](gossip-frontier/shard-algebra.md)                                                                                                        |
| Data structures     | [gossip-stdx.md](gossip-stdx.md)                                                                                                                            |
| Testing             | [simulation-harness.md](gossip-coordination/simulation-harness.md) → [counterexample-testing-unification.md](counterexample-testing-unification.md)         |

---

## 1. System Architecture

| Document                                               | Focus                            | Key Concepts                                           |
| ------------------------------------------------------ | -------------------------------- | ------------------------------------------------------ |
| [architecture-overview.md](architecture-overview.md)   | C4-style component diagram       | CLI, Engine, Pipeline, Memory, Data Structures         |
| [architecture.md](architecture.md)                     | Data flow                        | Walker → Reader → Scanner → Output, transform worklist |
| [data-types.md](data-types.md)                         | Class diagrams                   | Key type relationships across crates                   |
| [pipeline-flow.md](pipeline-flow.md)                   | Pipeline execution flow          | Discovery, executor model, backpressure                |
| [pipeline-state-machine.md](pipeline-state-machine.md) | State transitions & termination  | Reverse pump order, stall detection                    |
| [git-scanning.md](scanner-git/git-scanning.md)         | End-to-end Git scanning pipeline | Pipeline stages, persistence contract, ODB-blob mode   |
| [git-pack-execution.md](scanner-git/git-pack-execution.md) | Git packfile internals       | Pack parsing, delta resolution, blob introduction, caching |

---

## 2. Coordination & Distributed Runtime

### Boundary Contracts

| Document                                                                      | Focus                                        |
| ----------------------------------------------------------------------------- | -------------------------------------------- |
| [boundary-1-identity-spine.md](gossip-contracts/boundary-1-identity-spine.md) | Identity & hashing spine (foundational leaf) |
| [boundary-2-coordination.md](gossip-coordination/boundary-2-coordination.md)  | Shard coordination protocol                  |
| [boundary-3-shard-algebra.md](gossip-contracts/boundary-3-shard-algebra.md)   | Shard algebra and splitting                  |
| [boundary-4-connectors.md](gossip-connectors/boundary-4-connectors.md)        | Source connectors (FS, Git, in-memory)       |
| [boundary-5-persistence.md](gossip-contracts/boundary-5-persistence.md)       | Persistence layer contracts                  |

### Coordination Testing

| Document                                                               | Focus                                                        |
| ---------------------------------------------------------------------- | ------------------------------------------------------------ |
| [coordination-testing.md](gossip-coordination/coordination-testing.md) | Four-tier coordination testing strategy                      |
| [simulation-harness.md](gossip-coordination/simulation-harness.md)     | Deterministic simulation infrastructure (FoundationDB-style) |
| [coordination-error-model.md](gossip-coordination/coordination-error-model.md) | Error hierarchy, validation pipeline, lease/fence semantics  |

---

## 3. Detection Engine

### Core Engine

| Document                                                                        | Module                                                     | Description                                                                    |
| ------------------------------------------------------------------------------- | ---------------------------------------------------------- | ------------------------------------------------------------------------------ |
| [detection-engine.md](scanner-engine/detection-engine.md)                       | `crates/scanner-engine/`                                   | Multi-stage pattern matching: anchor scan, window building, regex confirmation |
| [detection-rules.md](scanner-engine/detection-rules.md)                         | `crates/scanner-engine/src/rules/`                         | Rule anatomy, anchor strategy, two-phase examples                              |
| [engine-vectorscan-prefilter.md](scanner-engine/engine-vectorscan-prefilter.md) | `crates/scanner-engine/src/engine/vectorscan_prefilter.rs` | Database compilation, pattern types, callback mechanism                        |
| [engine-window-validation.md](scanner-engine/engine-window-validation.md)       | `crates/scanner-engine/src/engine/window_validate.rs`      | Gate checks, regex execution, entropy checking                                 |

### Transforms & Decode

| Document                                                          | Module                                              | Description                                                     |
| ----------------------------------------------------------------- | --------------------------------------------------- | --------------------------------------------------------------- |
| [transform-chain.md](scanner-engine/transform-chain.md)           | `crates/scanner-engine/src/engine/transform.rs`     | Recursive URL/Base64 decode flow, TimingWheel scheduling        |
| [engine-transforms.md](scanner-engine/engine-transforms.md)       | `crates/scanner-engine/src/engine/transform.rs`     | URL/Base64 span detection, streaming decode, budget enforcement |
| [engine-stream-decode.md](scanner-engine/engine-stream-decode.md) | `crates/scanner-engine/src/engine/stream_decode.rs` | Streaming decode, ring buffer, timing wheel integration         |
| [engine-decode-state.md](scanner-engine/engine-decode-state.md)   | `crates/scanner-engine/src/engine/decode_state.rs`  | Decode step arena, provenance tracking, parent-linked chains    |

### Engine Internals & Policy

| Document                                                                                | Module                                                    | Description                                                        |
| --------------------------------------------------------------------------------------- | --------------------------------------------------------- | ------------------------------------------------------------------ |
| [engine-api-types.md](scanner-engine/engine-api-types.md)                               | `crates/scanner-engine/src/api.rs`                        | Public API types: RuleSpec, FindingRec, Tuning, gates, transforms  |
| [engine-offline-validation.md](scanner-engine/engine-offline-validation.md)             | `crates/scanner-engine/src/engine/offline_validate.rs`    | Offline structural validators: CRC32, AWS, GitHub PAT, JWT, Slack  |
| [regex-to-anchor-extraction.md](scanner-engine/regex-to-anchor-extraction.md)           | `crates/scanner-engine/src/regex2anchor.rs`               | Regex AST → literal anchor extraction for Vectorscan prefiltering  |
| [engine-internals.md](scanner-engine/engine-internals.md)                               | `crates/scanner-engine/src/engine/{scratch,hit_pool,...}` | ScanScratch layout, HitAccPool, VsDbCache, compiled rule repr      |
| [content-policy-and-caching.md](scanner-engine/content-policy-and-caching.md)           | `crates/scanner-engine/src/{content_policy,b64_yara,...}` | Content type detection, YARA base64 gate, set-associative cache    |

---

## 4. Scheduler Subsystem

### Core Scheduler

| Document                                                                             | Module                                                   | Description                                            |
| ------------------------------------------------------------------------------------ | -------------------------------------------------------- | ------------------------------------------------------ |
| [scheduler-task-graph.md](scanner-scheduler/scheduler-task-graph.md)                 | `crates/scanner-scheduler/src/scheduler/task_graph.rs`   | Object lifecycle FSM (enumerate → fetch → scan → done) |
| [scheduler-engine-abstraction.md](scanner-scheduler/scheduler-engine-abstraction.md) | `crates/scanner-scheduler/src/scheduler/engine_trait.rs` | ScanEngine/EngineScratch/FindingRecord traits          |
| [scheduler-engine-impl.md](scanner-scheduler/scheduler-engine-impl.md)               | `crates/scanner-scheduler/src/scheduler/engine_impl.rs`  | Real engine adapter, lazy reset, zero-copy extraction  |

### Scheduler Infrastructure

| Document                                                                                 | Module                                                           | Description                                            |
| ---------------------------------------------------------------------------------------- | ---------------------------------------------------------------- | ------------------------------------------------------ |
| [scheduler-remote-backend.md](scanner-scheduler/scheduler-remote-backend.md)             | `crates/scanner-scheduler/src/scheduler/remote.rs`               | HTTP/object-store backend, retry policies              |
| [scheduler-local-fs-uring.md](scanner-scheduler/scheduler-local-fs-uring.md)             | `crates/scanner-scheduler/src/scheduler/local_fs_uring.rs`       | Linux io_uring async I/O, SQE/CQE management           |
| [scheduler-ts-buffer-pool.md](scanner-scheduler/scheduler-ts-buffer-pool.md)             | `crates/scanner-scheduler/src/scheduler/ts_buffer_pool.rs`       | Thread-safe buffer recycling, work-conserving stealing |
| [scheduler-device-slots.md](scanner-scheduler/scheduler-device-slots.md)                 | `crates/scanner-scheduler/src/scheduler/device_slots.rs`         | Per-device I/O concurrency limits, backpressure        |
| [scheduler-global-resource-pool.md](scanner-scheduler/scheduler-global-resource-pool.md) | `crates/scanner-scheduler/src/scheduler/global_resource_pool.rs` | Centralized permits, SLAs, memory management           |
| [scheduler-executor.md](scanner-scheduler/scheduler-executor.md)                         | `crates/scanner-scheduler/src/scheduler/executor.rs`             | Work-stealing CPU executor, task lifecycle, shutdown    |
| [archive-scanning.md](scanner-scheduler/archive-scanning.md)                             | `crates/scanner-scheduler/src/archive/`                          | Archive parsing (tar/gzip/bzip2/zip), budget enforcement |

---

## 5. Persistence

| Document                                                                   | Focus                     | Key Concepts                                                |
| -------------------------------------------------------------------------- | ------------------------- | ----------------------------------------------------------- |
| [fs-persistence-pipeline.md](scanner-scheduler/fs-persistence-pipeline.md) | FS persistence write-side | StoreProducer trait, FsFindingRecord, loss accounting       |
| [persistence-identity.md](gossip-contracts/persistence-identity.md)        | Identity contracts        | Key bootstrap, rule fingerprint, secret hash, normalization |

---

## 6. Memory Management & Formal Verification

| Document                                     | Focus                    | Key Concepts                                                  |
| -------------------------------------------- | ------------------------ | ------------------------------------------------------------- |
| [memory-management.md](memory-management.md) | Buffer lifecycle & pools | BufferPool, RAII, 8MiB fixed buffers, DecodeSlab, ScanScratch |
| [kani-verification.md](kani-verification.md) | Bounded model checking   | 80 Kani proofs across 4 crates, Miri, Loom, ASAN              |

---

## 7. Testing & Simulation

| Document                                                                             | Focus                         | Key Concepts                                           |
| ------------------------------------------------------------------------------------ | ----------------------------- | ------------------------------------------------------ |
| [simulation-harness.md](gossip-coordination/simulation-harness.md)                   | Deterministic simulation      | FoundationDB-style, VOPR-inspired, fault injection     |
| [coordination-testing.md](gossip-coordination/coordination-testing.md)               | Coordination test tiers       | Isolation, invariant interaction, workflow, randomized |
| [counterexample-testing-unification.md](counterexample-testing-unification.md)       | Counterexample-driven testing | Unified approach across subsystems                     |
| [scanner_harness_modes.md](scanner-scheduler/scanner_harness_modes.md)               | Scanner test modes            | Mode 1 (synthetic stress) vs Mode 2 (real ruleset)     |
| [scanner_test_harness_guide.md](scanner-scheduler/scanner_test_harness_guide.md)     | Scanner simulation harness    | Corpus replay, random stress, deterministic oracles    |
| [scheduler_test_harness_guide.md](scanner-scheduler/scheduler_test_harness_guide.md) | Scheduler simulation harness  | Work-stealing policy checks, deterministic replay      |
| [git_simulation_harness_guide.md](scanner-git/git_simulation_harness_guide.md)       | Git simulation harness        | Stage model, fault injection, corpus replay            |
| [simulation-framework.md](scanner-scheduler/simulation-framework.md)                 | Scanner simulation framework  | SimClock, fault injection, mutation testing, minimization |

### Evaluation & Accuracy

| Document                           | Focus                                                                   |
| ---------------------------------- | ----------------------------------------------------------------------- |
| [eval-harness.md](eval-harness.md) | Precision/recall measurement against labeled corpora, regression gating |

---

## 8. Consolidation & Parity

| Document                                         | Focus                                                |
| ------------------------------------------------ | ---------------------------------------------------- |
| [scanner-core-parity.md](scanner-core-parity.md) | Scanner core parity gate for `crates/scanner-engine` |

---

## 9. Shared Infrastructure & Runtime

| Document                                                       | Crate                          | Focus                                                         |
| -------------------------------------------------------------- | ------------------------------ | ------------------------------------------------------------- |
| [gossip-scanner-runtime.md](gossip-scanner-runtime.md)         | `crates/gossip-scanner-runtime/` | Runtime orchestration: CLI, distributed mode, output sinks    |
| [gossip-scan-driver.md](gossip-scan-driver.md)                 | `crates/gossip-scan-driver/`     | Scan driver abstraction: Assignment, ScanSourceFactory, ScanDriver |
| [gossip-worker.md](gossip-worker.md)                           | `crates/gossip-worker/`          | Distributed worker binary: CLI, scan dispatch, tracing        |
| [scanner-rs-cli.md](scanner-rs-cli.md)                         | `crates/scanner-rs-cli/`         | Standalone CLI binary: argument parsing, output formats       |
| [shard-algebra.md](gossip-frontier/shard-algebra.md)           | `crates/gossip-frontier/`        | Shard algebra: key encoding, range arithmetic, hint framing   |
| [gossip-stdx.md](gossip-stdx.md)                               | `crates/gossip-stdx/`            | Shared data structures: ByteSlab, InlineVec, RingBuffer, TimingWheel, etc. |

---

## Performance Findings

Reports from benchmark and analysis sessions, stored in [`findings/`](findings/).

| Report                                                                                                      | Topic                                 |
| ----------------------------------------------------------------------------------------------------------- | ------------------------------------- |
| [2026-02-07-fs-scan-transform-overhead.md](findings/2026-02-07-fs-scan-transform-overhead.md)               | FS scan transform overhead analysis   |
| [2026-02-08-baseline-data-layout-benchmarks.md](findings/2026-02-08-baseline-data-layout-benchmarks.md)     | Baseline data layout benchmarks       |
| [2026-02-08-comparison-data-layout-benchmarks.md](findings/2026-02-08-comparison-data-layout-benchmarks.md) | Comparison data layout benchmarks     |
| [2026-02-11-scanner-comparison-fp-gap.md](findings/2026-02-11-scanner-comparison-fp-gap.md)                 | Scanner comparison false-positive gap |

Chart assets: [`assets/charts/`](assets/charts/) (scan-time, cold-warm-ratio, memory-rss, throughput SVGs).

---

## Finding Documentation

### By Task

| I want to...                        | Read this                                                                                                                                                     |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Understand the overall architecture | [architecture-overview.md](architecture-overview.md)                                                                                                          |
| Learn how detection works           | [detection-engine.md](scanner-engine/detection-engine.md)                                                                                                     |
| Add a new detection rule            | [detection-rules.md](scanner-engine/detection-rules.md)                                                                                                       |
| Understand the pipeline             | [pipeline-flow.md](pipeline-flow.md) → [pipeline-state-machine.md](pipeline-state-machine.md)                                                                 |
| Work on the scheduler               | [scheduler-engine-abstraction.md](scanner-scheduler/scheduler-engine-abstraction.md) → [scheduler-task-graph.md](scanner-scheduler/scheduler-task-graph.md)   |
| Work on coordination                | [boundary-2-coordination.md](gossip-coordination/boundary-2-coordination.md) → [coordination-testing.md](gossip-coordination/coordination-testing.md)         |
| Understand boundary contracts       | [boundary-1-identity-spine.md](gossip-contracts/boundary-1-identity-spine.md) through [boundary-5-persistence.md](gossip-contracts/boundary-5-persistence.md) |
| Debug memory issues                 | [memory-management.md](memory-management.md)                                                                                                                  |
| Add transform support               | [engine-transforms.md](scanner-engine/engine-transforms.md) → [transform-chain.md](scanner-engine/transform-chain.md)                                         |
| Understand window validation        | [engine-window-validation.md](scanner-engine/engine-window-validation.md)                                                                                     |
| Understand offline validation       | [engine-offline-validation.md](scanner-engine/engine-offline-validation.md)                                                                                   |
| Understand engine internals         | [engine-internals.md](scanner-engine/engine-internals.md)                                                                                                     |
| Understand the API surface          | [engine-api-types.md](scanner-engine/engine-api-types.md)                                                                                                     |
| Understand anchor extraction        | [regex-to-anchor-extraction.md](scanner-engine/regex-to-anchor-extraction.md)                                                                                 |
| Understand content detection        | [content-policy-and-caching.md](scanner-engine/content-policy-and-caching.md)                                                                                 |
| Understand the work-stealing executor | [scheduler-executor.md](scanner-scheduler/scheduler-executor.md)                                                                                            |
| Understand archive scanning         | [archive-scanning.md](scanner-scheduler/archive-scanning.md)                                                                                                  |
| Understand git pack internals       | [git-pack-execution.md](scanner-git/git-pack-execution.md)                                                                                                    |
| Understand coordination errors      | [coordination-error-model.md](gossip-coordination/coordination-error-model.md)                                                                                |
| Understand scanner simulation       | [simulation-framework.md](scanner-scheduler/simulation-framework.md)                                                                                          |
| Understand FS persistence           | [fs-persistence-pipeline.md](scanner-scheduler/fs-persistence-pipeline.md)                                                                                    |
| Understand persistence identity     | [persistence-identity.md](gossip-contracts/persistence-identity.md)                                                                                           |
| Measure scanner accuracy            | [eval-harness.md](eval-harness.md)                                                                                                                            |
| Write simulation tests              | [simulation-harness.md](gossip-coordination/simulation-harness.md) → [counterexample-testing-unification.md](counterexample-testing-unification.md)           |
| Understand Kani proofs              | [kani-verification.md](kani-verification.md)                                                                                                                  |
| Understand the scan driver seam     | [gossip-scan-driver.md](gossip-scan-driver.md)                                                                                                                |
| Work on scanner runtime / CLI       | [gossip-scanner-runtime.md](gossip-scanner-runtime.md)                                                                                                        |
| Understand the worker binary        | [gossip-worker.md](gossip-worker.md)                                                                                                                          |
| Understand the CLI binary           | [scanner-rs-cli.md](scanner-rs-cli.md)                                                                                                                        |
| Understand shard key encoding       | [shard-algebra.md](gossip-frontier/shard-algebra.md)                                                                                                          |
| Find the right data structure       | [gossip-stdx.md](gossip-stdx.md)                                                                                                                              |

---

## External Resources

### Tools & Dependencies
- [Vectorscan](https://github.com/VectorCamp/vectorscan) - Pattern matching library (Hyperscan fork)
- [Kani](https://model-checking.github.io/kani/) - Rust verification tool
- [Criterion](https://github.com/bheisler/criterion.rs) - Benchmarking framework

### Related Projects
- [gitleaks](https://github.com/gitleaks/gitleaks) - Source of rule definitions
- [TigerBeetle](https://github.com/tigerbeetle/tigerbeetle) - Inspiration for defensive programming style
- [FoundationDB](https://github.com/apple/foundationdb) - Inspiration for simulation testing

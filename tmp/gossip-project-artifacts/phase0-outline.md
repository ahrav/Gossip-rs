# Phase 0: `gossip-contracts` Crate Scaffolding

## Goal

Stand up the `gossip-contracts` crate so that `cargo build` and `cargo test` succeed from day one, with the module hierarchy, dependency declarations, feature flags, and foundational infrastructure in place. Every subsequent phase (B1 implementation through B5) drops code into this skeleton without structural changes.

## Why Phase 0 Exists as a Separate Effort

Three things block productivity if they aren't resolved upfront:

1. **Dependency on shared infrastructure.** Every boundary file assumes `CanonicalBytes`, `define_id_32!`, `domain_hasher`, and `finalize_32` exist. Without these, nothing compiles â€” not even type stubs. They must land first, and they must land in a location that all submodules can reach.

2. **Domain constant scattering.** The boundary drafts define domain separation tags in three different places (B1C1 has coordination domains, B1C4 has identity domains, B5C1 has persistence domains). In the crate, these must live in a single authoritative module to prevent duplication and to make the domain tag registry auditable. This consolidation is a one-time structural decision.

3. **Feature flag design.** The in-memory test doubles (B4C4 `DeterministicConnector`, B5C4 `InMemoryDoneLedger` / `InMemoryFindingsSink`) need to be conditionally compiled. The feature flag structure affects `Cargo.toml`, module visibility, and `cfg` attributes across the entire crate. Deciding this after code exists means retrofitting.

---

## Epic 1: Crate Creation & Workspace Integration

### Why

The crate must exist as a compilable workspace member before any contract code can land. This includes the manifest, the workspace membership declaration, and a minimal `lib.rs` that compiles.

### 1.1 â€” Create `Cargo.toml`

**Task:** Create `gossip-contracts/Cargo.toml` with package metadata, edition (2021), and the Rust version floor.

**Context:** The crate is a library (`[lib]`). It has no binaries. The package name should match the directory name for cargo convention. Set `publish = false` since this is an internal crate.

**Acceptance:** `cargo check -p gossip-contracts` succeeds with an empty `lib.rs`.

### 1.2 â€” Register in Workspace

**Task:** Add `gossip-contracts` to the workspace `members` list in the root `Cargo.toml`.

**Context:** If no workspace exists yet, this task also creates the root `Cargo.toml` with `[workspace]`. The workspace will eventually contain other crates (connectors, runtime, CLI), but `gossip-contracts` is the first.

**Acceptance:** `cargo build` from the workspace root compiles `gossip-contracts`.

### 1.3 â€” Create Minimal `lib.rs`

**Task:** Create `gossip-contracts/src/lib.rs` with `#![forbid(unsafe_code)]` and a module-level doc comment explaining the crate's purpose.

**Context:** The `#![forbid(unsafe_code)]` attribute is a project-wide decision: the contracts crate is pure computation with no FFI, no raw pointers, no `unsafe`. This is enforced at the crate level, not per-module. Every boundary draft file includes this attribute.

**Acceptance:** `cargo build -p gossip-contracts` succeeds. `cargo clippy -p gossip-contracts` has zero warnings.

---

## Epic 2: Dependency Declaration & Feature Flags

### Why

All five boundaries depend on `blake3` for content-addressed hashing. Property-based tests need `proptest`. The in-memory test doubles from B4C4 and B5C4 should only compile when explicitly requested (for testing) â€” they pull in `HashMap`, add code to the binary, and are reference implementations that should not be accidentally used in production paths.

### 2.1 â€” Declare Runtime Dependencies

**Task:** Add `blake3` to `[dependencies]` in `Cargo.toml`.

**Context:** `blake3` is the only runtime dependency for Phase 0. It provides `Hasher`, `new_keyed`, and the derive-key context mode. Every ID derivation, domain-tagged hash, and keyed secret hash in the contracts goes through `blake3`. Pin to a specific minor version (e.g., `"1.5"`) rather than `"*"` for reproducible builds.

No other runtime dependencies are needed at this point. The contracts crate is intentionally dependency-light â€” it defines types, traits, and pure functions.

**Acceptance:** `use blake3::Hasher;` compiles in `lib.rs`.

### 2.2 â€” Declare Dev Dependencies

**Task:** Add `proptest` to `[dev-dependencies]` in `Cargo.toml`.

**Context:** Property-based tests are the primary verification strategy for B1 (identity spine) and B3 (shard algebra). The B1C1-2 draft already uses `proptest::proptest!` macro, `proptest::num::u64::ANY`, `proptest::collection::vec`, and `proptest::array::uniform32`. These tests run during `cargo test` but do not affect the compiled library.

**Acceptance:** A `#[cfg(test)]` module in `lib.rs` can `use proptest::proptest;` and compile.

### 2.3 â€” Define the `test-support` Feature Flag

**Task:** Add a `[features]` section to `Cargo.toml` with a `test-support` feature that has no dependencies.

```toml
[features]
default = []
test-support = []
```

**Context:** This feature gates the in-memory test doubles (B5C4's `InMemoryDoneLedger`, `InMemoryFindingsSink`; B4C4's `DeterministicConnector`) and any test helper functions that other crates need. The distinction from `#[cfg(test)]` matters: `#[cfg(test)]` code is only available within the contracts crate's own test suite. `test-support` code is available to downstream crates that declare `gossip-contracts = { features = ["test-support"] }` â€” which the runtime crate's integration tests will need.

**Design rule:** In-memory implementations go behind `#[cfg(feature = "test-support")]`. `#[cfg(test)]` modules within the contracts crate itself should *also* enable the `test-support` feature via a `[dev-dependencies.self]` pattern or by using `#[cfg(any(test, feature = "test-support"))]` on the relevant modules.

**Acceptance:** `cargo build -p gossip-contracts` compiles without the feature. `cargo build -p gossip-contracts --features test-support` also compiles. No test double code is included in the default build.

---

## Epic 3: Module Hierarchy & Re-exports

### Why

The module tree mirrors the five-boundary decomposition. Getting this right now means implementation chunks (Phase 1 through Phase 5) drop code into existing modules without restructuring. The hierarchy also enforces visibility: types that must only be constructed through controlled derivation functions (e.g., `NormHash`, `SecretHash`) use `pub(crate)` constructors, which only works if the derivation function and the type live in the same crate.

### 3.1 â€” Create the Module Directory Structure

**Task:** Create the following directory and file structure under `gossip-contracts/src/`:

```
src/
â”œâ”€â”€ lib.rs
â”œâ”€â”€ identity/
â”‚   â””â”€â”€ mod.rs
â”œâ”€â”€ coordination/
â”‚   â””â”€â”€ mod.rs
â”œâ”€â”€ shard/
â”‚   â””â”€â”€ mod.rs
â”œâ”€â”€ connector/
â”‚   â””â”€â”€ mod.rs
â””â”€â”€ persistence/
    â””â”€â”€ mod.rs
```

**Context â€” what maps where:**

| Module | Boundary | Content Summary | Source Drafts |
|--------|----------|----------------|---------------|
| `identity` | B1 (all chunks) | Encoding infra (`CanonicalBytes`, macros), all ID types (`TenantId`, `SecretHash`, `FindingId`...), derivation functions (`key_secret_hash`, `derive_finding_id`...), `PolicyHash` | `boundary_1_chunks_1_2.rs`, `boundary_1_chunk_3.rs`, `boundary_1_chunk_4.rs`, `boundary_1_chunk_5.rs` |
| `coordination` | B2 (all chunks) | `Cursor`, `ShardSpec`, `ShardRecord`, `Lease`, `FenceEpoch` (moved from B1), `CoordinationBackend` trait, `RunRecord`, `WorkerSession`, error types | `boundary_2_chunk_1.rs` through `boundary_2_chunk_5.rs` |
| `shard` | B3 (all chunks) | Key encoding schemas (`PathKey`, `NumericPrefixKey`...), key range algebra, split key computation, ordering proofs, coverage verification | `boundary_3_chunk_1.rs` through `boundary_3_chunk_5.rs` |
| `connector` | B4 (all chunks) | `ScanItem`, `ItemRef`, `VersionId`, `EnumerationPage`, `EnumerationConnector` trait, `ReadConnector` trait, `PageValidation`, cursor extraction, error-to-`ParkReason` mapping, `CircuitBreakerState`/`CircuitConfig`, `ConnectorRegistration`, `ItemOutcome`, `ShardScanStats`, `DeterministicConnector` (behind feature flag) | `boundary_4_chunk_1.rs` through `boundary_4_chunk_5.rs` |
| `persistence` | B5 (all chunks) | `DoneLedgerKey`, `OvidHash`, `DoneLedger` trait, `TriageGroupKey`, `RuleName`, `FindingRecord`/`FindingRecordBuilder`, `OccurrenceRecord`/`OccurrenceRecordBuilder`, `FindingsUpsertBatch`, `FindingsSink` trait, `PageCommit<S>` typestate machine, `CommitProof`, in-memory implementations (behind feature flag) | `boundary_5_chunk_1.rs` through `boundary_5_chunk_5.rs` |

All 26 boundary draft files are present in the project. No implementation gaps remain in the draft coverage.

**Acceptance:** Every module directory exists. Each `mod.rs` is a valid (possibly empty) Rust file. `lib.rs` declares all five modules.

### 3.2 â€” Wire Modules in `lib.rs`

**Task:** Add `pub mod` declarations in `lib.rs` for all five modules. Add a crate-level doc comment that describes the boundary layering and dependency direction.

**Context:** The dependency direction between modules is strictly acyclic:

```
identity â† coordination â† shard â† connector â† persistence
   â†‘                                    â†‘            â†‘
   â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜            â”‚
   â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
```

In other words: `persistence` can `use crate::identity::*`, `use crate::coordination::*`, and `use crate::connector::*`. But `identity` cannot use anything from `coordination` or later modules. This mirrors the boundary dependency maps documented in each chunk 5 file.

The `lib.rs` should also re-export the most commonly used types at the crate root for ergonomic imports. This re-export list will grow during implementation â€” for Phase 0, it can be empty or contain only a placeholder comment.

**Acceptance:** `cargo build -p gossip-contracts` succeeds with all modules declared.

### 3.3 â€” Create Stub `mod.rs` for Each Module

**Task:** Each module's `mod.rs` should contain a module-level doc comment explaining what the module will contain (one paragraph), and nothing else. No types, no functions, no imports.

**Context:** The doc comments serve as implementation anchors. When Phase 1 starts (B1 implementation), the developer opens `identity/mod.rs` and sees exactly what goes here. Example for `identity/mod.rs`:

```rust
//! Identity spine types and derivation functions.
//!
//! This module defines all content-addressed identities used across
//! the scanner: TenantId, SecretHash, FindingId, OccurrenceId, and
//! their derivation functions. It also provides the shared encoding
//! infrastructure (CanonicalBytes trait, domain-tagged hashing, and
//! the ID newtype macros) that all other modules depend on.
```

**Acceptance:** Each `mod.rs` has a doc comment. `cargo doc -p gossip-contracts` generates documentation for all five modules.

---

## Epic 4: Foundational Infrastructure

### Why

This is the one piece of *implementation* that belongs in Phase 0 rather than Phase 1. Every boundary file opens with `use crate::{CanonicalBytes, Hasher}` or invokes `define_id_32!`. Without these, not even the type stubs in later epics will compile. The infrastructure is small (roughly 120 lines of code from B1C1), has no dependencies on any other module, and is the absolute leaf of the dependency graph.

### 4.1 â€” `CanonicalBytes` Trait and Primitive Implementations

**Task:** Implement the `CanonicalBytes` trait and its implementations for `u8`, `u32`, `u64`, `[u8]`, and `[u8; 32]` in the `identity` module.

**Reference code:** `boundary_1_chunks_1_2.rs` lines 68â€“145.

**Context:** `CanonicalBytes` is the trait that every type participating in content-addressed hashing must implement. The invariants are documented in the draft:
- **Collision-freedom:** Distinct values produce distinct byte sequences (variable-length fields are length-prefixed).
- **Determinism:** Output is identical across platforms and Rust versions (fixed-endian, little-endian by convention).
- **No allocation:** Implementations feed directly into the hasher.

The primitive implementations are building blocks. The `[u8]` impl uses a 4-byte LE length prefix. The `[u8; 32]` impl has no length prefix (fixed width).

**Acceptance:** All five `CanonicalBytes` impls compile. The three tests from B1C1 pass: `canonical_bytes_u64_deterministic`, `canonical_bytes_slice_length_prefixed`, `canonical_bytes_concatenation_unambiguous`.

### 4.2 â€” `domain_hasher` and `finalize_32` Helper Functions

**Task:** Implement the two hashing helpers that every derivation function uses.

**Reference code:** `boundary_1_chunks_1_2.rs` â€” these aren't shown inline in the draft but are referenced throughout. The pattern is:

```rust
/// Create a BLAKE3 hasher initialized with a domain separation context.
pub fn domain_hasher(context: &[u8]) -> blake3::Hasher {
    blake3::Hasher::new_derive_key(
        core::str::from_utf8(context).expect("domain tag must be valid UTF-8")
    )
}

/// Finalize a hasher into a 32-byte array.
pub fn finalize_32(hasher: &blake3::Hasher) -> [u8; 32] {
    *hasher.finalize().as_bytes()
}
```

**Context:** `domain_hasher` uses BLAKE3's derive-key mode (`new_derive_key`), which takes a context string and produces a domain-separated key derivation. This is the mechanism that prevents cross-domain collisions: `blake3("gossip/finding/v1", data)` can never collide with `blake3("gossip/occurrence/v1", data)` even for identical `data`. Every ID derivation in the system goes through this.

`finalize_32` is trivial but exists to avoid the `.finalize().as_bytes()` incantation everywhere.

**Visibility:** Both functions should be `pub` within the crate. Whether they're re-exported at the crate root depends on whether external crates (connectors) need to derive IDs â€” they do (connectors compute `ConnectorInstanceId`), so these should be `pub` and re-exported.

**Acceptance:** `domain_hasher(b"gossip/test/v1")` returns a hasher. `finalize_32(&hasher)` returns `[u8; 32]`. Two hashers with the same domain and data produce identical output. Two hashers with different domains and identical data produce different output.

### 4.3 â€” `define_id_32!` and `define_id_32_restricted!` Macros

**Task:** Implement both ID newtype macros.

**Reference code:** `boundary_1_chunks_1_2.rs` lines 161â€“240.

**Context:** These macros are the factory for every 32-byte identity type in the system. They generate:
- The struct (with `pub` or private inner field)
- `Clone`, `Copy`, `PartialEq`, `Eq`, `PartialOrd`, `Ord`, `Hash` derives
- Safe `Debug` implementation (hex prefix for `define_id_32!`, `[redacted]` for `define_id_32_restricted!`)
- `CanonicalBytes` implementation (fixed-width, no length prefix)
- `ZERO` constant and accessors

The distinction matters for safety: `define_id_32!` produces freely constructible types (like `TenantId`, `FindingId`). `define_id_32_restricted!` produces types where only the contracts crate's derivation functions can construct instances (like `NormHash`, `SecretHash`). The restricted variant uses `pub(crate) const fn from_bytes_internal` instead of `pub const fn from_bytes`.

**Acceptance:** Can invoke `define_id_32!{ TestId }` in a test module and construct `TestId::from_bytes([0u8; 32])`. Can invoke `define_id_32_restricted!{ TestRestricted, debug_display = "TestRestricted([redacted])" }` and verify that `from_bytes_internal` is not accessible from outside the crate. `Debug` output matches expectations.

---

## Epic 5: Domain Constant Registry

### Why

Domain separation tags are the most critical anti-collision mechanism in the system. If two derivation functions accidentally share a domain tag, their outputs can collide â€” which means two different identity types could produce the same 32-byte value, breaking the entire deduplication model. The domain tag registry must be a single, auditable module where every tag is defined exactly once.

The boundary drafts scatter these across three locations:

| Location | Tags Defined |
|----------|-------------|
| `boundary_1_chunks_1_2.rs` (`domain` module) | `SPLIT_ID_V1`, `OP_PAYLOAD_V1`, `FINDING_ID_V1`, `OCCURRENCE_ID_V1`, `SECRET_HASH_V1` |
| `boundary_1_chunk_3.rs` (added to `domain`) | `ITEM_ID_V1`, `OBJECT_VERSION_V1` |
| `boundary_1_chunk_4.rs` (repeated in `domain`) | `SECRET_HASH_V1`, `FINDING_ID_V1`, `OCCURRENCE_ID_V1`, `RULE_FINGERPRINT_V1` |
| `boundary_1_chunk_5.rs` (implied) | `RULES_DIGEST_V1`, `POLICY_HASH_V1` |
| `boundary_5_chunk_1.rs` (`domain_b5`) | `OVID_V1`, `DONE_LEDGER_KEY_V1` |
| `boundary_5_chunk_2.rs` (`domain_findings`) | `TRIAGE_GROUP_KEY_V1` |

Several tags appear in multiple files (e.g., `SECRET_HASH_V1` in both B1C1 and B1C4). In the crate, there must be exactly one definition.

### 5.1 â€” Audit All Domain Tags Across Boundary Drafts

**Task:** Enumerate every domain separation constant from all boundary draft files. Produce a deduplicated list with the subsystem each tag belongs to and the derivation function that uses it.

**Context:** This is a manual audit step. The output is a table that becomes the source of truth. Any tag missing from this table is a bug. Any tag appearing twice with different byte values is a critical defect.

**Acceptance:** A complete table exists. No duplicates. Every tag follows the naming convention: `"gossip/<subsystem>/v<N>/<operation>"` (or `"gossip/<subsystem>/v<N>"` for simple derivations).

### 5.2 â€” Create Unified `domain` Module

**Task:** Create a `domain` module (either as a top-level module in `lib.rs` or nested within `identity/`) containing every domain constant as a `pub const`.

**Context:** The module should be organized by subsystem with doc comments explaining which derivation function uses each tag. Group them logically:

- Coordination subsystem: `SPLIT_ID_V1`, `OP_PAYLOAD_V1`
- Identity subsystem: `FINDING_ID_V1`, `OCCURRENCE_ID_V1`, `SECRET_HASH_V1`, `RULE_FINGERPRINT_V1`, `ITEM_ID_V1`, `OBJECT_VERSION_V1`
- Policy subsystem: `RULES_DIGEST_V1`, `POLICY_HASH_V1`
- Persistence subsystem: `OVID_V1`, `DONE_LEDGER_KEY_V1`, `TRIAGE_GROUP_KEY_V1`

**Placement decision:** The domain module logically belongs in `identity/` because the domain-tagging mechanism is part of the hashing infrastructure. But it's used by every other module. Two options: (a) place it in `identity/domain.rs` and re-export from the crate root, or (b) place it as a top-level `domain.rs` module. Option (a) keeps the infrastructure grouped; option (b) avoids `identity` becoming a grab-bag. Both work â€” pick one and document the decision.

**Acceptance:** Every domain constant compiles. `cargo doc` shows the complete registry. A test asserts that no two constants have the same byte value.

### 5.3 â€” Domain Tag Uniqueness Test

**Task:** Write a `#[cfg(test)]` test that collects all domain constants into a `HashSet` and asserts no collisions.

**Context:** This is a meta-test â€” it validates the registry itself. If someone adds a new domain tag and accidentally copies the byte string of an existing one, this test catches it at `cargo test` time. The test should be exhaustive: every `pub const` in the `domain` module must appear in the test. If the team adds a constant to the module but forgets to add it to the test, the test is incomplete â€” but that's a human-process problem, not a code problem. A comment at the top of the test should say "add every new domain constant here."

**Acceptance:** Test passes. Intentionally duplicating a tag causes the test to fail.

---

## Epic 6: Placeholder Type Stubs (Optional Pre-work)

### Why

This epic is optional for Phase 0 but reduces friction for Phase 1. If the `identity` module exports `TenantId`, `PolicyHash`, and the coordination scalar types (`ShardId`, `WorkerId`, etc.) as stubs, then the `coordination` module stub can reference them in doc comments and future imports without forward-declaration gymnastics.

The reason this is "optional" is that Phase 1 (B1 implementation) will immediately fill in these types for real. If Phase 1 starts the same day Phase 0 finishes, the stubs are unnecessary. If there's a gap (e.g., Phase 0 is done by one person, Phase 1 by another, with a handoff), the stubs help.

### 6.1 â€” Scalar Coordination ID Stubs

**Task:** Using the infrastructure from Epic 4, declare the `u64`-width coordination types in the `identity` module: `ShardId`, `WorkerId`, `FenceEpoch`, `LogicalTime`, `JobId`, `OpId`.

**Reference code:** `boundary_1_chunks_1_2.rs` lines 241â€“577 (the newtype wrappers and their impls).

**Context:** These are simple `pub struct FooId(pub u64)` newtypes with `Debug`, `Clone`, `Copy`, `PartialEq`, `Eq`, `PartialOrd`, `Ord`, `Hash`. They don't use the `define_id_32!` macro â€” they're 8 bytes, not 32. `FenceEpoch` has special semantics (`INITIAL = 1`, saturating `next()`). `LogicalTime` has `ZERO` and `tick()`.

These are the lowest-risk types to implement because they're trivial newtypes with no derivation logic.

**Acceptance:** All six types compile. `FenceEpoch::INITIAL.next()` returns `FenceEpoch(2)`. `FenceEpoch(u64::MAX).next()` returns `FenceEpoch(u64::MAX)` (saturating).

### 6.2 â€” 32-Byte Identity Type Stubs

**Task:** Using `define_id_32!` and `define_id_32_restricted!`, declare the 32-byte identity types: `TenantId`, `PolicyHash`, `StableItemId`, `ObjectVersionId`, `FindingId`, `OccurrenceId`, `RuleFingerprint` (all `define_id_32!`), and `NormHash`, `SecretHash`, `TenantSecretKey` (all `define_id_32_restricted!`).

**Reference code:** `boundary_1_chunks_1_2.rs` (TenantId, PolicyHash, TenantSecretKey), `boundary_1_chunk_3.rs` (StableItemId, ObjectVersionId), `boundary_1_chunk_4.rs` (NormHash, SecretHash, RuleFingerprint, FindingId, OccurrenceId).

**Context:** At this stage, these are just the type declarations â€” no derivation functions yet (those come in Phase 1, chunks 3â€“5). The types need to exist so that downstream modules can reference them in signatures and doc comments.

**Acceptance:** All types compile. Restricted types cannot be constructed from outside the crate. `Debug` output is correct (hex prefix for public types, `[redacted]` for restricted types).

---

## Epic 7: Build Verification & Quality Gates

### Why

Phase 0 is complete when the crate compiles, tests pass, lints are clean, and documentation generates. These checks should be automated from day one so that Phase 1 implementation has a safety net.

### 7.1 â€” Verify Default Build

**Task:** `cargo build -p gossip-contracts` succeeds with zero warnings.

**Context:** Use `#![warn(missing_docs)]` if the team wants to enforce documentation on all public items from the start. This is recommended â€” the contracts crate is the API surface for the entire system, and undocumented public items are a maintenance hazard. An alternative is `#![deny(missing_docs)]` but that can be frustrating during early development; `warn` is friendlier.

**Acceptance:** Clean build, zero warnings.

### 7.2 â€” Verify Feature-Gated Build

**Task:** `cargo build -p gossip-contracts --features test-support` succeeds.

**Context:** At this point, the `test-support` feature doesn't gate any code yet. This task verifies the plumbing works so that when B4C4/B5C4 implementations land, the feature flag is ready.

**Acceptance:** Both `cargo build` and `cargo build --features test-support` succeed.

### 7.3 â€” Verify Test Suite

**Task:** `cargo test -p gossip-contracts` passes. This should run the infrastructure tests from Epic 4 (CanonicalBytes determinism, concatenation unambiguity, domain tag uniqueness) and the proptest smoke tests.

**Context:** The proptest tests from B1C1 (`canonical_bytes_u64_stable`, `canonical_bytes_slice_stable`, `canonical_bytes_tenant_id_stable`) should be included. They run 256 cases by default and take under a second. They validate the most foundational invariant: encoding determinism.

**Acceptance:** `cargo test -p gossip-contracts` reports all tests passing. At least 5 tests exist (3 unit + 2 proptest minimum).

### 7.4 â€” Verify Linting and Formatting

**Task:** `cargo clippy -p gossip-contracts -- -D warnings` and `cargo fmt -p gossip-contracts -- --check` both pass.

**Context:** Clippy catches common Rust anti-patterns. Running it with `-D warnings` (deny) ensures no clippy warning is ignored. `cargo fmt --check` ensures consistent formatting without actually modifying files.

**Acceptance:** Both commands exit with code 0.

### 7.5 â€” Verify Documentation Generation

**Task:** `cargo doc -p gossip-contracts --no-deps` succeeds and produces navigable HTML.

**Context:** Every module should have a doc comment (from Epic 3.3). The `domain` module should show all constants. The macros and traits from Epic 4 should have their invariants documented.

**Acceptance:** Documentation generates. Navigating to each module in the browser shows the doc comment.

---

## Dependency Graph Between Epics

```
Epic 1 (crate creation)
  â””â”€â–º Epic 2 (dependencies & features)
        â””â”€â–º Epic 3 (module hierarchy)
              â””â”€â–º Epic 4 (foundational infrastructure)
                    â”œâ”€â–º Epic 5 (domain constants)
                    â””â”€â–º Epic 6 (type stubs, optional)
                          â””â”€â–º Epic 7 (build verification)
```

Epics 1â€“4 are strictly sequential. Epic 5 can parallelize with Epic 6 once Epic 4 is done. Epic 7 runs last as integration verification.

---

## What Phase 0 Does NOT Include

These are explicitly deferred to later phases to keep Phase 0 scoped:

- **Derivation functions** (`key_secret_hash`, `derive_finding_id`, `derive_occurrence_id`, `compute_policy_hash`). These are B1 implementation work (Phase 1, chunks 3â€“5).
- **Composite types** (`ItemKey`, `RunId`, `Lease`, `ShardRecord`). These have cross-field invariants and `CanonicalBytes` implementations that need careful testing. Phase 1.
- **Trait definitions** (`CoordinationBackend`, `DoneLedger`, `FindingsSink`, `EnumerationConnector`, `ReadConnector`). These are the contract surfaces for B2/B4/B5 and land in their respective phases. B5C2 (findings sink trait, `FindingRecord`, `OccurrenceRecord`, `TriageGroupKey`, `FindingsUpsertBatch`) and B4C3 (runtime bridge â€” `PageValidation`, cursor extraction, circuit breaker, `ConnectorRegistration`, `ItemOutcome`) are now fully drafted and ready for implementation in those phases.
- **Typestate commit protocol** (`PageCommit<S>`). This is B5C3 and depends on the traits above.
- **In-memory test doubles**. These implement the traits above and land behind the `test-support` feature flag in Phase 5.
- **Integration tests**. These compose multiple boundaries and land in Phase 5 (B5C5).
- **TLA+ specifications**. These target the coordination state machine (B2) and commit protocol (B5C3) and are a separate verification effort.

---

## File Reference Map

For each task that involves writing code, the boundary draft to reference:

| Task | Primary Reference File(s) | Lines of Interest |
|------|--------------------------|-------------------|
| 4.1 CanonicalBytes | `boundary_1_chunks_1_2.rs` | 68â€“145 (trait + impls) |
| 4.2 domain_hasher / finalize_32 | `boundary_1_chunks_1_2.rs` | Pattern used throughout; see `derive_split_shard_id` for usage example |
| 4.3 ID macros | `boundary_1_chunks_1_2.rs` | 161â€“240 (both macros) |
| 5.2 Domain constants | `boundary_1_chunks_1_2.rs` (coord), `boundary_1_chunk_3.rs` (item/version), `boundary_1_chunk_4.rs` (secret/finding/rule), `boundary_5_chunk_1.rs` (persistence) | Domain module sections in each file |
| 6.1 Scalar IDs | `boundary_1_chunks_1_2.rs` | 241â€“577 (ShardId through RunId) |
| 6.2 32-byte ID stubs | `boundary_1_chunks_1_2.rs` (TenantId, PolicyHash), `boundary_1_chunk_3.rs` (StableItemId, ObjectVersionId), `boundary_1_chunk_4.rs` (NormHash, SecretHash, etc.) | Type definition sections in each file |

### Post-Phase 0: Complete Boundary-to-Module Reference

Every boundary draft is now present in the project. For implementation phases, here is the full mapping:

| Module | Implementation Phase | All Draft Files |
|--------|---------------------|-----------------|
| `identity/` | Phase 1 (B1) | `boundary_1_chunks_1_2.rs`, `boundary_1_chunk_3.rs`, `boundary_1_chunk_4.rs`, `boundary_1_chunk_5.rs` |
| `coordination/` | Phase 2 (B2) | `boundary_2_chunk_1.rs` (Cursor, ShardSpec), `boundary_2_chunk_2.rs` (ShardRecord, Lease), `boundary_2_chunk_3.rs` (CoordinationBackend trait), `boundary_2_chunk_4.rs` (RunRecord, admin ops), `boundary_2_chunk_5.rs` (WorkerSession, op-log, facade) |
| `shard/` | Phase 3 (B3, parallelizable with Phase 2) | `boundary_3_chunk_1.rs` (key encoding), `boundary_3_chunk_2.rs` (range algebra), `boundary_3_chunk_3.rs` (split key computation), `boundary_3_chunk_4.rs` (ordering proofs), `boundary_3_chunk_5.rs` (coverage verification) |
| `connector/` | Phase 4 (B4) | `boundary_4_chunk_1.rs` (value types), `boundary_4_chunk_2.rs` (Enumeration/Read traits), `boundary_4_chunk_3.rs` (runtime bridge: PageValidation, cursor extraction, error mapping, CircuitBreakerState, ConnectorRegistration, ItemOutcome), `boundary_4_chunk_4.rs` (DeterministicConnector), `boundary_4_chunk_5.rs` (ShardScanStats, integration helpers, invariant catalog) |
| `persistence/` | Phase 5 (B5) | `boundary_5_chunk_1.rs` (DoneLedger types + trait), `boundary_5_chunk_2.rs` (TriageGroupKey, RuleName, FindingRecord/Builder, OccurrenceRecord/Builder, FindingsUpsertBatch, FindingsSink trait), `boundary_5_chunk_3.rs` (commit protocol typestate), `boundary_5_chunk_4.rs` (InMemoryDoneLedger, InMemoryFindingsSink), `boundary_5_chunk_5.rs` (invariant catalog, integration tests) |

---

## Estimated Effort

| Epic | Estimated Time | Parallelizable? |
|------|---------------|-----------------|
| 1. Crate creation | 15 min | No (first) |
| 2. Dependencies & features | 15 min | No (needs Epic 1) |
| 3. Module hierarchy | 30 min | No (needs Epic 2) |
| 4. Foundational infrastructure | 1â€“2 hrs | No (needs Epic 3) |
| 5. Domain constants | 30â€“45 min | Yes (after Epic 4) |
| 6. Type stubs (optional) | 45 minâ€“1 hr | Yes (after Epic 4) |
| 7. Build verification | 15â€“30 min | No (last) |
| **Total** | **~3â€“5 hrs** | |

Phase 0 is deliberately small. The goal is to get `cargo test` green and move to Phase 1 (B1 implementation) the same day.

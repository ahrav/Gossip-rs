//! Shared contract types, encodings, and invariants for the gossip-rs distributed
//! secret scanner.
//!
//! This crate defines the boundary-oriented API surface that all runtime crates
//! depend on. It contains:
//!
//! - **Identity types** — content-addressed IDs (`TenantId`, `FindingId`, …),
//!   encoding infrastructure (`CanonicalBytes`), and domain-separated hashing.
//! - **Coordination contracts** — shard lifecycle, lease management, and the
//!   `CoordinationBackend` trait.
//! - **Shard algebra** — key encoding schemas, range arithmetic, and split
//!   computation.
//! - **Connector contracts** — enumeration/read traits and connector
//!   registration.
//! - **Persistence contracts** — done-ledger, findings-sink traits, and the
//!   commit protocol typestate machine.
//!
//! # Design principles
//!
//! 1. **No unsafe code.** This crate is pure computation — no FFI, no raw
//!    pointers.
//! 2. **Minimal dependencies.** Only `blake3` at runtime.
//! 3. **Boundary isolation.** Modules mirror the five-boundary decomposition
//!    and follow an acyclic dependency direction:
//!    `identity → coordination → shard → connector → persistence`.

#![forbid(unsafe_code)]

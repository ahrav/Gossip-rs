//! Simulation backend abstraction layer.
//!
//! Defines [`SimIntrospection`] for read-only observation of coordinator
//! state, and [`SimulationBackend`] as the combined trait bound for
//! backends usable by the simulation harness.
//!
//! # Why a separate trait?
//!
//! [`CoordinationBackend`](crate::coordination::traits::CoordinationBackend)
//! defines the mutation contract. The simulation also needs read-only
//! observation (iterating shards, point lookups) for invariant checking.
//! Keeping observation in a separate trait:
//!
//! - Avoids polluting the production mutation contract with test-only methods.
//! - Enables composition: [`FaultInjectingIntrospector`](super::fault_injector::FaultInjectingIntrospector)
//!   wraps any `SimIntrospection` impl to inject synthetic records for
//!   checker validation, without implementing the full mutation interface.
//!
//! # Consumers
//!
//! - [`InvariantChecker::check_all`](super::invariants::InvariantChecker::check_all)
//!   takes `&impl SimIntrospection` and uses [`shards()`](SimIntrospection::shards)
//!   for the S1–S7 shard-level invariant pass, [`runs()`](SimIntrospection::runs)
//!   for the S8 run-terminal irreversibility check, and
//!   [`shard_lookup()`](SimIntrospection::shard_lookup) for S7 split-coverage
//!   child verification.
//! - [`CoordinationSim`](super::harness::CoordinationSim) is generic over
//!   `B: SimulationBackend`, combining mutation and observation in one bound.
//!
//! # GAT design
//!
//! Iterator-returning methods use Generic Associated Types (GATs) rather than
//! boxed trait objects. This keeps observation paths allocation-free while
//! still allowing concrete composed iterators (for example `Chain<A, B>` in
//! wrappers).

use crate::coordination::facade::CoordinationFacade;
use crate::coordination::record::ShardRecord;
use crate::coordination::run::RunRecord;
use crate::identity::{RunId, ShardId, ShardKey, TenantId};

/// Read-only observation API for simulation backends.
///
/// Provides the shard-level introspection that the invariant checker
/// and simulation harness need to verify protocol correctness.
/// The trait intentionally hides allocator internals (`ByteSlab` and
/// `ByteSlot`): callers observe through borrowed accessors so
/// simulation logic stays storage-backend agnostic.
///
/// # Consistency contract
///
/// For a real backend, the three methods must be mutually consistent:
/// every record yielded by [`shards()`](Self::shards) must be
/// discoverable via [`shard_lookup()`](Self::shard_lookup), and
/// [`shard_count()`](Self::shard_count) must equal the iterator length.
///
/// [`FaultInjectingIntrospector`](super::fault_injector::FaultInjectingIntrospector)
/// **intentionally** violates this: synthetic records appear in
/// `shards()` but not in `shard_lookup()`, modeling scenarios where a
/// full scan reveals inconsistencies that targeted reads miss. The
/// invariant checker is designed to handle this asymmetry correctly.
///
/// # Ordering
///
/// Iteration order of [`shards()`](Self::shards) is unspecified — callers
/// must not depend on any particular ordering. All current shard-level
/// invariant checks (S1–S7) are order-independent.
pub trait SimIntrospection {
    /// Iterator over all shard records. Order is unspecified.
    ///
    /// The `where Self: 'a` bound ensures the iterator cannot outlive the
    /// borrow on `&'a self`, which is required for wrappers like
    /// [`FaultInjectingIntrospector`](super::fault_injector::FaultInjectingIntrospector)
    /// that chain the inner iterator with references to their own fields.
    type ShardIter<'a>: Iterator<Item = ((TenantId, ShardKey), &'a ShardRecord)>
    where
        Self: 'a;

    /// Iterator over all run records. Order is unspecified.
    ///
    /// Consumers must treat this as a full-scan view, not a sorted stream.
    /// Current checks only rely on set membership and terminal-state monotonicity,
    /// both of which are order-independent.
    type RunIter<'a>: Iterator<Item = ((TenantId, RunId), &'a RunRecord)>
    where
        Self: 'a;

    /// Iterator over a record's spawned child IDs.
    ///
    /// Returned as a borrowed view so callers can validate split lineage without
    /// allocating an owned child list.
    type SpawnedIter<'a>: Iterator<Item = ShardId>
    where
        Self: 'a;

    /// Iterate all shard records across all tenants.
    ///
    /// This is the primary shard observation method. The invariant checker
    /// performs a single pass over this iterator to check S1–S7 inline,
    /// with S7 issuing [`shard_lookup()`](Self::shard_lookup) calls
    /// within the same iteration to verify child shard references.
    fn shards(&self) -> Self::ShardIter<'_>;

    /// Iterate all run records across all tenants.
    ///
    /// Used by the S8 (RunTerminalIrreversibility) invariant check to
    /// verify that terminal run states never revert.
    fn runs(&self) -> Self::RunIter<'_>;

    /// Total number of shard records across all tenants.
    ///
    /// Must equal `self.shards().count()` but may be O(1) if the
    /// implementation maintains an inline counter.
    fn shard_count(&self) -> usize;

    /// Point-lookup a shard record by `(TenantId, ShardKey)`.
    ///
    /// Used by the S7 (split-coverage) check to verify that a
    /// split-parent's spawned children exist and reference the correct
    /// parent. Also used by the simulation harness to read borrowed
    /// shard bounds for cursor generation and split planning without
    /// materializing owned specs.
    ///
    /// Note: [`FaultInjectingIntrospector`](super::fault_injector::FaultInjectingIntrospector)
    /// delegates this to the inner backend only — synthetic records
    /// injected for checker validation are invisible via point lookup.
    /// See the [consistency contract](SimIntrospection#consistency-contract)
    /// discussion on the trait.
    fn shard_lookup(&self, tenant: &TenantId, key: &ShardKey) -> Option<&ShardRecord>;

    /// Return the record cursor's last-key view without allocation.
    ///
    /// Borrow is tied to `self` because pooled fields are slab-backed.
    /// Used by the checker/harness hot paths to avoid materializing owned
    /// cursor/spec values just to compare bounds/order.
    fn cursor_last_key<'a>(&'a self, record: &'a ShardRecord) -> Option<&'a [u8]>;

    /// Return the shard range bounds `[start, end)` as borrowed slices.
    ///
    /// Borrow is tied to `self` because pooled fields are slab-backed.
    /// This keeps split and cursor-bound validation allocation-free.
    fn spec_bounds<'a>(&'a self, record: &'a ShardRecord) -> (&'a [u8], &'a [u8]);

    /// Run shard-record structural validation against backend-owned storage.
    ///
    /// Backends with pooled storage use this hook to provide the required
    /// storage context (`ByteSlab`) without leaking allocator internals into
    /// simulation code.
    fn validate_record_invariants(&self, record: &ShardRecord) -> Result<(), String>;

    /// Iterate a record's spawned child IDs without materializing an owned list.
    ///
    /// Borrow is tied to `self` because pooled lineage storage is backend-owned.
    /// Iteration order is backend-defined and must be treated as unspecified.
    fn spawned_children<'a>(&'a self, record: &'a ShardRecord) -> Self::SpawnedIter<'a>;

    /// Release pooled fields for an observation-only record.
    ///
    /// This cleanup hook lets wrappers that own synthetic records
    /// (for example fault injectors) free slab-backed fields without
    /// exposing raw slab handles in the public simulation interface.
    /// Backends without pooled fields may implement this as a no-op.
    fn release_record_fields(&mut self, record: &mut ShardRecord);
}

/// Combined trait bound for backends usable by the simulation harness.
///
/// A simulation backend must support both the full coordination contract
/// (mutations via [`CoordinationFacade`]) and read-only observation
/// (via [`SimIntrospection`]).
///
/// The blanket impl means any type implementing both component traits
/// automatically satisfies `SimulationBackend`. Currently,
/// [`InMemoryCoordinator`](crate::coordination::in_memory::InMemoryCoordinator)
/// is the sole implementor.
///
/// This trait follows the same blanket-impl pattern as
/// [`CoordinationFacade`] itself: no manual `impl` blocks needed,
/// and adding a new backend requires only implementing the leaf traits.
pub trait SimulationBackend: CoordinationFacade + SimIntrospection {}
impl<T: CoordinationFacade + SimIntrospection> SimulationBackend for T {}

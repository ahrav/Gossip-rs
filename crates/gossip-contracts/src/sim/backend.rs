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
//!   for the S1–S6 sweep and [`shard_lookup()`](SimIntrospection::shard_lookup)
//!   for S7 split-coverage child verification.
//! - [`CoordinationSim`](super::harness::CoordinationSim) is generic over
//!   `B: SimulationBackend`, combining mutation and observation in one bound.
//!
//! # GAT design
//!
//! `ShardIter` uses a Generic Associated Type (GAT) rather than RPITIT
//! (`-> impl Iterator`) because concrete associated types enable iterator
//! composition (e.g., `Chain<A, B>`) that opaque return types prevent.
//! The explicit `'a` lifetime tied to `&'a self` makes borrow contracts
//! clear for downstream wrappers.

use crate::coordination::facade::CoordinationFacade;
use crate::coordination::record::ShardRecord;
use crate::identity::{ShardKey, TenantId};

/// Read-only observation API for simulation backends.
///
/// Provides the shard-level introspection that the invariant checker
/// and simulation harness need to verify protocol correctness.
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
/// must not depend on any particular ordering. All current invariant checks
/// (S1–S7) are order-independent.
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

    /// Iterate all shard records across all tenants.
    ///
    /// This is the primary observation method. The invariant checker
    /// performs a single pass over this iterator to check S1–S6, then
    /// uses [`shard_lookup()`](Self::shard_lookup) for S7 follow-up
    /// queries on specific child shards.
    fn shards(&self) -> Self::ShardIter<'_>;

    /// Total number of shard records across all tenants.
    ///
    /// Must equal `self.shards().count()` but may be O(1) if the
    /// implementation maintains an inline counter.
    fn shard_count(&self) -> usize;

    /// Point-lookup a shard record by `(TenantId, ShardKey)`.
    ///
    /// Used by the S7 (split-coverage) check to verify that a
    /// split-parent's spawned children exist and reference the correct
    /// parent. Also used by the simulation harness to read shard specs
    /// for cursor generation and split-point computation.
    ///
    /// Note: [`FaultInjectingIntrospector`](super::fault_injector::FaultInjectingIntrospector)
    /// delegates this to the inner backend only — synthetic records
    /// injected for checker validation are invisible via point lookup.
    /// See the [consistency contract](SimIntrospection#consistency-contract)
    /// discussion on the trait.
    fn shard_lookup(&self, tenant: &TenantId, key: &ShardKey) -> Option<&ShardRecord>;
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

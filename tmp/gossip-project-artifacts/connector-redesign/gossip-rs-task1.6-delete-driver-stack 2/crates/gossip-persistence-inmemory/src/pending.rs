//! Shared internal types for the pending-write queue used by all in-memory
//! persistence backends.
//!
//! These types are crate-private — they encode the lifecycle state of a
//! single in-memory write operation and its buffered payload.
//!
//! [`PendingOp`] and [`PendingState`] are the building blocks used by
//! [`InMemoryStoreCore`](crate::store::InMemoryStoreCore), which owns the
//! operation map, insertion-order queue, id counter, and all fault-injection
//! counters. Domain-specific apply logic (lattice merge for done-ledger,
//! referential integrity for findings) is injected through the
//! [`StoreBackend`](crate::store::StoreBackend) trait.

use crate::error::InMemoryPersistenceError;

/// Lifecycle state of a single in-memory write operation.
///
/// `Pending` -> `Finished(Some(...))` is the only valid transition.
/// The `Option` wrapper inside `Finished` exists so that
/// [`CommitHandle::wait`](gossip_contracts::persistence::CommitHandle::wait)
/// can `take()` the result exactly once — a second `wait` on the same
/// operation sees `None` and returns `UnknownOperation`.
pub(crate) enum PendingState<R> {
    Pending,
    Finished(Option<Result<R, InMemoryPersistenceError>>),
}

impl<R> PendingState<R> {
    #[inline]
    pub(crate) fn is_pending(&self) -> bool {
        matches!(self, Self::Pending)
    }
}

/// A buffered write operation: the payload to apply and its lifecycle state.
pub(crate) struct PendingOp<P, R> {
    pub(crate) payload: P,
    pub(crate) state: PendingState<R>,
}

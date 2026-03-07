//! Shared internal types for the pending-write queue used by both the
//! done-ledger and findings backends.
//!
//! These types are crate-private — they encode the lifecycle state of a
//! single in-memory write operation and its buffered payload.

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
///
/// The payload is retained even after completion because `finish_*_op` clones
/// the payload out of a shared `&HashMap` reference before mutably applying it
/// (we cannot hold a `&payload` and `&mut state` simultaneously).
pub(crate) struct PendingOp<P, R> {
    pub(crate) payload: P,
    pub(crate) state: PendingState<R>,
}

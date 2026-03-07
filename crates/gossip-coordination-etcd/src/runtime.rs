use std::future::Future;

use crate::error::EtcdCoordinatorError;

/// Small sync/async bridge for the synchronous coordination traits.
///
/// `gossip-coordination` is intentionally synchronous, while the upstream
/// etcd Rust client is asynchronous. This bridge uses a private
/// current-thread Tokio runtime to drive async etcd calls from the sync
/// trait surface.
///
/// # Why current-thread?
///
/// The coordination traits take `&mut self`, so there is no concurrent
/// access to the backend. A current-thread runtime avoids the thread-pool
/// overhead of the multi-thread scheduler while still providing the IO and
/// timer drivers that the gRPC/HTTP2 transport requires.
///
/// # Lifetime
///
/// A `SyncRuntime` is created once during
/// [`EtcdCoordinator::connect()`](crate::backend::EtcdCoordinator::connect)
/// and lives for the coordinator's lifetime. All subsequent etcd RPCs
/// (`status`, and eventually persistence operations) are driven through the
/// same runtime instance.
///
/// # Panic safety
///
/// [`block_on`](Self::block_on) must **not** be called from within an
/// existing Tokio async context — Tokio detects the nested runtime and
/// panics. This is safe here because every call site is a synchronous
/// coordination trait method.
#[derive(Debug)]
pub(crate) struct SyncRuntime {
    inner: tokio::runtime::Runtime,
}

impl SyncRuntime {
    /// Build a current-thread Tokio runtime with IO and timer drivers enabled.
    ///
    /// `enable_all()` activates both the IO driver (needed for TCP/TLS
    /// sockets used by gRPC) and the time driver (needed for connect
    /// timeouts and keep-alive intervals). Omitting either would cause the
    /// etcd client to panic or hang on the first RPC.
    pub(crate) fn new() -> Result<Self, EtcdCoordinatorError> {
        let inner = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(EtcdCoordinatorError::RuntimeBuild)?;
        Ok(Self { inner })
    }

    /// Block the calling thread until `future` completes, returning its
    /// output.
    ///
    /// # Panics
    ///
    /// Panics if called from within an existing Tokio runtime (nested
    /// `block_on` is not supported). All call sites in this crate are
    /// synchronous trait methods, so this constraint is upheld.
    pub(crate) fn block_on<F>(&self, future: F) -> F::Output
    where
        F: Future,
    {
        self.inner.block_on(future)
    }
}

use std::future::Future;

use crate::error::EtcdCoordinatorError;

/// Small sync/async bridge for the synchronous coordination traits.
#[derive(Debug)]
pub(crate) struct SyncRuntime {
    inner: tokio::runtime::Runtime,
}

impl SyncRuntime {
    pub(crate) fn new() -> Result<Self, EtcdCoordinatorError> {
        let inner = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(EtcdCoordinatorError::RuntimeBuild)?;
        Ok(Self { inner })
    }

    pub(crate) fn block_on<F>(&self, future: F) -> F::Output
    where
        F: Future,
    {
        self.inner.block_on(future)
    }
}

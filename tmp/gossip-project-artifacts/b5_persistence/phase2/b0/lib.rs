//! etcd-backed coordination backend scaffold.
//!
//! B0 scope is intentionally narrow:
//! - create the workspace crate and dependency wiring,
//! - own a real etcd client connection,
//! - expose the final backend type and trait impl surface,
//! - prove local etcd connectivity with a smoke test.
//!
//! Real etcd persistence of shard/run state starts in B1 once the keyspace
//! layout and versioned record codecs are implemented.

#![forbid(unsafe_code)]

mod backend;
mod config;
mod error;
mod runtime;

pub use backend::{EtcdCoordinator, EtcdEndpointStatus};
pub use config::{EtcdCoordinatorConfig, EtcdCoordinatorConfigError};
pub use error::{EtcdCoordinatorError, EtcdOperation};

#[cfg(test)]
mod tests;

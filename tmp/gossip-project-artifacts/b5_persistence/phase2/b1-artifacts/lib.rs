//! etcd-backed coordination backend.
//!
//! B0/B1 scope intentionally stops before real fenced etcd mutations:
//! - own a live etcd client connection,
//! - define the keyspace layout for run/shard records and indexes,
//! - define deterministic, versioned codecs for `RunRecord` and `ShardRecord`,
//! - prove local etcd connectivity and record round-trips in tests.
//!
//! Actual etcd-backed coordination semantics (acquire/checkpoint/split/etc.)
//! land in later Epic B items. Until then the protocol behavior delegates to
//! the executable reference backend (`InMemoryCoordinator`) so downstream
//! crates can compile against the final backend type without pretending etcd
//! persistence is already implemented.

#![forbid(unsafe_code)]

mod backend;
mod codec;
mod config;
mod error;
mod keyspace;
mod runtime;

pub use backend::{EtcdCoordinator, EtcdEndpointStatus};
pub use codec::{
    BlobKind, EtcdCodecError, decode_run_record_v1, decode_shard_record_v1, encode_run_record_v1,
    encode_shard_record_v1,
};
pub use config::{EtcdCoordinatorConfig, EtcdCoordinatorConfigError};
pub use error::{EtcdCoordinatorError, EtcdOperation};
pub use keyspace::{EtcdKeyspace, EtcdKeyspaceError};

#[cfg(test)]
mod tests;

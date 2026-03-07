//! etcd-backed coordination backend.
//!
//! B1 established the deterministic keyspace and explicit v1 record codecs.
//! B2 adds real storage-backed hot-path operations for:
//! - `acquire_and_restore_into`
//! - `renew`
//! - `checkpoint`
//! - run creation / shard registration / read-side queries needed to drive
//!   those hot-path operations against persisted state.
//!
//! These operations use etcd transactions with fencing compares over the
//! authoritative shard record and the ephemeral owner key. Owner keys are
//! attached to etcd leases for storage-layer liveness, while the protocol's
//! logical lease deadline remains encoded in `ShardRecord`/`Lease`.
//!
//! Out-of-scope mutating operations for this epic
//! (`complete`, `park_shard`, `split_*`, run terminal transitions, unpark)
//! intentionally fail closed and land in later Epic B items.

#![forbid(unsafe_code)]

mod backend;
mod codec;
mod config;
mod error;
mod keyspace;
mod runtime;

pub use backend::{EtcdCoordinator, EtcdEndpointStatus};
pub use codec::{
    BlobKind, EtcdCodecError, OwnerLeaseValueV1, decode_owner_value_v1, decode_run_record_v1,
    decode_shard_record_v1, encode_owner_value_v1, encode_run_record_v1, encode_shard_record_v1,
};
pub use config::{EtcdCoordinatorConfig, EtcdCoordinatorConfigError};
pub use error::{EtcdCoordinatorError, EtcdOperation};
pub use keyspace::{EtcdKeyspace, EtcdKeyspaceError};

#[cfg(test)]
mod tests;

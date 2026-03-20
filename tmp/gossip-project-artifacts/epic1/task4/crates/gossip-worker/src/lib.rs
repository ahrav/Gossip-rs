//! Library surface for the `gossip-worker` package.
//!
//! The binary remains the user-facing entrypoint. This library exposes:
//!
//! - the production composition root that wires the generic distributed
//!   runtime to the real etcd/PostgreSQL backends,
//! - the typed worker configuration surface used to resolve environment
//!   variables and CLI overrides into either a local scan launch or a real
//!   distributed worker launch, and
//! - the production coordination telemetry recorder used by distributed
//!   `WorkerIdentity` instances.

#![forbid(unsafe_code)]

pub mod config;
pub mod production;
pub mod recorder;

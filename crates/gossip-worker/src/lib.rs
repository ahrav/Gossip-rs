//! Library surface for the `gossip-worker` package.
//!
//! The binary remains the user-facing entrypoint. This library exposes:
//!
//! - the typed worker configuration surface used to resolve environment
//!   variables and CLI overrides into explicit launch modes, and
//! - the production composition root that wires the generic distributed
//!   runtime to the real etcd, done-ledger, findings, and optional Git
//!   repo-frontier PostgreSQL backends without coupling those backends into
//!   the runtime core.

#![forbid(unsafe_code)]

pub mod config;
pub mod production;
pub mod recorder;

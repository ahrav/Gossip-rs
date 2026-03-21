//! Library surface for the `gossip-worker` package.
//!
//! The binary remains the user-facing entrypoint. This library exposes the
//! production composition root that wires the generic distributed runtime to
//! the real etcd and PostgreSQL backends without coupling those backends into
//! the runtime core.

#![forbid(unsafe_code)]

pub mod production;

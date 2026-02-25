//! Coordination layer: trait implementations and backends for distributed work
//! assignment.
//!
//! This crate provides concrete backend implementations for the coordination
//! traits defined in [`gossip_contracts::coordination`]. The contract crate
//! defines the protocol surface ([`CoordinationBackend`], [`RunManagement`],
//! [`ShardClaiming`], [`CoordinationFacade`]) and an in-memory reference
//! implementation used by the simulation harness. This crate adds
//! production-grade backends (etcd, SQL) that satisfy the same trait contracts
//! while handling durable state, distributed fencing, and network faults.
//!
//! [`CoordinationBackend`]: gossip_contracts::coordination::CoordinationBackend
//! [`RunManagement`]: gossip_contracts::coordination::RunManagement
//! [`ShardClaiming`]: gossip_contracts::coordination::ShardClaiming
//! [`CoordinationFacade`]: gossip_contracts::coordination::CoordinationFacade

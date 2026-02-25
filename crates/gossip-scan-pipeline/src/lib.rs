//! Scan pipeline: I/O scheduling, chunking, and CPU-bound executor
//! orchestration.
//!
//! This crate bridges the coordination layer ([`gossip_contracts`]) and the
//! detection engine ([`gossip_engine`]) into a staged processing pipeline:
//!
//! 1. **I/O scheduling** — fetches data source content for assigned shards,
//!    managing concurrency limits and back-pressure.
//! 2. **Chunking** — splits fetched content into bounded byte slices
//!    suitable for parallel detection.
//! 3. **CPU-bound executor** — dispatches chunks to the detection engine
//!    on dedicated threads, collecting match results without blocking
//!    the I/O scheduler.
//!
//! The pipeline consumes shard assignments from the coordinator and produces
//! detection results, handling checkpoint progress and cursor management
//! along the way.

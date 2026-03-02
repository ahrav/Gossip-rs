//! FS finding-output contract aliases for scheduler extraction.
//!
//! `StoreProducer` remains the canonical trait in Step 2a. `FindingOutput` is
//! provided as a migration alias so downstream crates can move away from the
//! monolith naming without duplicating implementations.
pub use crate::store::{
    FsFindingBatch, FsFindingRecord, FsRunLoss, FsStoreError, InMemoryStoreProducer,
    NullStoreProducer, OwnedFsFindingBatch, StoreProducer,
};

pub trait FindingOutput: StoreProducer {}

impl<T: StoreProducer + ?Sized> FindingOutput for T {}

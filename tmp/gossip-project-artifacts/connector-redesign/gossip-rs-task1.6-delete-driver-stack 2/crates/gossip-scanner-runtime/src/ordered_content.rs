//! Ordered-content runtime boundary.
//!
//! This module exists to cut the compile surface over to the new family-based
//! connector model. Concrete worker loops arrive in later tasks.

use std::path::PathBuf;

use gossip_contracts::connector::OrderedContentSource;

use crate::{FsScanConfig, ScanReport, ScanRuntimeError};

/// Placeholder runtime entrypoint for ordered-content sources.
#[derive(Debug, Default)]
pub struct OrderedContentRuntime;

impl OrderedContentRuntime {
    pub fn execute_source<S: OrderedContentSource>(
        _source: &mut S,
    ) -> Result<ScanReport, ScanRuntimeError> {
        Err(ScanRuntimeError::FamilyRuntimeNotImplemented {
            family: "ordered-content",
            source: std::any::type_name::<S>(),
        })
    }
}

pub(crate) fn filesystem_placeholder(
    _config: &FsScanConfig,
    _canonical_path: PathBuf,
) -> Result<ScanReport, ScanRuntimeError> {
    Err(ScanRuntimeError::FamilyRuntimeNotImplemented {
        family: "ordered-content",
        source: "filesystem",
    })
}

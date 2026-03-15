//! Ordered-content runtime boundary.

use std::path::PathBuf;

use anyhow::anyhow;
use gossip_contracts::connector::ordered::OrderedContentSource;

use crate::{FsScanConfig, ScanReport, ScanRuntimeError};

/// Ordered-content runtime marker.
#[derive(Debug, Default)]
pub struct OrderedContentRuntime;

impl OrderedContentRuntime {
    /// Execute one ordered-content source.
    pub fn execute_source<S: OrderedContentSource>(
        _source: &mut S,
    ) -> Result<ScanReport, ScanRuntimeError> {
        Err(ScanRuntimeError::Driver(anyhow!(
            "ordered-content runtime path for source '{}' is not implemented yet",
            std::any::type_name::<S>()
        )))
    }
}

pub(crate) fn filesystem_placeholder(
    _config: &FsScanConfig,
    _canonical_path: PathBuf,
) -> Result<ScanReport, ScanRuntimeError> {
    Err(ScanRuntimeError::Driver(anyhow!(
        "ordered-content runtime path for source 'filesystem' is not implemented yet"
    )))
}

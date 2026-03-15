//! Git-repository runtime boundary.

use std::path::PathBuf;

use anyhow::anyhow;
use gossip_contracts::connector::git::{GitMirrorManager, GitRepoDiscoverySource, GitRepoExecutor};

use crate::{GitScanConfig, ScanReport, ScanRuntimeError};

/// Git-repository runtime marker.
#[derive(Debug, Default)]
pub struct GitRepoRuntime;

impl GitRepoRuntime {
    /// Execute one discovery source.
    pub fn execute_discovery<D: GitRepoDiscoverySource>(
        _discovery: &mut D,
    ) -> Result<ScanReport, ScanRuntimeError> {
        Err(ScanRuntimeError::Driver(anyhow!(
            "git-repo discovery runtime path for source '{}' is not implemented yet",
            std::any::type_name::<D>()
        )))
    }

    /// Execute one mirrored repository.
    pub fn execute_repo<M: GitMirrorManager, E: GitRepoExecutor>(
        _mirrors: &mut M,
        _executor: &mut E,
    ) -> Result<ScanReport, ScanRuntimeError> {
        Err(ScanRuntimeError::Driver(anyhow!(
            "git-repo execution runtime path for executor '{}' is not implemented yet",
            std::any::type_name::<E>()
        )))
    }
}

pub(crate) fn local_repo_placeholder(
    _config: &GitScanConfig,
    _canonical_repo: PathBuf,
) -> Result<ScanReport, ScanRuntimeError> {
    Err(ScanRuntimeError::Driver(anyhow!(
        "git-repo runtime path for source 'local-repo' is not implemented yet"
    )))
}

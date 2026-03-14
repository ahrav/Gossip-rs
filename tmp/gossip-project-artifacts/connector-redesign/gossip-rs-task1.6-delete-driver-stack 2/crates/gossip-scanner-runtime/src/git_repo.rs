//! Git repo runtime boundary.
//!
//! This module exists to cut the compile surface over to the new Git family:
//! repo discovery, mirror sync, and repo-native execution.

use std::path::PathBuf;

use gossip_contracts::connector::{GitMirrorManager, GitRepoDiscoverySource, GitRepoExecutor};

use crate::{GitScanConfig, ScanReport, ScanRuntimeError};

#[derive(Debug, Default)]
pub struct GitRepoRuntime;

impl GitRepoRuntime {
    pub fn execute_discovery<D: GitRepoDiscoverySource>(
        _discovery: &mut D,
    ) -> Result<ScanReport, ScanRuntimeError> {
        Err(ScanRuntimeError::FamilyRuntimeNotImplemented {
            family: "git-repo-discovery",
            source: std::any::type_name::<D>(),
        })
    }

    pub fn execute_repo<M: GitMirrorManager, E: GitRepoExecutor>(
        _mirrors: &mut M,
        _executor: &mut E,
    ) -> Result<ScanReport, ScanRuntimeError> {
        Err(ScanRuntimeError::FamilyRuntimeNotImplemented {
            family: "git-repo-execution",
            source: std::any::type_name::<E>(),
        })
    }
}

pub(crate) fn local_repo_placeholder(
    _config: &GitScanConfig,
    _canonical_repo: PathBuf,
) -> Result<ScanReport, ScanRuntimeError> {
    Err(ScanRuntimeError::FamilyRuntimeNotImplemented {
        family: "git-repo",
        source: "local-repo",
    })
}

use gossip_contracts::identity::PolicyHash;
use gossip_scanner_runtime::FsScanConfig;
use gossip_scanner_runtime::distributed::ShardLeaseAssignment;

/// Filesystem shard payload consumed by the distributed runtime.
///
/// Pairs a detection-policy hash (required by [`ShardLease`] validation to
/// ensure the assignment and write context agree on policy scope) with the
/// scanner configuration for the shard's filesystem subtree.
///
/// Constructed during shard acquisition in the adapter module. The
/// `scan_config.path` may be overridden per-shard when the coordination-layer
/// shard spec carries a UTF-8 path in its `connector_extra` metadata field;
/// otherwise the template path is used.
///
/// [`ShardLease`]: gossip_scanner_runtime::distributed::ShardLease
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilesystemAssignment {
    policy_hash: PolicyHash,
    scan_config: FsScanConfig,
}

impl FilesystemAssignment {
    /// Create a filesystem assignment binding a policy scope to a scan config.
    #[must_use]
    pub fn new(policy_hash: PolicyHash, scan_config: FsScanConfig) -> Self {
        Self {
            policy_hash,
            scan_config,
        }
    }

    /// The scanner configuration carried by this assignment.
    #[must_use]
    pub fn scan_config(&self) -> &FsScanConfig {
        &self.scan_config
    }
}

/// Exposes the policy hash for [`ShardLease`] cross-validation and provides
/// the filesystem scan config so the worker loop can build a scanner from
/// the assignment.
///
/// [`ShardLease`]: gossip_scanner_runtime::distributed::ShardLease
impl ShardLeaseAssignment for FilesystemAssignment {
    fn policy_hash(&self) -> PolicyHash {
        self.policy_hash
    }

    fn filesystem_scan_config(&self) -> Option<FsScanConfig> {
        Some(self.scan_config.clone())
    }
}

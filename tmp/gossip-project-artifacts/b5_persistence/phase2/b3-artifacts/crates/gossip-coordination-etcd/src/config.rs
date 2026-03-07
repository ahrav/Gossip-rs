use std::fmt;

use gossip_contracts::coordination::limits::MAX_SPLIT_CHILDREN;

/// Configuration for connecting the etcd coordination backend.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EtcdCoordinatorConfig {
    endpoints: Vec<String>,
    namespace_prefix: String,
    owner_lease_ttl_secs: i64,
    optimistic_txn_retries: usize,
    max_children_per_op: usize,
}

impl EtcdCoordinatorConfig {
    /// Create a validated configuration.
    pub fn new<I, S>(
        endpoints: I,
        namespace_prefix: impl Into<String>,
        owner_lease_ttl_secs: i64,
        optimistic_txn_retries: usize,
        max_children_per_op: usize,
    ) -> Result<Self, EtcdCoordinatorConfigError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let endpoints = endpoints
            .into_iter()
            .map(Into::into)
            .map(|s| s.trim().to_owned())
            .collect::<Vec<_>>();
        let namespace_prefix = namespace_prefix.into().trim().to_owned();

        let cfg = Self {
            endpoints,
            namespace_prefix,
            owner_lease_ttl_secs,
            optimistic_txn_retries,
            max_children_per_op,
        };
        cfg.validate()?;
        Ok(cfg)
    }

    /// Convenience configuration for a local single-node etcd.
    #[must_use]
    pub fn localhost() -> Self {
        Self {
            endpoints: vec!["http://127.0.0.1:2379".to_owned()],
            namespace_prefix: "/gossip/v1".to_owned(),
            owner_lease_ttl_secs: 60,
            optimistic_txn_retries: 8,
            max_children_per_op: 8,
        }
    }

    /// Parse a comma-separated endpoint list.
    pub fn from_endpoints_csv(
        endpoints_csv: &str,
        namespace_prefix: impl Into<String>,
    ) -> Result<Self, EtcdCoordinatorConfigError> {
        let endpoints = endpoints_csv
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>();
        Self::new(endpoints, namespace_prefix, 60, 8, 8)
    }

    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), EtcdCoordinatorConfigError> {
        if self.endpoints.is_empty() {
            return Err(EtcdCoordinatorConfigError::NoEndpoints);
        }

        for (index, endpoint) in self.endpoints.iter().enumerate() {
            if endpoint.trim().is_empty() {
                return Err(EtcdCoordinatorConfigError::EmptyEndpoint { index });
            }
        }

        if self.namespace_prefix.is_empty() {
            return Err(EtcdCoordinatorConfigError::EmptyNamespacePrefix);
        }
        if !self.namespace_prefix.starts_with('/') {
            return Err(EtcdCoordinatorConfigError::NamespacePrefixMustStartWithSlash);
        }
        if self.namespace_prefix.ends_with('/') && self.namespace_prefix.len() > 1 {
            return Err(EtcdCoordinatorConfigError::NamespacePrefixMustNotEndWithSlash);
        }
        if self.owner_lease_ttl_secs <= 0 {
            return Err(EtcdCoordinatorConfigError::NonPositiveOwnerLeaseTtl);
        }
        if self.optimistic_txn_retries == 0 {
            return Err(EtcdCoordinatorConfigError::ZeroOptimisticTxnRetries);
        }
        if self.max_children_per_op == 0 {
            return Err(EtcdCoordinatorConfigError::ZeroMaxChildrenPerOp);
        }
        if self.max_children_per_op > MAX_SPLIT_CHILDREN {
            return Err(EtcdCoordinatorConfigError::MaxChildrenPerOpExceedsGlobalLimit {
                requested: self.max_children_per_op,
                global_max: MAX_SPLIT_CHILDREN,
            });
        }

        Ok(())
    }

    #[must_use]
    pub fn endpoints(&self) -> &[String] {
        &self.endpoints
    }

    #[must_use]
    pub fn namespace_prefix(&self) -> &str {
        &self.namespace_prefix
    }

    /// Wall-clock etcd lease TTL used for ephemeral owner keys.
    ///
    /// This is intentionally separate from the protocol's logical lease
    /// deadline carried in `Lease` / `ShardRecord`. The coordination protocol
    /// continues to use logical time for fencing semantics; the etcd lease is
    /// an additional storage-layer liveness guard for owner keys.
    #[must_use]
    pub fn owner_lease_ttl_secs(&self) -> i64 {
        self.owner_lease_ttl_secs
    }

    /// Maximum number of optimistic re-read/retry loops around an etcd txn.
    #[must_use]
    pub fn optimistic_txn_retries(&self) -> usize {
        self.optimistic_txn_retries
    }

    /// Maximum children allowed in one atomic split operation for this backend.
    #[must_use]
    pub fn max_children_per_op(&self) -> usize {
        self.max_children_per_op
    }
}

impl Default for EtcdCoordinatorConfig {
    fn default() -> Self {
        Self::localhost()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EtcdCoordinatorConfigError {
    NoEndpoints,
    EmptyEndpoint { index: usize },
    EmptyNamespacePrefix,
    NamespacePrefixMustStartWithSlash,
    NamespacePrefixMustNotEndWithSlash,
    NonPositiveOwnerLeaseTtl,
    ZeroOptimisticTxnRetries,
    ZeroMaxChildrenPerOp,
    MaxChildrenPerOpExceedsGlobalLimit { requested: usize, global_max: usize },
}

impl fmt::Display for EtcdCoordinatorConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoEndpoints => f.write_str("at least one etcd endpoint is required"),
            Self::EmptyEndpoint { index } => {
                write!(f, "etcd endpoint at index {index} must not be empty")
            }
            Self::EmptyNamespacePrefix => f.write_str("namespace_prefix must not be empty"),
            Self::NamespacePrefixMustStartWithSlash => {
                f.write_str("namespace_prefix must start with '/'")
            }
            Self::NamespacePrefixMustNotEndWithSlash => {
                f.write_str("namespace_prefix must not end with '/' unless it is exactly '/'")
            }
            Self::NonPositiveOwnerLeaseTtl => {
                f.write_str("owner_lease_ttl_secs must be > 0")
            }
            Self::ZeroOptimisticTxnRetries => {
                f.write_str("optimistic_txn_retries must be > 0")
            }
            Self::ZeroMaxChildrenPerOp => {
                f.write_str("max_children_per_op must be > 0")
            }
            Self::MaxChildrenPerOpExceedsGlobalLimit { requested, global_max } => write!(
                f,
                "max_children_per_op ({requested}) exceeds global MAX_SPLIT_CHILDREN ({global_max})",
            ),
        }
    }
}

impl std::error::Error for EtcdCoordinatorConfigError {}

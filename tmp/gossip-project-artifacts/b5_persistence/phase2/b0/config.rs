use std::fmt;

/// Default logical lease duration for the temporary in-memory protocol
/// delegate used during B0 scaffolding.
///
/// This value is intentionally internal: once B1 lands, the etcd backend will
/// stop delegating coordination semantics to `InMemoryCoordinator` and this
/// bootstrap constant will disappear.
pub(crate) const DEFAULT_BOOTSTRAP_LEASE_DURATION: u64 = 30;

/// Configuration for connecting the etcd coordination backend.
///
/// B0 scope is intentionally narrow:
/// - establish a real etcd client connection,
/// - validate endpoint/prefix configuration,
/// - expose a backend type that already implements the coordination traits.
///
/// The actual etcd key layout and shard/run record serialization arrive in B1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EtcdCoordinatorConfig {
    endpoints: Vec<String>,
    namespace_prefix: String,
}

impl EtcdCoordinatorConfig {
    /// Create a validated configuration.
    pub fn new<I, S>(
        endpoints: I,
        namespace_prefix: impl Into<String>,
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
        }
    }

    /// Comma-separated endpoint parser for local/dev tests.
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
        Self::new(endpoints, namespace_prefix)
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

        Ok(())
    }

    /// Endpoints passed to the etcd client.
    #[must_use]
    pub fn endpoints(&self) -> &[String] {
        &self.endpoints
    }

    /// Keyspace namespace prefix for all keys written by this backend.
    #[must_use]
    pub fn namespace_prefix(&self) -> &str {
        &self.namespace_prefix
    }
}

impl Default for EtcdCoordinatorConfig {
    fn default() -> Self {
        Self::localhost()
    }
}

/// Validation errors for [`EtcdCoordinatorConfig`].
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EtcdCoordinatorConfigError {
    NoEndpoints,
    EmptyEndpoint { index: usize },
    EmptyNamespacePrefix,
    NamespacePrefixMustStartWithSlash,
    NamespacePrefixMustNotEndWithSlash,
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
        }
    }
}

impl std::error::Error for EtcdCoordinatorConfigError {}

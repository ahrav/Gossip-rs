use std::fmt;
use std::time::Duration;

/// Logical lease duration (in seconds) passed to the
/// [`InMemoryCoordinator`] delegate.
///
/// This constant is `pub(crate)` because it is only consumed by
/// [`EtcdCoordinator::connect`] when constructing the delegate.
///
/// [`InMemoryCoordinator`]: gossip_coordination::InMemoryCoordinator
/// [`EtcdCoordinator::connect`]: crate::backend::EtcdCoordinator::connect
pub(crate) const DEFAULT_BOOTSTRAP_LEASE_DURATION: u64 = 30;

/// Default timeout for establishing a gRPC connection to etcd.
///
/// Applied via [`ConnectOptions::with_connect_timeout`] to prevent
/// `connect()` from blocking indefinitely when an endpoint is unreachable
/// (firewall drop, wrong host, network partition). Five seconds is
/// generous for LAN/localhost and fast enough to surface misconfigurations
/// during startup.
///
/// [`ConnectOptions::with_connect_timeout`]: etcd_client::ConnectOptions::with_connect_timeout
pub(crate) const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Validated connection configuration for [`EtcdCoordinator`].
///
/// Captures two pieces of information needed to establish an etcd session:
///
/// - **Endpoints** — one or more `http(s)://host:port` addresses of etcd
///   cluster members. At least one is required; each must be non-empty after
///   whitespace trimming.
/// - **Namespace prefix** — the etcd key prefix that scopes all coordination
///   keys (e.g. `/gossip/v1`). Must start with `/` and must not end with `/`
///   (unless it is exactly `/`). This prevents accidental key collisions
///   between independent deployments sharing the same etcd cluster.
///
/// # Construction and normalization
///
/// [`new`] and [`from_endpoints_csv`] trim leading/trailing whitespace from
/// each endpoint and the namespace prefix before validation. This means
/// `"  http://host:2379  "` is accepted and stored as `"http://host:2379"`.
/// [`localhost`] delegates to [`new`] and is therefore subject to the same
/// validation rules.
///
/// # Invariants
///
/// A successfully constructed `EtcdCoordinatorConfig` satisfies:
/// - `endpoints` is non-empty and every element is non-empty.
/// - `namespace_prefix` starts with `'/'`.
/// - `namespace_prefix` does not end with `'/'` (unless it is `"/"`).
///
/// [`EtcdCoordinator`]: crate::EtcdCoordinator
/// [`new`]: Self::new
/// [`from_endpoints_csv`]: Self::from_endpoints_csv
/// [`localhost`]: Self::localhost
#[derive(Clone, PartialEq, Eq)]
pub struct EtcdCoordinatorConfig {
    endpoints: Vec<String>,
    namespace_prefix: String,
}

/// Redacts endpoint URIs to prevent credential leakage in logs and
/// diagnostics. Endpoint strings may contain embedded credentials
/// (e.g. `http://user:pass@host:2379`); the `Debug` output shows only
/// the host:port portion of each endpoint.
impl fmt::Debug for EtcdCoordinatorConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        /// Strip the userinfo portion from a URI, keeping only `scheme://host:port/path`.
        fn redact_endpoint(endpoint: &str) -> String {
            // Find `://`, then check if there's a `@` before the next `/`.
            if let Some(scheme_end) = endpoint.find("://") {
                let authority_start = scheme_end + 3;
                let rest = &endpoint[authority_start..];
                // If there's an `@`, the part before it is userinfo — strip it.
                let path_start = rest.find('/').unwrap_or(rest.len());
                if let Some(at_pos) = rest[..path_start].find('@') {
                    return format!("{}://***@{}", &endpoint[..scheme_end], &rest[at_pos + 1..]);
                }
            }
            endpoint.to_owned()
        }

        let redacted: Vec<String> = self.endpoints.iter().map(|e| redact_endpoint(e)).collect();
        f.debug_struct("EtcdCoordinatorConfig")
            .field("endpoints", &redacted)
            .field("namespace_prefix", &self.namespace_prefix)
            .finish()
    }
}

impl EtcdCoordinatorConfig {
    /// Create a validated configuration from an iterator of endpoints and a
    /// namespace prefix.
    ///
    /// Both endpoints and the prefix are trimmed of surrounding whitespace
    /// before validation. Empty strings that result from trimming are
    /// rejected (see [`EtcdCoordinatorConfigError`]).
    ///
    /// # Errors
    ///
    /// Returns [`EtcdCoordinatorConfigError`] if the endpoint list is empty,
    /// any endpoint is blank, or the namespace prefix violates the leading/
    /// trailing slash rules.
    ///
    /// # Examples
    ///
    /// ```
    /// use gossip_coordination_etcd::EtcdCoordinatorConfig;
    ///
    /// let config = EtcdCoordinatorConfig::new(
    ///     ["http://etcd-0:2379", "http://etcd-1:2379"],
    ///     "/gossip/v1",
    /// ).unwrap();
    /// assert_eq!(config.endpoints().len(), 2);
    /// ```
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
            .map(|endpoint| endpoint.trim().to_owned())
            .collect::<Vec<_>>();
        let namespace_prefix = namespace_prefix.into().trim().to_owned();

        let config = Self {
            endpoints,
            namespace_prefix,
        };
        config.validate()?;
        Ok(config)
    }

    /// Convenience configuration targeting a local single-node etcd at
    /// `http://127.0.0.1:2379` with namespace prefix `/gossip/v1`.
    ///
    /// Useful for development and integration tests that run against a
    /// local etcd instance. Routed through [`new`](Self::new) so the
    /// hard-coded values stay in lockstep with the validation rules.
    #[must_use]
    pub fn localhost() -> Self {
        Self::new(["http://127.0.0.1:2379"], "/gossip/v1")
            .expect("hard-coded localhost config must remain valid")
    }

    /// Parse a comma-separated endpoint string into a validated config.
    ///
    /// Splits `endpoints_csv` on `,`, trims each segment, and silently
    /// drops segments that are empty after trimming. The surviving
    /// endpoints are forwarded to [`new`](Self::new) for full validation.
    ///
    /// This is primarily intended for environment-variable-driven
    /// configuration (e.g. `ETCD_ENDPOINTS=http://host1:2379,http://host2:2379`).
    ///
    /// # Errors
    ///
    /// Same as [`new`](Self::new) — returns
    /// [`EtcdCoordinatorConfigError`] on validation failure.
    pub fn from_endpoints_csv(
        endpoints_csv: &str,
        namespace_prefix: impl Into<String>,
    ) -> Result<Self, EtcdCoordinatorConfigError> {
        let endpoints = endpoints_csv
            .split(',')
            .map(str::trim)
            .filter(|endpoint| !endpoint.is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>();
        Self::new(endpoints, namespace_prefix)
    }

    /// Check all configuration invariants and return an error describing
    /// the first violation found.
    ///
    /// Called automatically by [`new`](Self::new) and
    /// [`from_endpoints_csv`](Self::from_endpoints_csv), but exposed
    /// publicly so callers can re-validate after deserialization or
    /// manual construction.
    ///
    /// # Validation rules (checked in order)
    ///
    /// 1. At least one endpoint must be present.
    /// 2. No endpoint may be empty.
    ///    2b. Every endpoint must start with `http://` or `https://`.
    /// 3. Namespace prefix must be non-empty.
    /// 4. Namespace prefix must start with `'/'`.
    /// 5. Namespace prefix must not end with `'/'` (unless it is exactly
    ///    `"/"`).
    pub fn validate(&self) -> Result<(), EtcdCoordinatorConfigError> {
        if self.endpoints.is_empty() {
            return Err(EtcdCoordinatorConfigError::NoEndpoints);
        }

        for (index, endpoint) in self.endpoints.iter().enumerate() {
            if endpoint.is_empty() {
                return Err(EtcdCoordinatorConfigError::EmptyEndpoint { index });
            }
            if !(endpoint.starts_with("http://") || endpoint.starts_with("https://")) {
                return Err(EtcdCoordinatorConfigError::InvalidEndpointScheme { index });
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

    /// Configured etcd cluster endpoints.
    ///
    /// Guaranteed non-empty; every element is a non-empty, trimmed string.
    #[must_use]
    pub fn endpoints(&self) -> &[String] {
        &self.endpoints
    }

    /// Namespace prefix that roots all coordination keys in etcd.
    ///
    /// Guaranteed to start with `'/'` and not end with `'/'` (unless it
    /// is exactly `"/"`).
    #[must_use]
    pub fn namespace_prefix(&self) -> &str {
        &self.namespace_prefix
    }
}

/// Validation errors returned when constructing an
/// [`EtcdCoordinatorConfig`].
///
/// Each variant maps to exactly one of the validation rules enforced by
/// [`EtcdCoordinatorConfig::validate`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EtcdCoordinatorConfigError {
    /// The endpoint list is empty — at least one etcd member is required.
    NoEndpoints,
    /// The endpoint at the given `index` is empty (after trimming).
    EmptyEndpoint { index: usize },
    /// The endpoint at the given `index` has an invalid scheme (expected
    /// `http://` or `https://`).
    InvalidEndpointScheme { index: usize },
    /// The namespace prefix is empty (after trimming).
    EmptyNamespacePrefix,
    /// The namespace prefix does not start with `'/'`.
    NamespacePrefixMustStartWithSlash,
    /// The namespace prefix ends with `'/'` and is longer than `"/"`.
    NamespacePrefixMustNotEndWithSlash,
}

impl fmt::Display for EtcdCoordinatorConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoEndpoints => f.write_str("at least one etcd endpoint is required"),
            Self::EmptyEndpoint { index } => {
                write!(f, "etcd endpoint at index {index} must not be empty")
            }
            Self::InvalidEndpointScheme { index } => {
                write!(
                    f,
                    "etcd endpoint at index {index} has invalid scheme (expected http:// or https://)"
                )
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

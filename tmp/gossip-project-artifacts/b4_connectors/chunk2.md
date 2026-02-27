## 1) Scope (Chunk 2)

- Add the **connector traits** and **capability flags** on top of the Chunk 1 value types.
- Keep tests as stubs.
- Do **not** add the validator/harness yet (Chunk 3/4).

## 2) Assumptions

- Chunk 1 exists at `crates/gossip-contracts/src/connector/{mod.rs,types.rs}` and exports:
  - `ItemKey`, `ItemRef`, `Cursor`, `Budgets`, `EnumerationPage`

- `crate::coordination::ShardSpec` exists (we only need it as an opaque-ish spec reference).
- Blocking I/O is the contract shape, so `open()` returns `Box<dyn std::io::Read + Send>`.

## 3) Decision

- Define **two traits**:
  - `EnumerationConnector` with `enumerate_page()` (+ optional `choose_split_point()` hook, default `Ok(None)`).
  - `ReadConnector` with `open()` (+ optional `read_range()` hook, default “unsupported” error).

- Provide a supertrait `ConnectorInstance = EnumerationConnector + ReadConnector` so runtime can hold one trait object.
- Capabilities are a plain struct `ConnectorCapabilities` (not bitflags yet) to keep it obvious and extensible.

Alternative:

- Collapse to one trait with all methods. Tradeoff: fewer types but harder mocking/separation later.

## 4) Invariants and failure behavior

- Capability flags are **claims**; runtime should enforce them later:
  - If `caps.seek_by_key == false`, B1 runtime should reject the connector for range scanning unless it’s operating in a manifest keyspace (future capability).

- Default implementations:
  - `read_range()` returns a **Permanent** error (“not supported”).
  - `choose_split_point()` returns `Ok(None)`.

## 5) Tests (stubs)

- Minimal unit tests:
  - default `read_range()` returns Permanent “unsupported”
  - default capabilities are conservative (all false)

## 6) Implementation

### File changes

- Update `crates/gossip-contracts/src/connector/mod.rs`
- Add new file `crates/gossip-contracts/src/connector/api.rs`

---

## 7) Code

### `crates/gossip-contracts/src/connector/mod.rs`

```rust
//! Connector boundary: shared value types and traits for enumeration + reads.
//!
//! Chunk 1 locked down value types with strict caps and redacted formatting.
//! Chunk 2 adds traits and capability flags.
//!
//! Hard rule:
//! - `ItemKey`, `ItemRef`, cursor tokens are toxic. Do not log raw bytes.

mod types;
mod api;

pub use types::{
    Budgets, ConnectorInputError, ContentHints, Cursor, EnumerationPage, ItemKey, ItemRef,
    Location, ScanItem, TokenBytes, VersionId, MAX_ITEM_KEY_SIZE, MAX_ITEM_REF_SIZE,
    MAX_LOCATION_DISPLAY_SIZE, MAX_LOCATION_URL_SIZE,
};

pub use api::{
    ConnectorCapabilities, ConnectorInstance, EnumerateError, EnumerationConnector, ErrorClass,
    ReadConnector, ReadError,
};
```

### `crates/gossip-contracts/src/connector/api.rs`

```rust
use std::fmt;
use std::io;

use crate::coordination::ShardSpec;

use super::{Budgets, Cursor, EnumerationPage, ItemKey, ItemRef};

/// High-level classification for connector errors.
///
/// This is intentionally small:
/// - Retryable: transient failure (timeouts, rate limits, 5xx)
/// - Permanent: misconfig/auth/unsupported/buggy behavior (no point retrying)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorClass {
    Retryable,
    Permanent,
}

/// Enumeration error returned by connectors.
///
/// `message` must be display-safe (no raw secrets, no raw ItemKey/ItemRef bytes).
#[derive(Clone, Debug)]
pub struct EnumerateError {
    pub class: ErrorClass,
    pub message: String,
    pub retry_after_ms: Option<u64>,
}

impl EnumerateError {
    #[must_use]
    pub fn retryable(message: impl Into<String>) -> Self {
        Self {
            class: ErrorClass::Retryable,
            message: message.into(),
            retry_after_ms: None,
        }
    }

    #[must_use]
    pub fn rate_limited(message: impl Into<String>, retry_after_ms: u64) -> Self {
        Self {
            class: ErrorClass::Retryable,
            message: message.into(),
            retry_after_ms: Some(retry_after_ms),
        }
    }

    #[must_use]
    pub fn permanent(message: impl Into<String>) -> Self {
        Self {
            class: ErrorClass::Permanent,
            message: message.into(),
            retry_after_ms: None,
        }
    }
}

impl fmt::Display for EnumerateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.retry_after_ms {
            Some(ms) => write!(f, "{:?}: {} (retry_after_ms={})", self.class, self.message, ms),
            None => write!(f, "{:?}: {}", self.class, self.message),
        }
    }
}

impl std::error::Error for EnumerateError {}

/// Read/open error returned by connectors.
///
/// `message` must be display-safe (no raw secrets, no raw ItemKey/ItemRef bytes).
#[derive(Clone, Debug)]
pub struct ReadError {
    pub class: ErrorClass,
    pub message: String,
    pub retry_after_ms: Option<u64>,
}

impl ReadError {
    #[must_use]
    pub fn retryable(message: impl Into<String>) -> Self {
        Self {
            class: ErrorClass::Retryable,
            message: message.into(),
            retry_after_ms: None,
        }
    }

    #[must_use]
    pub fn rate_limited(message: impl Into<String>, retry_after_ms: u64) -> Self {
        Self {
            class: ErrorClass::Retryable,
            message: message.into(),
            retry_after_ms: Some(retry_after_ms),
        }
    }

    #[must_use]
    pub fn permanent(message: impl Into<String>) -> Self {
        Self {
            class: ErrorClass::Permanent,
            message: message.into(),
            retry_after_ms: None,
        }
    }

    #[must_use]
    pub fn unsupported(feature: &'static str) -> Self {
        Self {
            class: ErrorClass::Permanent,
            message: format!("{feature} not supported"),
            retry_after_ms: None,
        }
    }
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.retry_after_ms {
            Some(ms) => write!(f, "{:?}: {} (retry_after_ms={})", self.class, self.message, ms),
            None => write!(f, "{:?}: {}", self.class, self.message),
        }
    }
}

impl std::error::Error for ReadError {}

/// Declared connector capabilities used by the runtime to plan work.
///
/// Capabilities are claims. The runtime should enforce requirements:
/// - B1 correctness generally requires `seek_by_key == true` (or a manifest-based keyspace).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectorCapabilities {
    /// Connector can resume enumeration from `cursor.last_key` without relying on a token.
    pub seek_by_key: bool,

    /// Connector supports an opaque pagination token as an optimization.
    pub token_resume: bool,

    /// Connector supports random-access range reads (`read_range`).
    pub range_read: bool,

    /// Connector can provide split hints via `choose_split_point`.
    pub split_hints: bool,
}

impl Default for ConnectorCapabilities {
    fn default() -> Self {
        // Conservative defaults: connector implementations must opt into claims.
        Self {
            seek_by_key: false,
            token_resume: false,
            range_read: false,
            split_hints: false,
        }
    }
}

/// Enumeration interface for connectors.
///
/// Contract shape:
/// - Inputs: shard spec, current cursor, budgets
/// - Output: a single page of ordered items + next cursor
///
/// Correctness invariants (checked later by validator/harness):
/// - membership: keys within shard range
/// - ordering: non-decreasing keys within page
/// - resumable-by-key: must work without token
pub trait EnumerationConnector: Send {
    fn caps(&self) -> ConnectorCapabilities;

    fn enumerate_page(
        &mut self,
        shard: &ShardSpec,
        cursor: &Cursor,
        budgets: Budgets,
    ) -> Result<EnumerationPage, EnumerateError>;

    /// Optional: provide a split point hint `m` such that `cursor < m < shard.end`.
    ///
    /// Default: no hint.
    fn choose_split_point(
        &mut self,
        _shard: &ShardSpec,
        _cursor: &Cursor,
    ) -> Result<Option<ItemKey>, EnumerateError> {
        Ok(None)
    }
}

/// Read interface for connectors.
///
/// Contract shape:
/// - open() returns a blocking reader
/// - read_range() is optional (runtime checks `caps.range_read`)
pub trait ReadConnector: Send {
    fn open(
        &mut self,
        item_ref: &ItemRef,
        budgets: Budgets,
    ) -> Result<Box<dyn io::Read + Send>, ReadError>;

    /// Optional random-access read.
    ///
    /// Default: unsupported.
    fn read_range(
        &mut self,
        _item_ref: &ItemRef,
        _offset: u64,
        _dst: &mut [u8],
        _budgets: Budgets,
    ) -> Result<usize, ReadError> {
        Err(ReadError::unsupported("range_read"))
    }
}

/// Convenience supertrait for runtime usage.
///
/// A "connector instance" is generally a configured client that can both enumerate and read.
pub trait ConnectorInstance: EnumerationConnector + ReadConnector {}
impl<T: EnumerationConnector + ReadConnector + ?Sized> ConnectorInstance for T {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connector::{Cursor, ItemRef};

    struct Dummy;
    impl EnumerationConnector for Dummy {
        fn caps(&self) -> ConnectorCapabilities {
            ConnectorCapabilities::default()
        }

        fn enumerate_page(
            &mut self,
            _shard: &ShardSpec,
            _cursor: &Cursor,
            _budgets: Budgets,
        ) -> Result<EnumerationPage, EnumerateError> {
            Err(EnumerateError::permanent("not implemented"))
        }
    }

    impl ReadConnector for Dummy {
        fn open(
            &mut self,
            _item_ref: &ItemRef,
            _budgets: Budgets,
        ) -> Result<Box<dyn io::Read + Send>, ReadError> {
            Err(ReadError::permanent("not implemented"))
        }
    }

    #[test]
    fn default_caps_are_conservative() {
        let caps = ConnectorCapabilities::default();
        assert!(!caps.seek_by_key);
        assert!(!caps.token_resume);
        assert!(!caps.range_read);
        assert!(!caps.split_hints);
    }

    #[test]
    fn default_read_range_is_unsupported() {
        let mut c = Dummy;
        let item_ref = ItemRef::try_from_slice(b"opaque").unwrap();

        let mut buf = [0u8; 8];
        let err = c
            .read_range(&item_ref, 0, &mut buf, Budgets::new(1, 1024, None))
            .unwrap_err();

        assert_eq!(err.class, ErrorClass::Permanent);
        assert!(err.message.contains("not supported"));
    }
}
```

---

## 8) Commands

```sh
cargo test -p gossip-contracts
```

That’s Chunk 2. Next (Chunk 3) is where things get real: the page validator becomes the actual executable spec for membership/order/cursor monotonicity and the place we encode empty-page semantics.

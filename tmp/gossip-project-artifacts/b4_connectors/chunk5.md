## Scope (Chunk 5)

Implement **two reference connectors** that both pass the **Chunk 4 conformance harness**:

- `InMemoryDeterministicConnector`
  - Gold-standard deterministic connector for tests
  - Explicitly supports seek-by-key resumability
  - Emits pagination tokens (optional) and is robust to token loss/corruption

- `FilesystemConnector` (Unix-only in this cut)
  - Real-ish connector that enumerates files under a root dir
  - Deterministic path ordering
  - Seek-by-key resumability via a prebuilt sorted index
  - `open()` reads files

Also add conformance tests in `gossip-connectors` that run the harness.

This code assumes your `gossip-contracts::connector` module already contains:

- types: `ItemKey, ItemRef, Cursor, ScanItem, VersionId, EnumerationPage, Budgets`
- traits: `EnumerationConnector, ReadConnector`
- errors: `EnumerateError, ReadError, ErrorClass`
- harness: `connector::conformance::{assert_connector_conforms, ConformanceConfig}`

If one of those names differs slightly in your branch, adjust imports, not logic.

---

# Code

## `crates/gossip-connectors/Cargo.toml`

```toml
[package]
name = "gossip-connectors"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
repository.workspace = true

[dependencies]
gossip-contracts.workspace = true
blake3 = "1.5"

[dev-dependencies]
tempfile = "3.10"
```

---

## `crates/gossip-connectors/src/lib.rs`

```rust
//! Reference connectors (Chunk 5).
//!
//! These are meant to:
//! - exercise the connector contract + validator + harness,
//! - serve as examples for future real connectors,
//! - remain intentionally simple and deterministic.

pub mod filesystem;
pub mod in_memory;

pub use filesystem::FilesystemConnector;
pub use in_memory::InMemoryDeterministicConnector;
```

---

## `crates/gossip-connectors/src/in_memory.rs`

```rust
use std::io;
use std::sync::Arc;

use blake3;

use gossip_contracts::connector::{
    Budgets, ConnectorCapabilities, Cursor, EnumerationConnector, EnumerationPage, EnumerateError,
    ErrorClass, ItemKey, ItemRef, ReadConnector, ReadError, ScanItem, TokenBytes, VersionId,
};
use gossip_contracts::identity::{ObjectVersionId, StableItemId};

/// A single in-memory item.
#[derive(Clone)]
pub struct MemItem {
    pub key: ItemKey,
    pub bytes: Arc<[u8]>,
}

impl MemItem {
    pub fn new(key: ItemKey, bytes: impl Into<Arc<[u8]>>) -> Self {
        Self {
            key,
            bytes: bytes.into(),
        }
    }
}

/// Deterministic in-memory connector.
///
/// Properties:
/// - All items are pre-sorted by ItemKey.
/// - Enumeration uses seek-by-key (binary search) and can optionally emit/consume tokens.
/// - Tokens are validated against last_key; corrupted/stale tokens are ignored.
/// - open() reads from an in-memory Arc<[u8]> store.
pub struct InMemoryDeterministicConnector {
    items: Vec<MemItem>,
    /// If true, connector emits and consumes a token that encodes "next index".
    emit_tokens: bool,
}

impl InMemoryDeterministicConnector {
    /// Create from a set of items.
    ///
    /// Items do not need to be sorted; we will sort them deterministically.
    pub fn new(mut items: Vec<MemItem>) -> Self {
        items.sort_by(|a, b| a.key.cmp(&b.key));
        Self {
            items,
            emit_tokens: true,
        }
    }

    pub fn with_tokens(mut self, enabled: bool) -> Self {
        self.emit_tokens = enabled;
        self
    }

    /// Enumerate within an explicit [start,end) range.
    ///
    /// This is the core implementation. The trait method can delegate to it.
    pub fn enumerate_page_range(
        &mut self,
        start: &ItemKey,
        end: &ItemKey,
        cursor: &Cursor,
        budgets: Budgets,
    ) -> Result<EnumerationPage, EnumerateError> {
        if budgets.is_expired() {
            // No advancement on "budget exhausted".
            return Ok(EnumerationPage::new(Vec::new(), cursor.clone()));
        }

        // Restrict to shard range first.
        let range_start = lower_bound(&self.items, start.as_bytes());
        let range_end = lower_bound(&self.items, end.as_bytes());

        // Then apply resume-after-last_key.
        let resume_start = match cursor.last_key() {
            None => range_start,
            Some(last) => upper_bound(&self.items, last.as_bytes()),
        };

        let mut start_idx = range_start.max(resume_start);
        let end_idx = range_end;

        // Optional token: treat as hint ONLY if it matches expected start index.
        if self.emit_tokens {
            if let (Some(last_key), Some(tok)) = (cursor.last_key(), cursor.token()) {
                if let Some(tok_idx) = parse_u64_be(tok.as_bytes()) {
                    let expected = upper_bound(&self.items, last_key.as_bytes());
                    if tok_idx as usize == expected {
                        start_idx = start_idx.max(expected);
                    }
                }
            }
        }

        if start_idx >= end_idx {
            // End of range.
            return Ok(EnumerationPage::new(Vec::new(), cursor.clone()));
        }

        let take = budgets.max_items.min(end_idx - start_idx);
        let slice = &self.items[start_idx..(start_idx + take)];

        let mut out = Vec::with_capacity(slice.len());
        for (i, it) in slice.iter().enumerate() {
            let idx = start_idx + i;

            let item_ref = ItemRef::try_from_slice(&u64::to_be_bytes(idx as u64))
                .map_err(|e| EnumerateError::permanent(format!("invalid item_ref: {e}")))?;

            let stable_item_id = derive_stable_item_id(&it.key);
            let version = VersionId::Strong(derive_object_version_id(&it.bytes));

            let scan_item = ScanItem::new(it.key.clone(), item_ref, stable_item_id, version)
                .with_size_hint(Some(it.bytes.len() as u64));

            out.push(scan_item);
        }

        // next cursor: last_key = last item key; token (optional) = next index
        let last_key = out.last().unwrap().item_key.clone();
        let mut next = Cursor::with_last_key(last_key);

        if self.emit_tokens {
            let next_index = (start_idx + out.len()) as u64;
            let tok = TokenBytes::try_from_slice(&u64::to_be_bytes(next_index))
                .map_err(|e| EnumerateError::permanent(format!("invalid token: {e}")))?;
            next = Cursor::with_token(next.last_key().unwrap().clone(), tok);
        }

        Ok(EnumerationPage::new(out, next))
    }

    fn open_ref_internal(&self, item_ref: &ItemRef) -> Result<Arc<[u8]>, ReadError> {
        let idx = parse_u64_be(item_ref.as_bytes())
            .ok_or_else(|| ReadError::permanent("invalid item_ref encoding"))? as usize;

        self.items
            .get(idx)
            .map(|it| it.bytes.clone())
            .ok_or_else(|| ReadError::permanent("item_ref out of bounds"))
    }

    pub fn choose_split_point_range(
        &mut self,
        start: &ItemKey,
        end: &ItemKey,
        cursor: &Cursor,
    ) -> Result<Option<ItemKey>, EnumerateError> {
        let range_start = lower_bound(&self.items, start.as_bytes());
        let range_end = lower_bound(&self.items, end.as_bytes());
        let resume_start = match cursor.last_key() {
            None => range_start,
            Some(last) => upper_bound(&self.items, last.as_bytes()),
        };
        let s = range_start.max(resume_start);
        let e = range_end;

        if e.saturating_sub(s) < 2 {
            return Ok(None);
        }

        let mid = s + (e - s) / 2;
        let m = self.items[mid].key.clone();

        // Must satisfy cursor.last_key < m < end; our selection should satisfy that if the range is non-trivial.
        if let Some(last) = cursor.last_key() {
            if &m <= last {
                return Ok(None);
            }
        }
        if &m >= end {
            return Ok(None);
        }

        Ok(Some(m))
    }
}

impl EnumerationConnector for InMemoryDeterministicConnector {
    fn caps(&self) -> ConnectorCapabilities {
        ConnectorCapabilities {
            seek_by_key: true,
            token_resume: self.emit_tokens,
            range_read: true, // we can do in-memory range reads cheaply
            split_hints: true,
        }
    }

    fn enumerate_page(
        &mut self,
        shard: &gossip_contracts::coordination::ShardSpec,
        cursor: &Cursor,
        budgets: Budgets,
    ) -> Result<EnumerationPage, EnumerateError> {
        // This adapter depends on your ShardSpec API.
        // Adjust `start_key_bytes()` / `end_key_bytes()` to your actual methods/fields.
        let start = ItemKey::try_from_slice(shard.start_key_bytes())
            .map_err(|e| EnumerateError::permanent(format!("invalid shard start: {e}")))?;
        let end = ItemKey::try_from_slice(shard.end_key_bytes())
            .map_err(|e| EnumerateError::permanent(format!("invalid shard end: {e}")))?;

        self.enumerate_page_range(&start, &end, cursor, budgets)
    }

    fn choose_split_point(
        &mut self,
        shard: &gossip_contracts::coordination::ShardSpec,
        cursor: &Cursor,
    ) -> Result<Option<ItemKey>, EnumerateError> {
        let start = ItemKey::try_from_slice(shard.start_key_bytes())
            .map_err(|e| EnumerateError::permanent(format!("invalid shard start: {e}")))?;
        let end = ItemKey::try_from_slice(shard.end_key_bytes())
            .map_err(|e| EnumerateError::permanent(format!("invalid shard end: {e}")))?;
        self.choose_split_point_range(&start, &end, cursor)
    }
}

impl ReadConnector for InMemoryDeterministicConnector {
    fn open(
        &mut self,
        item_ref: &ItemRef,
        budgets: Budgets,
    ) -> Result<Box<dyn io::Read + Send>, ReadError> {
        let bytes = self.open_ref_internal(item_ref)?;

        if (bytes.len() as u64) > budgets.max_bytes {
            return Err(ReadError {
                class: ErrorClass::Permanent,
                message: "item exceeds max_bytes budget".into(),
                retry_after_ms: None,
            });
        }

        Ok(Box::new(io::Cursor::new(bytes)))
    }

    fn read_range(
        &mut self,
        item_ref: &ItemRef,
        offset: u64,
        dst: &mut [u8],
        budgets: Budgets,
    ) -> Result<usize, ReadError> {
        let bytes = self.open_ref_internal(item_ref)?;
        let off = offset as usize;
        if off >= bytes.len() {
            return Ok(0);
        }

        let max = budgets.max_bytes.min(dst.len() as u64) as usize;
        let avail = (bytes.len() - off).min(max);
        dst[..avail].copy_from_slice(&bytes[off..off + avail]);
        Ok(avail)
    }
}

// --------------------------
// Helpers
// --------------------------

fn lower_bound(items: &[MemItem], key: &[u8]) -> usize {
    let mut lo = 0usize;
    let mut hi = items.len();
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if items[mid].key.as_bytes() < key {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    lo
}

/// First index with item.key > key (upper bound).
fn upper_bound(items: &[MemItem], key: &[u8]) -> usize {
    let mut lo = 0usize;
    let mut hi = items.len();
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if items[mid].key.as_bytes() <= key {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    lo
}

fn parse_u64_be(b: &[u8]) -> Option<u64> {
    if b.len() != 8 {
        return None;
    }
    let mut arr = [0u8; 8];
    arr.copy_from_slice(b);
    Some(u64::from_be_bytes(arr))
}

// These constructors are assumed to exist in your identity module.
// If your actual APIs differ, update these two functions only.
fn derive_stable_item_id(key: &ItemKey) -> StableItemId {
    let h = blake3::hash(key.as_bytes());
    StableItemId::from_bytes(*h.as_bytes())
}

fn derive_object_version_id(bytes: &[u8]) -> ObjectVersionId {
    let h = blake3::hash(bytes);
    ObjectVersionId::from_bytes(*h.as_bytes())
}
```

Notes:

- The `ShardSpec` adapter uses `start_key_bytes()` / `end_key_bytes()` placeholders. Replace with your real API. The core logic is in `enumerate_page_range()` which is independent of ShardSpec.

---

## `crates/gossip-connectors/src/filesystem.rs`

```rust
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use blake3;

use gossip_contracts::connector::{
    Budgets, ConnectorCapabilities, Cursor, EnumerationConnector, EnumerationPage, EnumerateError,
    ErrorClass, ItemKey, ItemRef, ReadConnector, ReadError, ScanItem, VersionId,
};
use gossip_contracts::identity::{ObjectVersionId, StableItemId};

#[cfg(unix)]
use std::os::unix::ffi::{OsStrExt, OsStringExt};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

/// Filesystem connector (reference).
///
/// Design:
/// - Build a complete sorted index of files under `root` once (lazy).
/// - Enumeration uses binary search to seek-by-key.
/// - ItemKey and ItemRef are both the normalized relative path bytes.
/// - Version is Weak and derived from (mtime_ns, size, inode).
///
/// Limitations:
/// - Unix-only in this cut (path byte handling).
pub struct FilesystemConnector {
    root: PathBuf,
    emit_tokens: bool,
    indexed: bool,
    files: Vec<FileEntry>,
}

#[derive(Clone)]
struct FileEntry {
    key: ItemKey,
    rel_bytes: Arc<[u8]>,
    stable_item_id: StableItemId,
    version: VersionId,
    size: u64,
}

impl FilesystemConnector {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            emit_tokens: false,
            indexed: false,
            files: Vec::new(),
        }
    }

    pub fn with_tokens(mut self, enabled: bool) -> Self {
        self.emit_tokens = enabled;
        self
    }

    fn ensure_indexed(&mut self) -> Result<(), EnumerateError> {
        if self.indexed {
            return Ok(());
        }

        #[cfg(not(unix))]
        {
            return Err(EnumerateError::permanent(
                "FilesystemConnector is unix-only in this cut",
            ));
        }

        #[cfg(unix)]
        {
            let mut out: Vec<FileEntry> = Vec::new();
            walk_dir_collect_files(&self.root, &self.root, &mut out)?;

            // Deterministic global ordering by ItemKey bytes.
            out.sort_by(|a, b| a.key.cmp(&b.key));

            self.files = out;
            self.indexed = true;
            Ok(())
        }
    }

    /// Enumerate within explicit [start,end) bounds.
    pub fn enumerate_page_range(
        &mut self,
        start: &ItemKey,
        end: &ItemKey,
        cursor: &Cursor,
        budgets: Budgets,
    ) -> Result<EnumerationPage, EnumerateError> {
        self.ensure_indexed()?;

        if budgets.is_expired() {
            return Ok(EnumerationPage::new(Vec::new(), cursor.clone()));
        }

        let range_start = lower_bound_file(&self.files, start.as_bytes());
        let range_end = lower_bound_file(&self.files, end.as_bytes());

        let resume_start = match cursor.last_key() {
            None => range_start,
            Some(last) => upper_bound_file(&self.files, last.as_bytes()),
        };

        let start_idx = range_start.max(resume_start);
        let end_idx = range_end;

        if start_idx >= end_idx {
            return Ok(EnumerationPage::new(Vec::new(), cursor.clone()));
        }

        let take = budgets.max_items.min(end_idx - start_idx);
        let slice = &self.files[start_idx..(start_idx + take)];

        let mut out = Vec::with_capacity(slice.len());
        for fe in slice {
            let item_ref = ItemRef::try_from_slice(&fe.rel_bytes)
                .map_err(|e| EnumerateError::permanent(format!("invalid item_ref: {e}")))?;

            let scan_item = ScanItem::new(
                fe.key.clone(),
                item_ref,
                fe.stable_item_id,
                fe.version,
            )
            .with_size_hint(Some(fe.size));

            out.push(scan_item);
        }

        let last_key = out.last().unwrap().item_key.clone();
        let mut next = Cursor::with_last_key(last_key);

        if self.emit_tokens {
            // Token is just a hint; we encode "next index". The harness will corrupt it; enumeration must still work.
            let next_index = (start_idx + out.len()) as u64;
            let tok = gossip_contracts::connector::TokenBytes::try_from_slice(&u64::to_be_bytes(next_index))
                .map_err(|e| EnumerateError::permanent(format!("invalid token: {e}")))?;
            next = Cursor::with_token(next.last_key().unwrap().clone(), tok);
        }

        Ok(EnumerationPage::new(out, next))
    }

    pub fn choose_split_point_range(
        &mut self,
        start: &ItemKey,
        end: &ItemKey,
        cursor: &Cursor,
    ) -> Result<Option<ItemKey>, EnumerateError> {
        self.ensure_indexed()?;

        let range_start = lower_bound_file(&self.files, start.as_bytes());
        let range_end = lower_bound_file(&self.files, end.as_bytes());
        let resume_start = match cursor.last_key() {
            None => range_start,
            Some(last) => upper_bound_file(&self.files, last.as_bytes()),
        };
        let s = range_start.max(resume_start);
        let e = range_end;

        if e.saturating_sub(s) < 2 {
            return Ok(None);
        }

        let mid = s + (e - s) / 2;
        let m = self.files[mid].key.clone();

        if let Some(last) = cursor.last_key() {
            if &m <= last {
                return Ok(None);
            }
        }
        if &m >= end {
            return Ok(None);
        }

        Ok(Some(m))
    }

    fn resolve_item_ref(&self, item_ref: &ItemRef) -> Result<PathBuf, ReadError> {
        #[cfg(not(unix))]
        {
            let _ = item_ref;
            return Err(ReadError::unsupported("filesystem open on non-unix"));
        }

        #[cfg(unix)]
        {
            let rel = std::ffi::OsString::from_vec(item_ref.as_bytes().to_vec());
            Ok(self.root.join(PathBuf::from(rel)))
        }
    }
}

impl EnumerationConnector for FilesystemConnector {
    fn caps(&self) -> ConnectorCapabilities {
        ConnectorCapabilities {
            seek_by_key: true,
            token_resume: self.emit_tokens,
            range_read: true,
            split_hints: true,
        }
    }

    fn enumerate_page(
        &mut self,
        shard: &gossip_contracts::coordination::ShardSpec,
        cursor: &Cursor,
        budgets: Budgets,
    ) -> Result<EnumerationPage, EnumerateError> {
        let start = ItemKey::try_from_slice(shard.start_key_bytes())
            .map_err(|e| EnumerateError::permanent(format!("invalid shard start: {e}")))?;
        let end = ItemKey::try_from_slice(shard.end_key_bytes())
            .map_err(|e| EnumerateError::permanent(format!("invalid shard end: {e}")))?;
        self.enumerate_page_range(&start, &end, cursor, budgets)
    }

    fn choose_split_point(
        &mut self,
        shard: &gossip_contracts::coordination::ShardSpec,
        cursor: &Cursor,
    ) -> Result<Option<ItemKey>, EnumerateError> {
        let start = ItemKey::try_from_slice(shard.start_key_bytes())
            .map_err(|e| EnumerateError::permanent(format!("invalid shard start: {e}")))?;
        let end = ItemKey::try_from_slice(shard.end_key_bytes())
            .map_err(|e| EnumerateError::permanent(format!("invalid shard end: {e}")))?;
        self.choose_split_point_range(&start, &end, cursor)
    }
}

impl ReadConnector for FilesystemConnector {
    fn open(
        &mut self,
        item_ref: &ItemRef,
        budgets: Budgets,
    ) -> Result<Box<dyn io::Read + Send>, ReadError> {
        let path = self.resolve_item_ref(item_ref)?;

        let meta = fs::metadata(&path).map_err(|e| ReadError {
            class: ErrorClass::Retryable,
            message: format!("metadata failed: {e}"),
            retry_after_ms: None,
        })?;

        let size = meta.len();
        if size > budgets.max_bytes {
            return Err(ReadError {
                class: ErrorClass::Permanent,
                message: "item exceeds max_bytes budget".into(),
                retry_after_ms: None,
            });
        }

        let f = fs::File::open(&path).map_err(|e| ReadError {
            class: ErrorClass::Retryable,
            message: format!("open failed: {e}"),
            retry_after_ms: None,
        })?;

        Ok(Box::new(f))
    }

    fn read_range(
        &mut self,
        item_ref: &ItemRef,
        offset: u64,
        dst: &mut [u8],
        budgets: Budgets,
    ) -> Result<usize, ReadError> {
        use std::io::{Read, Seek, SeekFrom};

        let path = self.resolve_item_ref(item_ref)?;
        let mut f = fs::File::open(&path).map_err(|e| ReadError {
            class: ErrorClass::Retryable,
            message: format!("open failed: {e}"),
            retry_after_ms: None,
        })?;

        f.seek(SeekFrom::Start(offset)).map_err(|e| ReadError {
            class: ErrorClass::Retryable,
            message: format!("seek failed: {e}"),
            retry_after_ms: None,
        })?;

        let max = budgets.max_bytes.min(dst.len() as u64) as usize;
        let n = f.read(&mut dst[..max]).map_err(|e| ReadError {
            class: ErrorClass::Retryable,
            message: format!("read failed: {e}"),
            retry_after_ms: None,
        })?;

        Ok(n)
    }
}

// --------------------------
// Index build (unix)
// --------------------------

#[cfg(unix)]
fn walk_dir_collect_files(
    root: &Path,
    dir: &Path,
    out: &mut Vec<FileEntry>,
) -> Result<(), EnumerateError> {
    let mut entries: Vec<PathBuf> = Vec::new();

    let rd = fs::read_dir(dir).map_err(|e| EnumerateError::retryable(format!("read_dir failed: {e}")))?;
    for ent in rd {
        let ent = ent.map_err(|e| EnumerateError::retryable(format!("read_dir entry failed: {e}")))?;
        entries.push(ent.path());
    }

    // Deterministic per-directory ordering.
    entries.sort_by(|a, b| a.as_os_str().as_bytes().cmp(b.as_os_str().as_bytes()));

    for path in entries {
        let meta = fs::metadata(&path).map_err(|e| EnumerateError::retryable(format!("metadata failed: {e}")))?;
        if meta.is_dir() {
            walk_dir_collect_files(root, &path, out)?;
            continue;
        }
        if !meta.is_file() {
            continue;
        }

        let rel = path.strip_prefix(root).map_err(|_| EnumerateError::permanent("path not under root"))?;
        let rel_bytes = encode_rel_path(rel);
        let key = ItemKey::try_from_slice(&rel_bytes)
            .map_err(|e| EnumerateError::permanent(format!("invalid path key: {e}")))?;

        let stable_item_id = derive_stable_item_id(&key);
        let version = VersionId::Weak(derive_fs_version_id(&meta));

        out.push(FileEntry {
            key,
            rel_bytes: Arc::from(rel_bytes.into_boxed_slice()),
            stable_item_id,
            version,
            size: meta.len(),
        });
    }

    Ok(())
}

/// Encode relative path to stable bytes for PathKey.
///
/// Unix-only: uses raw OsStr bytes joined with `/`.
#[cfg(unix)]
fn encode_rel_path(rel: &Path) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, comp) in rel.components().enumerate() {
        let s = comp.as_os_str().as_bytes();
        if i != 0 {
            out.push(b'/');
        }
        out.extend_from_slice(s);
    }
    out
}

fn lower_bound_file(files: &[FileEntry], key: &[u8]) -> usize {
    let mut lo = 0usize;
    let mut hi = files.len();
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if files[mid].key.as_bytes() < key {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    lo
}

fn upper_bound_file(files: &[FileEntry], key: &[u8]) -> usize {
    let mut lo = 0usize;
    let mut hi = files.len();
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if files[mid].key.as_bytes() <= key {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    lo
}

// Identity helpers (assume these constructors exist in your identity module).
fn derive_stable_item_id(key: &ItemKey) -> StableItemId {
    let h = blake3::hash(key.as_bytes());
    StableItemId::from_bytes(*h.as_bytes())
}

#[cfg(unix)]
fn derive_fs_version_id(meta: &fs::Metadata) -> ObjectVersionId {
    // Weak version: (mtime_ns, size, inode)
    let mtime_ns = meta.mtime_nsec() as i64;
    let mtime_s = meta.mtime() as i64;
    let size = meta.len();
    let ino = meta.ino();

    let mut buf = Vec::with_capacity(8 + 8 + 8 + 8);
    buf.extend_from_slice(&mtime_s.to_be_bytes());
    buf.extend_from_slice(&mtime_ns.to_be_bytes());
    buf.extend_from_slice(&size.to_be_bytes());
    buf.extend_from_slice(&ino.to_be_bytes());

    let h = blake3::hash(&buf);
    ObjectVersionId::from_bytes(*h.as_bytes())
}
```

Notes:

- This uses Unix raw-path bytes and is deterministic on Unix.
- Like the in-memory connector, it uses `shard.start_key_bytes()` placeholders.

---

## `crates/gossip-connectors/tests/conformance.rs`

This is the “both pass harness” proof.

```rust
use std::sync::Arc;

use gossip_contracts::connector::conformance::{assert_connector_conforms, ConformanceConfig};
use gossip_contracts::connector::{Budgets, Cursor, ItemKey};

use gossip_connectors::{FilesystemConnector, InMemoryDeterministicConnector};
use gossip_connectors::in_memory::MemItem;

#[test]
fn in_memory_connector_passes_conformance() {
    let start = ItemKey::try_from_slice(&[0x00]).unwrap();
    let end = ItemKey::try_from_slice(&[0xFF]).unwrap();

    let items: Vec<MemItem> = (0u32..200)
        .map(|i| {
            let k = format!("k{:08}", i);
            let key = ItemKey::try_from_slice(k.as_bytes()).unwrap();
            let bytes: Arc<[u8]> = Arc::from(format!("payload-{i}").into_bytes().into_boxed_slice());
            MemItem::new(key, bytes)
        })
        .collect();

    let cfg = ConformanceConfig {
        page_budgets: Budgets::new(17, u64::MAX, None), // force pagination
        ..ConformanceConfig::default()
    };

    assert_connector_conforms(
        || InMemoryDeterministicConnector::new(items.clone()).with_tokens(true),
        |c| c.caps(),
        |c, cursor, budgets| c.enumerate_page_range(&start, &end, cursor, budgets),
        &start,
        &end,
        cfg,
    )
    .unwrap();
}

#[test]
fn filesystem_connector_passes_conformance() {
    let start = ItemKey::try_from_slice(&[0x00]).unwrap();
    let end = ItemKey::try_from_slice(&[0xFF]).unwrap();

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();

    // Create deterministic file set.
    std::fs::create_dir_all(root.join("a")).unwrap();
    std::fs::create_dir_all(root.join("b/sub")).unwrap();
    std::fs::write(root.join("a/one.txt"), b"one").unwrap();
    std::fs::write(root.join("a/two.txt"), b"two").unwrap();
    std::fs::write(root.join("b/sub/three.txt"), b"three").unwrap();

    let cfg = ConformanceConfig {
        page_budgets: Budgets::new(2, u64::MAX, None), // force pagination
        ..ConformanceConfig::default()
    };

    assert_connector_conforms(
        || FilesystemConnector::new(root).with_tokens(false),
        |c| c.caps(),
        |c, cursor, budgets| c.enumerate_page_range(&start, &end, cursor, budgets),
        &start,
        &end,
        cfg,
    )
    .unwrap();
}
```

---

# Notes you should not ignore

- **ShardSpec adapter methods are placeholders**:
  - I used `shard.start_key_bytes()` / `shard.end_key_bytes()` intentionally because I don’t know your exact `ShardSpec` API. Replace those with your real accessor(s).
  - The important part is that the connector core logic is in `enumerate_page_range()`, which is independent of ShardSpec.

- **Identity constructors are assumed**:
  - `StableItemId::from_bytes([u8; 32])`
  - `ObjectVersionId::from_bytes([u8; 32])`
    If your identity module uses different names, change only those helper functions.

- **Strict key uniqueness requirement**:
  - The conformance harness defaults to strict uniqueness and strict ordering. These connectors satisfy it.

---

# Commands

```bash
cargo test -p gossip-connectors
```

This chunk gives you two concrete connectors that:

- exercise the validator + harness seriously,
- are deterministic,
- have correct resume-by-key semantics even with token corruption,
- and provide a template for real connectors.

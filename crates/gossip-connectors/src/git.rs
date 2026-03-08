//! Deterministic connector for Git-tracked files.
//!
//! This connector indexes tracked files via `git ls-files -z`, then serves
//! key-range pages over that static snapshot. Item keys and item refs are both
//! the raw repository-relative path bytes.
//!
//! # Indexing model
//!
//! - Indexing is lazy (`ensure_indexed`): the first
//!   enumerate or read call shells out to `git ls-files -z` and builds a
//!   sorted in-memory snapshot.
//! - Once indexed, the snapshot is immutable for the connector's lifetime.
//!   The connector does **not** track live repository changes — any new
//!   commits, staging-area edits, or working-tree mutations after the first
//!   enumeration call are invisible.
//! - Enumeration order is deterministic for a fixed repository state because
//!   entries are globally sorted by raw key bytes after indexing.
//! - Split hints bulk-load the indexed suffix into
//!   `StreamingSplitEstimator`,
//!   so git and filesystem connectors share the same byte-weighted split
//!   algorithm even though one indexes eagerly and the other streams walks.
//!
//! # Version model
//!
//! Git does not expose a strong per-file content hash through `ls-files`, so
//! this connector produces **weak** versions: a BLAKE3 digest over
//! `(path, file_size, mtime_nanos)`. Two snapshots of the same file will
//! yield identical versions only when both size and mtime agree. This is
//! sufficient for change-detection but does not guarantee content identity.
//!
//! # Security model
//!
//! The connector defends against path traversal and symlink escapes in
//! untrusted repositories using a three-layer approach:
//!
//! 1. The repo root is canonicalized at index time.
//! 2. Each tracked path is rejected if it contains `..` components or
//!    resolves outside the canonical repo root.
//! 3. Only regular files are indexed (`symlink_metadata`); symlinks are
//!    skipped regardless of target.
//! 4. Read-time containment: `open_path_for_ref` re-canonicalizes and
//!    checks the boundary before returning a path.
//!
//! # Error classification
//!
//! I/O errors are classified as *permanent* (not-found, permission-denied,
//! invalid-input, symlink loops) or *retryable* (everything else — typically
//! transient filesystem errors). Permanent errors during initial indexing
//! latch `IndexState::Failed` so subsequent calls fail fast without
//! re-shelling to `git`.
//!
//! # Platform behavior
//!
//! On Unix, git paths are converted to `OsString` losslessly via
//! `OsStringExt::from_vec`. On non-Unix platforms, paths are decoded
//! through `String::from_utf8_lossy`, which replaces invalid UTF-8 with
//! U+FFFD — a lossy but safe fallback.

use std::{
    fs,
    io::{self, Read, Seek, SeekFrom},
    path::{Component, Path, PathBuf},
    process::Command,
    time::{Instant, UNIX_EPOCH},
};

use gossip_contracts::{
    connector::{
        Budgets, ConnectorCapabilities, Cursor, EnumerateError, EnumerationPage, ItemKey, ItemRef,
        ReadError, ScanItem, VersionId,
    },
    coordination::ShardSpec,
    identity::{ConnectorInstanceIdHash, ObjectVersionId, StableItemId},
};

use crate::common::{
    self, GIT_CONNECTOR_TAG, borrowed_shard_bound, classify_io_enumerate_error,
    classify_io_read_error, derive_stable_item_id, enumerate_error_to_read, path_buf_from_bytes,
};

/// A single indexed file from `git ls-files`.
///
/// Each entry caches the pre-computed identity and weak version so that
/// enumeration pages can be assembled without re-hashing on every page
/// request. Entries are sorted by `key` (byte-lexicographic) after indexing
/// and remain immutable thereafter.
#[derive(Debug)]
struct GitEntry {
    /// Repository-relative path used as both the item key and the item ref.
    key: ItemKey,
    /// Domain-separated BLAKE3 identity derived from
    /// `(ConnectorTag, ConnectorInstanceIdHash, key)`.
    stable_item_id: StableItemId,
    /// Weak version fingerprint over `(path, size, mtime)`.
    version: VersionId,
    /// File size in bytes at index time, used as a size hint for budgeting.
    size_hint: u64,
}

impl common::KeyedEntry for GitEntry {
    fn key_bytes(&self) -> &[u8] {
        self.key.as_bytes()
    }
}

/// Tri-state machine for the lazy indexing lifecycle.
///
/// Transitions:
/// - `NotIndexed → Indexed` on successful `git ls-files` + snapshot build.
/// - `NotIndexed → Failed` on permanent I/O or git errors.
///
/// Both `Indexed` and `Failed` are **terminal**: once reached, the connector
/// never re-attempts indexing. `Failed` latches an error message so that
/// subsequent calls fail fast with a stable diagnostic.
enum IndexState {
    /// No indexing attempt has been made yet.
    NotIndexed,
    /// Snapshot built successfully; entries are populated and sorted.
    Indexed,
    /// A permanent error occurred during indexing; retries are suppressed.
    Failed(String),
}

/// Connector that enumerates and reads Git-tracked repository files.
///
/// The connector lazily indexes tracked files on first use, then serves
/// paginated enumeration and byte-range reads from that frozen snapshot.
///
/// # Invariants
///
/// - After `index_state` reaches `IndexState::Indexed`, `entries` is
///   non-empty (unless the repository has no tracked files), sorted by
///   `key` in byte-lexicographic order, and never mutated again.
/// - `repo` is validated once during indexing; a missing or non-directory
///   path latches a permanent failure.
/// - When `emit_tokens` is true, cursors carry an 8-byte big-endian
///   absolute index that enables O(1) resume. Token validity is always
///   cross-checked against the last emitted key.
pub struct GitConnector {
    /// Absolute path to the repository root (working directory).
    repo: PathBuf,
    /// Stable connector-instance scope used for `StableItemId` derivation.
    connector_instance: ConnectorInstanceIdHash,
    /// Whether pagination cursors include positional tokens for O(1)
    /// resume. Defaults to `true`; set to `false` for key-only cursors.
    emit_tokens: bool,
    /// Optional upper bound on tracked files. When set, `ensure_indexed`
    /// rejects repositories that exceed this limit with a permanent error.
    max_tracked_files: Option<usize>,
    /// Lazy indexing state machine. See [`IndexState`].
    index_state: IndexState,
    /// Sorted snapshot of tracked files, populated by [`ensure_indexed`].
    entries: Vec<GitEntry>,
}

impl GitConnector {
    /// Create a connector rooted at `repo`.
    pub fn new(repo: impl Into<PathBuf>) -> Self {
        let repo = repo.into();
        assert!(
            !repo.as_os_str().is_empty(),
            "GitConnector repo path must not be empty"
        );
        let connector_instance =
            ConnectorInstanceIdHash::from_instance_id_bytes(repo.as_os_str().as_encoded_bytes());
        Self {
            repo,
            connector_instance,
            emit_tokens: true,
            max_tracked_files: None,
            index_state: IndexState::NotIndexed,
            entries: Vec::new(),
        }
    }

    /// Enable or disable pagination token emission/consumption.
    #[must_use]
    pub fn with_tokens(mut self, enabled: bool) -> Self {
        self.emit_tokens = enabled;
        self
    }

    /// Set an upper bound on tracked files. Repositories exceeding this
    /// limit will fail indexing with a permanent error.
    #[must_use]
    pub fn with_max_tracked_files(mut self, limit: usize) -> Self {
        self.max_tracked_files = Some(limit);
        self
    }

    /// Enumerate one page over the explicit half-open key range `[start, end)`.
    ///
    /// # Errors
    ///
    /// Returns `EnumerateError::permanent` if `start > end`.
    pub fn enumerate_page_range(
        &mut self,
        start: &ItemKey,
        end: &ItemKey,
        cursor: &Cursor,
        budgets: Budgets,
    ) -> Result<EnumerationPage, EnumerateError> {
        self.enumerate_page_bounds(
            Some(start.as_bytes()),
            Some(end.as_bytes()),
            cursor,
            budgets,
        )
    }

    /// Return a split-point hint over the explicit half-open key range
    /// `[start, end)`.
    ///
    /// # Errors
    ///
    /// Returns `EnumerateError::permanent` if `start > end`.
    pub fn choose_split_point_range(
        &mut self,
        start: &ItemKey,
        end: &ItemKey,
        cursor: &Cursor,
        deadline: Option<Instant>,
    ) -> Result<Option<ItemKey>, EnumerateError> {
        self.choose_split_point_bounds(
            Some(start.as_bytes()),
            Some(end.as_bytes()),
            cursor,
            deadline,
        )
    }

    /// Lazily build the sorted file snapshot on first call.
    ///
    /// Runs `git ls-files -z` in the repository, stats each tracked path,
    /// and populates `self.entries` in sorted key order. Subsequent calls
    /// are no-ops (indexed) or fast-fail (permanently failed).
    ///
    /// # Security hardening
    ///
    /// The repo root is canonicalized before any file operations so that
    /// subsequent path joins resolve against the real filesystem path.
    /// Each tracked path is then validated with a three-layer defense:
    ///
    /// 1. **Component filter** — paths containing `..` are rejected.
    /// 2. **Canonicalize + containment** — the resolved absolute path
    ///    must start with the canonicalized repo root.
    /// 3. **Symlink rejection** — `symlink_metadata` ensures only
    ///    regular files are indexed (symlinks are skipped).
    ///
    /// The `deadline` is checked both before shelling out and between
    /// per-file stat calls, so large repositories can be interrupted
    /// without blocking the caller. A deadline expiry returns a
    /// *retryable* error (the index state stays `NotIndexed`), while a
    /// git/I/O failure that is classified as permanent latches
    /// [`IndexState::Failed`].
    fn ensure_indexed(&mut self, deadline: Option<Instant>) -> Result<(), EnumerateError> {
        match &self.index_state {
            IndexState::Indexed => return Ok(()),
            IndexState::Failed(message) => {
                return Err(EnumerateError::permanent(message.clone()));
            }
            IndexState::NotIndexed => {}
        }

        if deadline_expired(deadline) {
            return Err(EnumerateError::retryable("indexing deadline expired"));
        }

        // Canonicalize the repo root so all subsequent joins resolve against
        // the real path. This also fails fast for non-existent paths.
        match fs::canonicalize(&self.repo) {
            Ok(canonical) => self.repo = canonical,
            Err(err) => {
                let e = classify_io_enumerate_error("canonicalize", &self.repo, &err);
                if !e.is_retryable() {
                    self.index_state = IndexState::Failed(e.message().to_owned());
                }
                return Err(e);
            }
        }
        if !self.repo.is_dir() {
            let digest = common::path_digest(&self.repo);
            let msg = format!("repository path must be a directory: ({digest})");
            self.index_state = IndexState::Failed(msg.clone());
            return Err(EnumerateError::permanent(msg));
        }

        let tracked = match list_git_tracked_paths(&self.repo) {
            Ok(paths) => paths,
            Err(error) => {
                if !error.is_retryable() {
                    self.index_state = IndexState::Failed(error.message().to_owned());
                }
                return Err(error);
            }
        };

        if let Some(max) = self.max_tracked_files
            && tracked.len() > max
        {
            let msg = format!(
                "repository tracks {} files, exceeding limit of {max}",
                tracked.len()
            );
            self.index_state = IndexState::Failed(msg.clone());
            return Err(EnumerateError::permanent(msg));
        }

        let mut entries = Vec::with_capacity(tracked.len());
        for key_bytes in tracked {
            if deadline_expired(deadline) {
                return Err(EnumerateError::retryable("indexing deadline expired"));
            }
            if key_bytes.is_empty() {
                continue;
            }

            let rel_path = path_buf_from_bytes(&key_bytes);
            // Reject paths containing ".." to prevent directory traversal.
            if rel_path
                .components()
                .any(|c| matches!(c, Component::ParentDir))
            {
                continue;
            }
            let abs_path = self.repo.join(&rel_path);

            // Canonicalize to verify the resolved path stays within the repo.
            let canonical_abs = match fs::canonicalize(&abs_path) {
                Ok(p) => p,
                Err(_) => continue,
            };
            if !canonical_abs.starts_with(&self.repo) {
                continue;
            }

            // symlink_metadata avoids following symlinks — a tracked symlink
            // must not be indexed since it could escape the repo root in
            // untrusted repositories.
            let metadata = match fs::symlink_metadata(&abs_path) {
                Ok(m) => m,
                Err(error) => {
                    return Err(classify_io_enumerate_error("metadata", &abs_path, &error));
                }
            };
            if !metadata.is_file() {
                continue;
            }
            let entry = build_git_entry(
                self.connector_instance,
                &key_bytes,
                metadata.len(),
                metadata.modified().ok(),
            )?;
            entries.push(entry);
        }

        entries.sort_unstable_by(|left, right| left.key.cmp(&right.key));

        self.entries = entries;
        self.index_state = IndexState::Indexed;
        Ok(())
    }

    /// Core pagination over an optional half-open byte range `[start, end)`.
    ///
    /// 1. Ensures the index is built (lazy, respects `budgets.deadline()`).
    /// 2. Resolves shard bounds to index positions via binary search.
    /// 3. Determines the resume position from the cursor — first by
    ///    key-authoritative O(log N) upper-bound, then accelerated to
    ///    O(1) when a valid positional token is present and its key
    ///    cross-check passes (see inline comments below).
    /// 4. Slices at most `budgets.max_items()` entries, assembles pooled
    ///    `ScanItem`s, and builds the continuation cursor.
    ///
    /// `None` bounds mean unbounded on that side.
    fn enumerate_page_bounds(
        &mut self,
        start: Option<&[u8]>,
        end: Option<&[u8]>,
        cursor: &Cursor,
        budgets: Budgets,
    ) -> Result<EnumerationPage, EnumerateError> {
        self.ensure_indexed(budgets.deadline())?;
        let bounds = common::resolve_page_bounds(&self.entries, start, end, budgets)?;
        let key_resume = common::key_resume_start(&self.entries, cursor, bounds.range_start);
        let mut start_idx = key_resume;

        // Token fast-path: when the cursor carries a positional token and the
        // entry at `token_idx - 1` still matches the last emitted key, we can
        // skip the O(log N) binary search and resume at O(1). If the token is
        // missing, malformed, out of range, or disagrees with the key, we
        // silently fall back to `key_resume` (the binary-search result above).
        //
        // The `.max(token_idx)` ensures the token can only advance the resume
        // position forward — never behind the key-derived floor.
        if let Some(last_key) = cursor.last_key() {
            let token_idx = self
                .emit_tokens
                .then(|| common::cursor_token_index(cursor))
                .flatten();
            if let Some(token_idx) = token_idx
                && token_idx > 0
                && token_idx <= self.entries.len()
                && self.entries[token_idx - 1].key == *last_key
            {
                start_idx = start_idx.max(token_idx);

                // In debug builds, verify the O(1) token path and O(log N)
                // key path agree — a mismatch indicates an index corruption
                // or a cursor that was constructed against a different snapshot.
                #[cfg(debug_assertions)]
                debug_assert_eq!(
                    token_idx, key_resume,
                    "token index {token_idx} disagrees with key-derived resume position {key_resume}"
                );
            }
        }

        if start_idx >= bounds.range_end {
            return Ok(EnumerationPage::new(Vec::new(), cursor.clone()));
        }

        let take = budgets.max_items().min(bounds.range_end - start_idx);
        let page_entries = &self.entries[start_idx..(start_idx + take)];

        let staged = common::assemble_pooled_page_shared_key_ref(
            page_entries.iter().map(|entry| entry.key.as_bytes()),
            self.emit_tokens,
            start_idx,
        )?;

        let common::StagedPage { wrappers, token } = staged;
        let mut out = Vec::with_capacity(wrappers.len());
        for ((item_key, item_ref), entry) in wrappers.into_iter().zip(page_entries) {
            out.push(
                ScanItem::new(item_key, item_ref, entry.stable_item_id, entry.version)
                    .with_size_hint(entry.size_hint),
            );
        }

        let last_key = match out.last() {
            Some(item) => item.item_key().clone(),
            None => return Ok(EnumerationPage::new(Vec::new(), cursor.clone())),
        };
        let next_cursor = common::build_next_cursor_from_staged(
            last_key,
            start_idx,
            out.len(),
            self.emit_tokens,
            token,
        )?;

        Ok(EnumerationPage::new(out, next_cursor))
    }

    /// Choose a byte-weighted split point in the optional range `[start, end)`.
    ///
    /// Delegates to [`common::estimate_split_from_sorted`] after resolving
    /// bounds and the cursor resume position. Returns `None` when fewer than
    /// two keys remain, the estimator produces no candidate, or the candidate
    /// fails validation.
    fn choose_split_point_bounds(
        &mut self,
        start: Option<&[u8]>,
        end: Option<&[u8]>,
        cursor: &Cursor,
        deadline: Option<Instant>,
    ) -> Result<Option<ItemKey>, EnumerateError> {
        self.ensure_indexed(deadline)?;

        let bounds = common::resolve_bounds(&self.entries, start, end)?;
        let start_idx = common::key_resume_start(&self.entries, cursor, bounds.range_start);
        if start_idx >= bounds.range_end {
            return Ok(None);
        }

        let range = &self.entries[start_idx..bounds.range_end];
        common::estimate_split_from_sorted(
            range
                .iter()
                .map(|entry| (entry.key.as_bytes(), entry.size_hint)),
            range.len(),
            cursor,
            end,
        )
    }

    /// Resolve an `ItemRef` to an absolute filesystem path.
    ///
    /// Ensures the index is built, then performs an O(log N) binary search
    /// to verify the ref exists in the snapshot. The resolved path is then
    /// canonicalized and checked against the repo boundary before the caller
    /// opens it. This catches snapshot drift such as a tracked path being
    /// replaced with an out-of-repo symlink after indexing, but it is still a
    /// best-effort containment check rather than a TOCTOU-proof openat walk.
    fn open_path_for_ref(&mut self, item_ref: &ItemRef) -> Result<PathBuf, ReadError> {
        self.ensure_indexed(None).map_err(enumerate_error_to_read)?;

        let ref_bytes = item_ref.as_bytes();
        self.entries
            .binary_search_by(|entry| entry.key.as_bytes().cmp(ref_bytes))
            .map_err(|_| ReadError::permanent("item_ref not found in index"))?;

        let abs_path = self.repo.join(path_buf_from_bytes(ref_bytes));
        let canonical = fs::canonicalize(&abs_path)
            .map_err(|error| classify_io_read_error("canonicalize", Some(&abs_path), &error))?;
        if !canonical.starts_with(&self.repo) {
            return Err(ReadError::permanent(
                "resolved path escapes repository boundary",
            ));
        }
        Ok(abs_path)
    }
}

impl GitConnector {
    /// Advertise connector capabilities used by orchestration planning.
    pub fn caps(&self) -> ConnectorCapabilities {
        ConnectorCapabilities {
            seek_by_key: true,
            token_resume: self.emit_tokens,
            range_read: true,
            split_hints: true,
        }
    }

    /// Enumerate one page of items.
    pub fn enumerate_page(
        &mut self,
        shard: &ShardSpec,
        cursor: &Cursor,
        budgets: Budgets,
    ) -> Result<EnumerationPage, EnumerateError> {
        let start = borrowed_shard_bound(shard.key_range_start(), "start")?;
        let end = borrowed_shard_bound(shard.key_range_end(), "end")?;
        self.enumerate_page_bounds(start, end, cursor, budgets)
    }

    /// Split-point hint for dynamic shard subdivision.
    pub fn choose_split_point(
        &mut self,
        shard: &ShardSpec,
        cursor: &Cursor,
        budgets: Budgets,
    ) -> Result<Option<ItemKey>, EnumerateError> {
        let start = borrowed_shard_bound(shard.key_range_start(), "start")?;
        let end = borrowed_shard_bound(shard.key_range_end(), "end")?;
        self.choose_split_point_bounds(start, end, cursor, budgets.deadline())
    }

    /// Open an item for sequential read access.
    pub fn open(
        &mut self,
        item_ref: &ItemRef,
        _budgets: Budgets,
    ) -> Result<Box<dyn io::Read + Send>, ReadError> {
        let path = self.open_path_for_ref(item_ref)?;
        let file = fs::File::open(&path)
            .map_err(|error| classify_io_read_error("open", Some(&path), &error))?;
        Ok(Box::new(file))
    }

    /// Range-read fast path.
    pub fn read_range(
        &mut self,
        item_ref: &ItemRef,
        offset: u64,
        dst: &mut [u8],
        budgets: Budgets,
    ) -> Result<usize, ReadError> {
        if offset.checked_add(dst.len() as u64).is_none() {
            return Err(ReadError::permanent("offset + dst length overflow"));
        }

        let max_bytes = usize::try_from(budgets.max_bytes()).unwrap_or(usize::MAX);
        let allowed = dst.len().min(max_bytes);
        if allowed == 0 {
            return Ok(0);
        }

        let path = self.open_path_for_ref(item_ref)?;
        let mut file = fs::File::open(&path)
            .map_err(|error| classify_io_read_error("open", Some(&path), &error))?;
        file.seek(SeekFrom::Start(offset))
            .map_err(|error| classify_io_read_error("seek", Some(&path), &error))?;
        file.read(&mut dst[..allowed])
            .map_err(|error| classify_io_read_error("read", Some(&path), &error))
    }
}

/// Construct a [`GitEntry`] from raw path bytes and filesystem metadata.
///
/// Validates `key_bytes` as both an [`ItemKey`] and an [`ItemRef`] (they
/// share the same byte representation for this connector). The dual
/// validation catches oversized or malformed paths at index time rather
/// than during later enumeration or read calls.
fn build_git_entry(
    connector_instance: ConnectorInstanceIdHash,
    key_bytes: &[u8],
    size_hint: u64,
    modified: Option<std::time::SystemTime>,
) -> Result<GitEntry, EnumerateError> {
    let key = ItemKey::try_from_slice(key_bytes)
        .map_err(|error| EnumerateError::permanent(format!("invalid git item key: {error}")))?;
    // Validate that the same bytes are also a valid ItemRef. This connector
    // uses identical bytes for key and ref, but the types have independent
    // size limits, so both must pass.
    let _ = ItemRef::try_from_slice(key_bytes)
        .map_err(|error| EnumerateError::permanent(format!("invalid git item_ref: {error}")))?;
    let stable_item_id = derive_stable_item_id(GIT_CONNECTOR_TAG, connector_instance, &key);
    let version = build_weak_version(key_bytes, size_hint, modified);

    Ok(GitEntry {
        key,
        stable_item_id,
        version,
        size_hint,
    })
}

/// Derive a weak version fingerprint from `(path, size, mtime)`.
///
/// "Weak" means the version is based on filesystem metadata rather than
/// file content — two files with identical size and mtime but different
/// contents will collide. This is acceptable because the coordination
/// layer treats weak versions as change-detection hints, not as content
/// identity proofs.
///
/// The encoded material includes `key_bytes`, so renaming a tracked file
/// changes its weak version even if the file's bytes and metadata are
/// otherwise unchanged. That matches the connector's path-keyed item model:
/// path changes are visible as item-version changes to downstream resume and
/// occurrence tracking.
///
/// When `modified` is `None` (e.g., on filesystems that lack mtime
/// support), the mtime component defaults to zero. This still produces a
/// unique version per `(path, size)` pair but loses change sensitivity.
fn build_weak_version(
    key_bytes: &[u8],
    size_hint: u64,
    modified: Option<std::time::SystemTime>,
) -> VersionId {
    // Fixed metadata: 8 (size_hint) + 16 (mtime u128) = 24 bytes.
    // Paths up to 128 bytes fit entirely on the stack (128 + 24 = 152).
    const INLINE_CAP: usize = 152;
    let total_len = key_bytes.len() + 24;
    let modified_nanos = modified
        .and_then(|value| value.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);

    if total_len <= INLINE_CAP {
        let mut buf = [0u8; INLINE_CAP];
        buf[..key_bytes.len()].copy_from_slice(key_bytes);
        buf[key_bytes.len()..key_bytes.len() + 8].copy_from_slice(&size_hint.to_le_bytes());
        buf[key_bytes.len() + 8..key_bytes.len() + 24]
            .copy_from_slice(&modified_nanos.to_le_bytes());
        VersionId::Weak(ObjectVersionId::from_version_bytes(&buf[..total_len]))
    } else {
        let mut version_material = Vec::with_capacity(total_len);
        version_material.extend_from_slice(key_bytes);
        version_material.extend_from_slice(&size_hint.to_le_bytes());
        version_material.extend_from_slice(&modified_nanos.to_le_bytes());
        VersionId::Weak(ObjectVersionId::from_version_bytes(&version_material))
    }
}

/// Shell out to `git ls-files -z` and return NUL-split raw path entries.
///
/// Uses `-z` for NUL-delimited output so paths containing newlines or
/// other special characters are handled correctly. The returned byte
/// vectors are raw repository-relative paths — no encoding conversion is
/// applied here (that happens in [`path_buf_from_bytes`]).
///
/// A non-zero exit from `git` is classified as a permanent error because
/// it typically indicates that the directory is not a git repository.
fn list_git_tracked_paths(repo: &Path) -> Result<Vec<Vec<u8>>, EnumerateError> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .arg("ls-files")
        .arg("-z")
        .arg("--")
        .output()
        .map_err(|error| classify_io_enumerate_error("git ls-files", repo, &error))?;

    if !output.status.success() {
        let digest = common::path_digest(repo);
        return Err(EnumerateError::permanent(format!(
            "git ls-files failed in ({digest}) (status={:?}): {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }

    let mut paths = Vec::new();
    for entry in output.stdout.split(|byte| *byte == 0) {
        if entry.is_empty() {
            continue;
        }
        paths.push(entry.to_vec());
    }
    Ok(paths)
}

/// Returns `true` when a deadline is present and has already passed.
fn deadline_expired(deadline: Option<Instant>) -> bool {
    deadline.is_some_and(|value| Instant::now() >= value)
}

#[cfg(test)]
#[path = "git_tests.rs"]
mod tests;

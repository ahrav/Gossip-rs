//! Worker-local mirror lifecycle helpers for repo-native Git execution.
//!
//! [`LocalMirrorManager`] is the concrete [`GitMirrorManager`] implementation
//! for the current local-path repository surface. Local repositories are
//! validated in place and returned as [`LocalMirror`] values rooted at the
//! canonical repository path.
//!
//! Mirror cache naming is defined independently from local-path validation so
//! every locator kind has one bounded, redaction-safe filesystem layout. Cache
//! paths use the `GIT_MIRROR_PATH_V1` hash domain and the layout
//! `<mirror_root>/local/<prefix>/<digest>.git`, where `digest` is the
//! 256-bit hash of the canonical `RepoKey` encoding (locator-kind tag followed
//! by canonical repo path).
//!
//! Cache mutation control files live beside the authoritative mirror directory:
//! `<digest>.git.initializing` marks first-create publication and
//! `<digest>.git.lock` serializes mirror mutation. Construction removes stale
//! control files left behind by dead processes or files older than the
//! configured age backstop. The cleanup logic removes stale control files but
//! does not itself create them; the write path depends on mirror mutation
//! operations not yet implemented for this locator kind.
//!
//! Error classification follows the connector I/O policy: structural
//! filesystem failures are permanent, concurrent maintenance remains
//! retryable, and every path-bearing diagnostic is redacted through
//! [`ToxicDigest`](gossip_contracts::connector::ToxicDigest).
//!
//! Allocation tier: COLD. Mirror management runs during repo setup, not in any
//! steady-state scan loop.

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use gossip_connectors::is_permanent_io_error;
use gossip_contracts::connector::git::{
    GitMirrorManager, GitRunError, LocalMirror, RepoKey, RepoLocator,
};
use gossip_contracts::identity::CanonicalBytes;
use gossip_contracts::identity::finalize_32;
use gossip_contracts::identity::hashing::MIRROR_PATH_HASHER;
use scanner_git::{ArtifactStatus, PreflightError, PreflightLimits, preflight};

use crate::git_repo::digest_repo_path as redacted_path_digest;

const MIRROR_LOCAL_LOCATOR_DIR: &str = "local";
const DEFAULT_STALE_CONTROL_AGE: Duration = Duration::from_secs(30 * 60);

/// Concrete worker-local mirror manager for repo-native Git execution.
///
/// The manager validates local-path repositories in place and returns
/// canonical repo roots as [`LocalMirror`] values. It also owns the
/// deterministic cache-path layout and stale control-file cleanup for
/// worker-local mirror directories.
///
/// # Invariants
///
/// - `mirror_root` is canonicalized during construction.
/// - Cache paths are derived from canonical repo identity bytes, never raw
///   display metadata.
/// - Control-file cleanup only targets manager-owned sibling files
///   (`*.git.lock`, `*.git.initializing`), not Git's internal maintenance
///   locks inside repository directories.
/// - `&mut self` on [`GitMirrorManager`] provides single-owner access, so this
///   type does not need internal mutexes or lock maps.
pub struct LocalMirrorManager {
    mirror_root: PathBuf,
    preflight_limits: PreflightLimits,
    stale_control_age: Duration,
}

impl LocalMirrorManager {
    /// Construct a mirror manager rooted at `mirror_root`.
    ///
    /// The root directory is created if needed, canonicalized, and scanned for
    /// stale manager control files before the manager is returned. Local-path
    /// repositories validate in place, but the root still owns the
    /// deterministic cache namespace and control-file cleanup policy.
    ///
    /// # Errors
    ///
    /// Returns [`GitRunError`] when the root directory cannot be created,
    /// canonicalized, or traversed during stale-control cleanup.
    pub fn new(mirror_root: impl Into<PathBuf>) -> Result<Self, GitRunError> {
        Self::with_settings(
            mirror_root.into(),
            PreflightLimits::default(),
            DEFAULT_STALE_CONTROL_AGE,
        )
    }

    fn with_settings(
        mirror_root: PathBuf,
        preflight_limits: PreflightLimits,
        stale_control_age: Duration,
    ) -> Result<Self, GitRunError> {
        let layout_root = mirror_root.join(MIRROR_LOCAL_LOCATOR_DIR);
        fs::create_dir_all(&layout_root)
            .map_err(|err| classify_io_git_run_error("create mirror root", &layout_root, &err))?;
        let canonical_root = fs::canonicalize(&mirror_root).map_err(|err| {
            classify_io_git_run_error("canonicalize mirror root", &mirror_root, &err)
        })?;

        let manager = Self {
            mirror_root: canonical_root,
            preflight_limits,
            stale_control_age,
        };
        if let Err(err) = manager.cleanup_stale_control_files() {
            tracing::warn!(
                error = %err,
                mirror_root = %redacted_path_digest(manager.mirror_root()),
                "stale control-file cleanup failed, proceeding with manager construction"
            );
        }
        Ok(manager)
    }

    /// Returns the canonical mirror-root directory.
    #[must_use]
    pub fn mirror_root(&self) -> &Path {
        self.mirror_root.as_path()
    }

    /// Derive the authoritative cache path for `locator`.
    ///
    /// This helper uses canonical repo identity bytes rather than raw
    /// user-supplied path spellings, so equivalent local-path inputs resolve to
    /// the same worker-local mirror directory. Local-path mirror sync validates
    /// in place and returns the original canonical repo root, so this path is
    /// a **stable naming convention only** — the returned directory is not
    /// materialized on disk for local-path locators. Callers needing the actual
    /// on-disk mirror path should use [`sync_mirror`](GitMirrorManager::sync_mirror).
    ///
    /// # Errors
    ///
    /// Returns [`GitRunError`] when the locator does not resolve to a valid
    /// local Git repository or when identity encoding exceeds the connector key
    /// contract.
    pub fn authoritative_cache_path(&self, locator: &RepoLocator) -> Result<PathBuf, GitRunError> {
        let report = self.preflight_local_repo(locator)?;
        let repo_key = repo_key_for_local_root(report.repo.canonical_repo_root())?;
        Ok(self.cache_path_for_repo_key(&repo_key))
    }

    fn preflight_local_repo(
        &self,
        locator: &RepoLocator,
    ) -> Result<scanner_git::PreflightReport, GitRunError> {
        match locator {
            RepoLocator::LocalPath(path) => preflight(path, self.preflight_limits)
                .map_err(|err| classify_preflight_error(path, err)),
        }
    }

    fn sync_local_path(&self, path: &Path) -> Result<LocalMirror, GitRunError> {
        let locator = RepoLocator::local_path(path);
        let report = self.preflight_local_repo(&locator)?;

        // Only active lock contention blocks mirror sync. Missing performance
        // indexes (commit-graph, multi-pack-index) degrade traversal speed but
        // do not affect correctness, so repos without them are accepted.
        if matches!(
            report.status,
            ArtifactStatus::NeedsMaintenance {
                lock_present: true,
                ..
            }
        ) {
            return Err(GitRunError::concurrent_maintenance());
        }

        Ok(
            LocalMirror::new(report.repo.canonical_repo_root().to_path_buf())
                .with_last_synced_at_ms(crate::epoch_millis_now()),
        )
    }

    fn layout_root(&self) -> PathBuf {
        self.mirror_root.join(MIRROR_LOCAL_LOCATOR_DIR)
    }

    fn cache_path_for_repo_key(&self, repo_key: &RepoKey) -> PathBuf {
        let mut hasher = MIRROR_PATH_HASHER.clone();
        repo_key.as_bytes().write_canonical(&mut hasher);
        let digest = finalize_32(&hasher);
        let hex = gossip_stdx::hex_encode(&digest);
        let prefix = &hex[..4];
        self.layout_root().join(prefix).join(format!("{hex}.git"))
    }

    fn cleanup_stale_control_files(&self) -> Result<(), GitRunError> {
        let layout_root = self.layout_root();
        let mut stack = vec![layout_root.clone()];
        let now_ms = crate::epoch_millis_now();
        while let Some(dir) = stack.pop() {
            let entries = match fs::read_dir(&dir) {
                Ok(entries) => entries,
                Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
                Err(err) => {
                    return Err(classify_io_git_run_error(
                        "scan mirror control files",
                        &dir,
                        &err,
                    ));
                }
            };

            for entry in entries {
                let entry = entry.map_err(|err| {
                    classify_io_git_run_error("read mirror control entry", &dir, &err)
                })?;
                let file_type = entry.file_type().map_err(|err| {
                    classify_io_git_run_error("read mirror control file type", &dir, &err)
                })?;
                let path = entry.path();
                if file_type.is_dir() {
                    // Only recurse into hash-prefix directories (4-character
                    // hex names), never into `.git` mirror directories or
                    // other nested trees that could contain thousands of
                    // entries.
                    if dir == layout_root {
                        stack.push(path);
                    }
                    continue;
                }
                if !file_type.is_file() || !is_manager_control_file(&path) {
                    continue;
                }

                match control_file_is_stale(&path, now_ms, self.stale_control_age) {
                    Ok(true) => {
                        tracing::debug!(
                            path_digest = %redacted_path_digest(&path),
                            "removing stale or unparseable control file"
                        );
                        // TOCTOU: a concurrent process could replace this file between the
                        // staleness check and removal. The configurable age backstop
                        // (`stale_control_age`) makes this window practically unreachable
                        // — a freshly written file would not pass the age test.
                        if let Err(err) = fs::remove_file(&path)
                            && err.kind() != io::ErrorKind::NotFound
                        {
                            return Err(classify_io_git_run_error(
                                "remove stale mirror control file",
                                &path,
                                &err,
                            ));
                        }
                    }
                    Ok(false) => {}
                    Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                    Err(err) => {
                        return Err(classify_io_git_run_error(
                            "read mirror control file",
                            &path,
                            &err,
                        ));
                    }
                }
            }
        }
        Ok(())
    }
}

impl GitMirrorManager for LocalMirrorManager {
    /// Acquire or refresh a local mirror for `locator`.
    ///
    /// Local-path locators are validated in place and returned as canonical
    /// repo roots. Successful calls always populate
    /// [`LocalMirror::last_synced_at_ms`] with the validation time.
    ///
    /// # Errors
    ///
    /// Returns permanent errors for invalid local paths or non-repositories.
    /// Lock-file based concurrent maintenance remains retryable through
    /// [`GitRunError::concurrent_maintenance`].
    fn sync_mirror(&mut self, locator: &RepoLocator) -> Result<LocalMirror, GitRunError> {
        match locator {
            RepoLocator::LocalPath(path) => self.sync_local_path(path),
        }
    }
}

impl fmt::Debug for LocalMirrorManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalMirrorManager")
            .field("mirror_root", &redacted_path_digest(self.mirror_root()))
            .field("preflight_limits", &self.preflight_limits)
            .field("stale_control_age_ms", &self.stale_control_age.as_millis())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ControlFileMetadata {
    pid: u32,
    created_at_ms: u64,
}

impl ControlFileMetadata {
    #[cfg(test)]
    fn encode(self) -> String {
        format!("{}:{}\n", self.pid, self.created_at_ms)
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(bytes).ok()?.trim();
        let (pid, created_at_ms) = text.split_once(':')?;
        let pid: u32 = pid.parse().ok()?;
        if pid == 0 {
            return None;
        }
        Some(Self {
            pid,
            created_at_ms: created_at_ms.parse().ok()?,
        })
    }
}

fn repo_key_for_local_root(canonical_repo_root: &Path) -> Result<RepoKey, GitRunError> {
    RepoKey::for_local_path(canonical_repo_root.as_os_str().as_encoded_bytes()).map_err(|err| {
        GitRunError::permanent(format!(
            "mirror identity encoding failed for ({digest}): {err}",
            digest = redacted_path_digest(canonical_repo_root)
        ))
    })
}

fn is_manager_control_file(path: &Path) -> bool {
    let Some(file_name) = path.file_name() else {
        return false;
    };
    let bytes = file_name.as_encoded_bytes();
    bytes.ends_with(b".git.lock") || bytes.ends_with(b".git.initializing")
}

/// Maximum control file size. Valid files are ~25 bytes (`pid:timestamp\n`);
/// anything larger is corrupt or adversarially placed.
const MAX_CONTROL_FILE_BYTES: u64 = 256;

fn control_file_is_stale(path: &Path, now_ms: u64, max_age: Duration) -> io::Result<bool> {
    // Reject oversized files before reading to avoid unbounded allocation.
    let metadata = fs::metadata(path)?;
    if metadata.len() > MAX_CONTROL_FILE_BYTES {
        return Ok(true);
    }
    let bytes = fs::read(path)?;
    let Some(metadata) = ControlFileMetadata::decode(&bytes) else {
        return Ok(true);
    };

    let max_age_ms = u64::try_from(max_age.as_millis()).unwrap_or(u64::MAX);
    Ok(!pid_is_alive(metadata.pid) || now_ms.saturating_sub(metadata.created_at_ms) >= max_age_ms)
}

#[cfg(unix)]
fn pid_is_alive(pid: u32) -> bool {
    let Ok(pid_i32) = i32::try_from(pid) else {
        return false;
    };
    if pid_i32 <= 0 {
        return false;
    }

    // `kill(pid, 0)` does not send a signal; it only queries whether
    // the process exists and whether the caller may signal it.
    let rc = unsafe { libc::kill(pid_i32 as libc::pid_t, 0) };
    if rc == 0 {
        return true;
    }

    matches!(
        io::Error::last_os_error().raw_os_error(),
        Some(code) if code == libc::EPERM
    )
}

// Non-Unix platforms lack a cheap process-liveness syscall, so staleness
// detection falls back to the age backstop only. Orphaned control files
// from crashed processes may linger for up to `DEFAULT_STALE_CONTROL_AGE`.
#[cfg(not(unix))]
fn pid_is_alive(_pid: u32) -> bool {
    true
}

fn classify_preflight_error(path: &Path, err: PreflightError) -> GitRunError {
    match err {
        PreflightError::Io(source) | PreflightError::Canonicalization(source) => {
            classify_io_git_run_error("prepare local mirror", path, &source)
        }
        PreflightError::NotARepository => GitRunError::permanent(format!(
            "local repository ({}) is not a git repository",
            redacted_path_digest(path)
        )),
        PreflightError::MalformedGitdirFile => GitRunError::permanent(format!(
            "local repository ({}) has a malformed .git file",
            redacted_path_digest(path)
        )),
        PreflightError::GitdirTargetNotDir => GitRunError::permanent(format!(
            "local repository ({}) points at a non-directory gitdir",
            redacted_path_digest(path)
        )),
        PreflightError::MalformedCommondirFile => GitRunError::permanent(format!(
            "local repository ({}) has a malformed commondir file",
            redacted_path_digest(path)
        )),
        PreflightError::CommonDirNotDir => GitRunError::permanent(format!(
            "local repository ({}) points at a non-directory commondir",
            redacted_path_digest(path)
        )),
        PreflightError::ObjectsDirNotDir => GitRunError::permanent(format!(
            "local repository ({}) does not have a valid objects directory",
            redacted_path_digest(path)
        )),
        PreflightError::AlternateNotDir => GitRunError::permanent(format!(
            "local repository ({}) references a non-directory alternate",
            redacted_path_digest(path)
        )),
        PreflightError::FileTooLarge { size, limit } => GitRunError::permanent(format!(
            "local repository ({}) exceeds preflight file limits: size={size} limit={limit}",
            redacted_path_digest(path)
        )),
        // `PreflightError` is `#[non_exhaustive]`, so this arm catches future
        // variants. Defaulting to retryable is safer than permanent — a
        // retryable error lets the caller retry, whereas a false permanent
        // error silently drops the repo. The warn log ensures new variants
        // surface during development.
        _ => {
            tracing::warn!(
                error = %err,
                "unrecognized preflight error variant, classifying as retryable"
            );
            GitRunError::retryable(format!(
                "prepare local mirror failed for ({}): {err}",
                redacted_path_digest(path)
            ))
        }
    }
}

fn classify_io_git_run_error(op: &str, path: &Path, err: &io::Error) -> GitRunError {
    let detail = match err.raw_os_error() {
        Some(code) => format!("kind={:?} raw_os_error={code}", err.kind()),
        None => format!("kind={:?}", err.kind()),
    };
    let message = format!(
        "{op} failed for ({digest}): {detail}",
        digest = redacted_path_digest(path)
    );
    if is_permanent_io_error(err) {
        GitRunError::permanent(message)
    } else {
        GitRunError::retryable(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_fixtures::{init_git_repo, run_git_in};

    use tempfile::tempdir;

    fn init_repo(dir: &Path) {
        init_git_repo(dir, "mirror-tests@example.com", "Mirror Tests");
    }

    #[test]
    fn sync_mirror_returns_canonical_local_repo_root() {
        let repo_dir = tempdir().expect("repo tempdir");
        init_repo(repo_dir.path());
        let mirror_root = tempdir().expect("mirror root");
        let mut manager = LocalMirrorManager::new(mirror_root.path()).expect("manager");

        let before = crate::epoch_millis_now();
        let mirror = manager
            .sync_mirror(&RepoLocator::local_path(repo_dir.path()))
            .expect("sync mirror");
        let after = crate::epoch_millis_now();

        assert_eq!(
            mirror.path(),
            fs::canonicalize(repo_dir.path())
                .expect("canonical repo")
                .as_path()
        );
        let ts = mirror.last_synced_at_ms().expect("timestamp populated");
        assert!(
            ts >= before && ts <= after,
            "timestamp {ts} not in [{before}, {after}]"
        );
    }

    #[test]
    fn sync_mirror_rejects_non_repository_paths_permanently() {
        let mirror_root = tempdir().expect("mirror root");
        let non_repo = tempdir().expect("plain dir");
        let mut manager = LocalMirrorManager::new(mirror_root.path()).expect("manager");

        let err = manager
            .sync_mirror(&RepoLocator::local_path(non_repo.path()))
            .expect_err("non-repository paths must fail");

        assert!(!err.is_retryable());
        assert!(
            !err.message()
                .contains(non_repo.path().to_string_lossy().as_ref())
        );
    }

    #[test]
    fn sync_mirror_classifies_pack_lock_contention_as_retryable() {
        let repo_dir = tempdir().expect("repo tempdir");
        init_repo(repo_dir.path());
        let lock_path = repo_dir.path().join(".git/objects/pack/mirror-test.lock");
        fs::write(&lock_path, b"lock").expect("write pack lock");
        let mirror_root = tempdir().expect("mirror root");
        let mut manager = LocalMirrorManager::new(mirror_root.path()).expect("manager");

        let err = manager
            .sync_mirror(&RepoLocator::local_path(repo_dir.path()))
            .expect_err("pack lock must block sync");

        assert!(err.is_retryable());
        assert!(err.message().contains("concurrent git maintenance"));
    }

    #[test]
    fn sync_mirror_succeeds_when_maintenance_needed_without_lock() {
        // Create a repo with at least one pack file so that preflight inspects
        // pack-level artifacts, then remove the commit-graph to trigger
        // `NeedsMaintenance { lock_present: false }`. The mirror manager
        // accepts repos that lack performance indexes (commit-graph, MIDX)
        // because they only affect traversal speed, not correctness.
        let repo_dir = tempdir().expect("repo tempdir");
        init_repo(repo_dir.path());

        // Create a commit so `git gc` has objects to pack.
        let sentinel = repo_dir.path().join("sentinel.txt");
        fs::write(&sentinel, b"data").expect("write sentinel");
        run_git_in(repo_dir.path(), &["add", "sentinel.txt"]);
        run_git_in(
            repo_dir.path(),
            &["-c", "gc.auto=0", "commit", "-m", "seed"],
        );
        run_git_in(repo_dir.path(), &["-c", "gc.auto=0", "repack", "-a", "-d"]);

        // Remove the commit-graph (if created) so preflight reports
        // `missing_commit_graph = true`.
        let commit_graph = repo_dir.path().join(".git/objects/info/commit-graph");
        let _ = fs::remove_file(&commit_graph);

        // Also remove the multi-pack-index to guarantee at least one
        // `missing_*` flag is set.
        let midx = repo_dir.path().join(".git/objects/pack/multi-pack-index");
        let _ = fs::remove_file(&midx);

        let mirror_root = tempdir().expect("mirror root");
        let mut manager = LocalMirrorManager::new(mirror_root.path()).expect("manager");

        let before = crate::epoch_millis_now();
        let mirror = manager
            .sync_mirror(&RepoLocator::local_path(repo_dir.path()))
            .expect("maintenance without locks must not block sync");
        let after = crate::epoch_millis_now();

        assert_eq!(
            mirror.path(),
            fs::canonicalize(repo_dir.path())
                .expect("canonical repo")
                .as_path()
        );
        let ts = mirror.last_synced_at_ms().expect("timestamp populated");
        assert!(
            ts >= before && ts <= after,
            "timestamp {ts} not in [{before}, {after}]"
        );
    }

    #[test]
    fn authoritative_cache_path_uses_canonical_repo_identity() {
        let repo_dir = tempdir().expect("repo tempdir");
        init_repo(repo_dir.path());
        let mirror_root = tempdir().expect("mirror root");
        let manager = LocalMirrorManager::new(mirror_root.path()).expect("manager");

        let cache_a = manager
            .authoritative_cache_path(&RepoLocator::local_path(repo_dir.path()))
            .expect("cache path");
        let cache_b = manager
            .authoritative_cache_path(&RepoLocator::local_path(repo_dir.path().join(".")))
            .expect("cache path for equivalent spelling");

        assert_eq!(cache_a, cache_b);
        assert!(cache_a.starts_with(manager.mirror_root()));
        assert!(
            !cache_a
                .to_string_lossy()
                .contains(repo_dir.path().to_string_lossy().as_ref())
        );
        assert_eq!(
            cache_a.extension().and_then(|ext| ext.to_str()),
            Some("git")
        );
    }

    #[test]
    fn constructor_removes_stale_manager_control_files() {
        let mirror_root = tempdir().expect("mirror root");
        let layout_dir = mirror_root.path().join("local/abcd");
        fs::create_dir_all(&layout_dir).expect("create layout dir");
        let stale_lock = layout_dir.join("0123.git.lock");
        let stale_init = layout_dir.join("0123.git.initializing");
        let dead = ControlFileMetadata {
            pid: u32::MAX,
            created_at_ms: 1,
        };
        fs::write(&stale_lock, dead.encode()).expect("write stale lock");
        fs::write(&stale_init, dead.encode()).expect("write stale init");

        let manager = LocalMirrorManager::new(mirror_root.path()).expect("manager");

        assert!(manager.mirror_root().exists());
        assert!(!stale_lock.exists());
        assert!(!stale_init.exists());
    }

    #[test]
    fn constructor_keeps_live_manager_control_files() {
        let mirror_root = tempdir().expect("mirror root");
        let layout_dir = mirror_root.path().join("local/abcd");
        fs::create_dir_all(&layout_dir).expect("create layout dir");
        let live_lock = layout_dir.join("live.git.lock");
        let live = ControlFileMetadata {
            pid: std::process::id(),
            created_at_ms: crate::epoch_millis_now(),
        };
        fs::write(&live_lock, live.encode()).expect("write live lock");

        let _manager = LocalMirrorManager::with_settings(
            mirror_root.path().to_path_buf(),
            PreflightLimits::default(),
            DEFAULT_STALE_CONTROL_AGE,
        )
        .expect("manager");

        assert!(live_lock.exists());
    }

    #[test]
    fn debug_redacts_manager_root_path() {
        let mirror_root = tempdir().expect("mirror root");
        let manager = LocalMirrorManager::new(mirror_root.path()).expect("manager");

        let rendered = format!("{manager:?}");
        assert!(rendered.contains("LocalMirrorManager"));
        assert!(!rendered.contains(mirror_root.path().to_string_lossy().as_ref()));
    }

    #[test]
    fn constructor_removes_unparseable_control_files() {
        let mirror_root = tempdir().expect("mirror root");
        let layout_dir = mirror_root.path().join("local/abcd");
        fs::create_dir_all(&layout_dir).expect("create layout dir");
        let garbage = layout_dir.join("bad.git.lock");
        fs::write(&garbage, b"not-a-control-file").expect("write garbage");
        let _manager = LocalMirrorManager::new(mirror_root.path()).expect("manager");
        assert!(!garbage.exists());
    }

    // --- ControlFileMetadata::decode unit tests ---

    #[test]
    fn decode_roundtrips_valid_metadata() {
        let original = ControlFileMetadata {
            pid: 42,
            created_at_ms: 1_700_000_000_000,
        };
        let decoded =
            ControlFileMetadata::decode(original.encode().as_bytes()).expect("valid roundtrip");
        assert_eq!(decoded, original);
    }

    #[test]
    fn decode_rejects_empty_bytes() {
        assert!(ControlFileMetadata::decode(b"").is_none());
    }

    #[test]
    fn decode_rejects_non_utf8() {
        assert!(ControlFileMetadata::decode(&[0xFF, 0xFE, 0xFD]).is_none());
    }

    #[test]
    fn decode_rejects_missing_colon() {
        assert!(ControlFileMetadata::decode(b"12345").is_none());
    }

    #[test]
    fn decode_rejects_non_numeric_pid() {
        assert!(ControlFileMetadata::decode(b"abc:123").is_none());
    }

    #[test]
    fn decode_rejects_non_numeric_timestamp() {
        assert!(ControlFileMetadata::decode(b"123:xyz").is_none());
    }

    #[test]
    fn decode_rejects_zero_pid() {
        assert!(ControlFileMetadata::decode(b"0:123").is_none());
    }

    #[test]
    fn decode_handles_surrounding_whitespace() {
        let decoded =
            ControlFileMetadata::decode(b"  42:100  \n").expect("trim handles whitespace");
        assert_eq!(decoded.pid, 42);
        assert_eq!(decoded.created_at_ms, 100);
    }

    #[test]
    fn decode_rejects_multiple_colons() {
        // split_once(':') on "1:2:3" yields ("1", "2:3"); "2:3" fails u64 parse.
        assert!(ControlFileMetadata::decode(b"1:2:3").is_none());
    }
}

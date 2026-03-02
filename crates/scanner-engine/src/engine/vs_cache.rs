//! On-disk cache for serialized Vectorscan databases.
//!
//! Reduces repeated startup compilation by caching serialized `hs_database_t`
//! to disk, keyed by a deterministic BLAKE3 hash of compile inputs.
//!
//! # File format
//!
//! ```text
//! | MAGIC (8B): b"VSDBCACH"              |
//! | PAYLOAD_LEN (8B, LE u64)             |
//! | KEY_HASH (32B): blake3 of cache key  |
//! | PAYLOAD (PAYLOAD_LEN bytes)          |  -- hs_serialize_database output
//! | MAC_TAG (16B): AEGIS-128L MAC        |  -- over header || payload
//! ```
//!
//! # Integrity
//!
//! A 16-byte AEGIS-128L MAC covers the header and payload. The MAC key is
//! derived from the cache key hash: `blake3(b"vsdb-mac-key" || key_hash)[..16]`.
//! On load, any mismatch (magic, payload length, key hash, or MAC) causes the
//! corrupt file to be deleted and a cache miss returned.
//!
//! # Cache key
//!
//! The key is a BLAKE3 hash over a domain separation tag plus all compile
//! inputs: kind, mode, platform, Vectorscan version, patterns, flags, and ids.
//! A domain tag (`DOMAIN_TAG`) encodes structural assumptions about the file
//! format and MAC scheme; changing it automatically invalidates all old caches.
//!
//! # Environment controls
//!
//! - `SCANNER_VS_DB_CACHE=0|false|off|no` disables caching.
//! - `SCANNER_VS_DB_CACHE_DIR=/path` overrides the cache directory.
//! - Default directory: `$HOME/.cache/scanner-rs/vsdb`, fallback `$TMPDIR/scanner-rs-vsdb`.

use libc::{c_char, c_int, c_uint};
use std::ffi::CString;
use std::path::PathBuf;
use std::ptr;

use vectorscan_rs_sys as vs;

/// Magic bytes at the start of every cache file.
const MAGIC: &[u8; 8] = b"VSDBCACH";

/// Header size: 8 (magic) + 8 (payload_len) + 32 (key_hash).
const HEADER_LEN: usize = 8 + 8 + 32;

/// AEGIS-128L MAC tag size.
const MAC_LEN: usize = 16;

/// Domain separation tag embedded in the cache key hash. Changing this string
/// invalidates all previously cached files without requiring a manual version
/// bump.
const DOMAIN_TAG: &[u8] = b"scanner-rs-vsdb-v2:blake3+aegis128l-mac";

/// Inputs for computing a deterministic cache key.
pub(super) struct CacheKeyInput<'a> {
    /// DB kind tag, e.g. `b"prefilter"`, `b"stream"`.
    pub kind: &'a [u8],
    /// Vectorscan compile mode (`HS_MODE_BLOCK` or `HS_MODE_STREAM`).
    pub mode: c_uint,
    /// Target platform fingerprint.
    pub platform: &'a vs::hs_platform_info_t,
    /// Compiled pattern expressions.
    pub patterns: &'a [CString],
    /// Per-pattern compile flags. `None` when the flags pointer is null.
    pub flags: Option<&'a [c_uint]>,
    /// Per-pattern expression IDs.
    pub ids: &'a [c_uint],
}

/// On-disk cache for serialized Vectorscan databases.
///
/// A `None` `dir` means the cache is disabled (either explicitly via env var
/// or implicitly under `cfg!(test)`). All methods degrade to no-ops: `try_load`
/// returns `None`, `try_store` silently does nothing.
///
/// # Thread safety
///
/// Each `VsDbCache` is used within a single thread during engine construction.
/// Concurrent processes writing the same key are safe because `try_store` uses
/// tmp-file + rename, so readers never observe partial writes.
pub(super) struct VsDbCache {
    /// Cache directory, or `None` when caching is disabled.
    dir: Option<PathBuf>,
}

impl VsDbCache {
    /// Creates a new cache handle by reading environment variables once.
    ///
    /// Returns a disabled cache under `cfg!(test)` unless
    /// `SCANNER_VS_DB_CACHE_TEST=1` is set.
    pub fn new() -> Self {
        if !Self::enabled() {
            return Self { dir: None };
        }
        Self {
            dir: Self::resolve_dir(),
        }
    }

    /// Computes a deterministic BLAKE3 hex cache key from compile inputs.
    ///
    /// The key is a 64-char hex string. Identical inputs always produce the
    /// same key; any change in kind, mode, platform, patterns, flags, or ids
    /// yields a different key. Works even when the cache is disabled (the key
    /// is cheap to compute and callers may log it).
    pub fn cache_key(&self, input: &CacheKeyInput<'_>) -> String {
        let mut hasher = blake3::Hasher::new();
        hash_len_prefixed(&mut hasher, DOMAIN_TAG);
        hash_len_prefixed(&mut hasher, input.kind);
        hash_u32(&mut hasher, input.mode);
        hash_u32(&mut hasher, input.platform.tune);
        hash_u64(&mut hasher, input.platform.cpu_features);
        hash_u64(&mut hasher, input.platform.reserved1);
        hash_u64(&mut hasher, input.platform.reserved2);
        hash_len_prefixed(&mut hasher, vs::HS_VERSION_STRING);
        hash_u64(&mut hasher, input.patterns.len() as u64);
        for pat in input.patterns {
            hash_len_prefixed(&mut hasher, pat.as_bytes_with_nul());
        }
        match input.flags {
            Some(flags) => {
                hash_u64(&mut hasher, flags.len() as u64);
                for &f in flags {
                    hash_u32(&mut hasher, f);
                }
            }
            None => {
                // Distinguish "no flags" from "zero flags".
                hash_u64(&mut hasher, u64::MAX);
            }
        }
        hash_u64(&mut hasher, input.ids.len() as u64);
        for &id in input.ids {
            hash_u32(&mut hasher, id);
        }
        hasher.finalize().to_hex().to_string()
    }

    /// Attempts to load a cached, integrity-verified database by key.
    ///
    /// Returns `None` on any failure (disabled, missing, corrupt, MAC mismatch).
    /// Corrupt files are deleted as a side effect.
    ///
    /// # Safety (caller obligation)
    ///
    /// The returned `*mut hs_database_t` is heap-allocated by Vectorscan and
    /// must be freed with `hs_free_database` when no longer needed. The caller
    /// owns the pointer.
    pub fn try_load(&self, key: &str) -> Option<*mut vs::hs_database_t> {
        let dir = self.dir.as_ref()?;
        let path = dir.join(format!("{key}.hsdb"));
        let bytes = std::fs::read(&path).ok()?;

        // Minimum size: header + mac (payload may be zero but hs_deserialize
        // rejects that, so we still check).
        if bytes.len() < HEADER_LEN + MAC_LEN {
            let _ = std::fs::remove_file(&path);
            return None;
        }

        // Verify magic.
        if &bytes[..8] != MAGIC.as_slice() {
            let _ = std::fs::remove_file(&path);
            return None;
        }

        // Read and validate payload length.
        let payload_len = u64::from_le_bytes(bytes[8..16].try_into().unwrap()) as usize;
        let expected_total = HEADER_LEN + payload_len + MAC_LEN;
        if bytes.len() != expected_total {
            let _ = std::fs::remove_file(&path);
            return None;
        }

        // Verify key hash.
        let stored_key_hash: [u8; 32] = bytes[16..48].try_into().unwrap();
        let expected_key_hash = *blake3::hash(key.as_bytes()).as_bytes();
        if stored_key_hash != expected_key_hash {
            let _ = std::fs::remove_file(&path);
            return None;
        }

        // Verify MAC over (header || payload).
        let data_end = HEADER_LEN + payload_len;
        let stored_mac: [u8; 16] = bytes[data_end..data_end + MAC_LEN].try_into().unwrap();
        let computed_mac = compute_mac(&stored_key_hash, &bytes[..data_end]);
        if computed_mac != stored_mac {
            let _ = std::fs::remove_file(&path);
            return None;
        }

        // Deserialize the Vectorscan database.
        let payload = &bytes[HEADER_LEN..data_end];
        let mut db: *mut vs::hs_database_t = ptr::null_mut();
        // SAFETY: `payload` is a valid byte slice from a MAC-verified file, and
        // `db` is a properly aligned out-pointer. `hs_deserialize_database` only
        // reads `payload.len()` bytes and writes a heap-allocated DB to `db`.
        let rc = unsafe {
            vs::hs_deserialize_database(
                payload.as_ptr().cast::<c_char>(),
                payload.len(),
                &mut db as *mut *mut vs::hs_database_t,
            )
        };
        if rc == vs::HS_SUCCESS as c_int && !db.is_null() {
            Some(db)
        } else {
            let _ = std::fs::remove_file(&path);
            None
        }
    }

    /// Serializes and stores a compiled database under `key` (best-effort).
    ///
    /// Uses write-to-tmp + rename for atomic file creation. Any failure is
    /// silently ignored — correctness never depends on cache persistence.
    pub fn try_store(&self, key: &str, db: *const vs::hs_database_t) {
        let Some(dir) = self.dir.as_ref() else {
            return;
        };
        if std::fs::create_dir_all(dir).is_err() {
            return;
        }

        let out_path = dir.join(format!("{key}.hsdb"));
        if out_path.exists() {
            return;
        }

        // Serialize the database.
        let mut bytes_ptr: *mut c_char = ptr::null_mut();
        let mut bytes_len: usize = 0;
        // SAFETY: `db` is a valid, compiled Vectorscan database pointer (caller
        // obligation). `bytes_ptr` and `bytes_len` are valid out-pointers.
        // `hs_serialize_database` allocates the output buffer internally.
        let rc = unsafe {
            vs::hs_serialize_database(
                db,
                &mut bytes_ptr as *mut *mut c_char,
                &mut bytes_len as *mut usize,
            )
        };
        if rc != vs::HS_SUCCESS as c_int || bytes_ptr.is_null() || bytes_len == 0 {
            if !bytes_ptr.is_null() {
                // SAFETY: `bytes_ptr` was allocated by Vectorscan's allocator
                // (libc malloc) and the null check above ensures it is valid.
                unsafe { libc::free(bytes_ptr.cast()) };
            }
            return;
        }

        // SAFETY: `hs_serialize_database` succeeded (rc == HS_SUCCESS), so
        // `bytes_ptr` is non-null and points to `bytes_len` contiguous bytes
        // allocated by libc malloc. The slice borrows the buffer until `free`.
        let payload = unsafe { std::slice::from_raw_parts(bytes_ptr.cast::<u8>(), bytes_len) };

        // Build the file contents: header || payload || mac.
        let key_hash = *blake3::hash(key.as_bytes()).as_bytes();

        let total_len = HEADER_LEN + bytes_len + MAC_LEN;
        let mut buf = Vec::with_capacity(total_len);
        buf.extend_from_slice(MAGIC);
        buf.extend_from_slice(&(bytes_len as u64).to_le_bytes());
        buf.extend_from_slice(&key_hash);
        buf.extend_from_slice(payload);

        // SAFETY: `bytes_ptr` was allocated by Vectorscan (libc malloc), is
        // non-null (checked after hs_serialize_database), and the `payload`
        // slice derived from it is no longer referenced after this point.
        unsafe { libc::free(bytes_ptr.cast()) };

        // Compute MAC over header + payload (everything before the MAC slot).
        let mac = compute_mac(&key_hash, &buf);
        buf.extend_from_slice(&mac);

        // Atomic write via tmp + rename.
        let tmp_path = dir.join(format!("{key}.{}.tmp", std::process::id()));
        if std::fs::write(&tmp_path, &buf).is_err() {
            let _ = std::fs::remove_file(&tmp_path);
            return;
        }
        let _ = std::fs::rename(&tmp_path, &out_path);
        let _ = std::fs::remove_file(&tmp_path);
    }

    /// Returns `true` if the cache is enabled.
    ///
    /// Disabled under `cfg!(test)` unless `SCANNER_VS_DB_CACHE_TEST=1` is set.
    /// Otherwise reads `SCANNER_VS_DB_CACHE`; any of `0|false|off|no` disables.
    fn enabled() -> bool {
        if cfg!(test) {
            return std::env::var("SCANNER_VS_DB_CACHE_TEST").is_ok_and(|v| v.trim() == "1");
        }
        match std::env::var("SCANNER_VS_DB_CACHE") {
            Ok(v) => {
                let v = v.trim().to_ascii_lowercase();
                !(v == "0" || v == "false" || v == "off" || v == "no")
            }
            Err(_) => true,
        }
    }

    /// Resolves the cache directory with a 3-tier fallback:
    /// 1. `SCANNER_VS_DB_CACHE_DIR` env var (explicit override)
    /// 2. `$HOME/.cache/scanner-rs/vsdb` (XDG-style default)
    /// 3. `$TMPDIR/scanner-rs-vsdb` (last resort)
    fn resolve_dir() -> Option<PathBuf> {
        if let Some(dir) = std::env::var_os("SCANNER_VS_DB_CACHE_DIR") {
            return Some(PathBuf::from(dir));
        }
        if let Some(home) = std::env::var_os("HOME") {
            return Some(
                PathBuf::from(home)
                    .join(".cache")
                    .join("scanner-rs")
                    .join("vsdb"),
            );
        }
        Some(std::env::temp_dir().join("scanner-rs-vsdb"))
    }
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Computes an AEGIS-128L MAC over `data` using a key derived from `key_hash`.
///
/// Key derivation: `blake3(b"vsdb-mac-key" || key_hash)[..16]`. The domain
/// prefix prevents the MAC key from colliding with the cache key itself.
fn compute_mac(key_hash: &[u8; 32], data: &[u8]) -> [u8; 16] {
    use aegis::aegis128l::Aegis128LMac;

    // Derive a 16-byte MAC key: blake3(b"vsdb-mac-key" || key_hash)[..16].
    let mut kdf = blake3::Hasher::new();
    kdf.update(b"vsdb-mac-key");
    kdf.update(key_hash);
    let derived = kdf.finalize();
    let mac_key: [u8; 16] = derived.as_bytes()[..16].try_into().unwrap();

    let mut mac = Aegis128LMac::<16>::new(&mac_key);
    mac.update(data);
    mac.finalize()
}

/// Feeds `bytes` into `hasher` with a length prefix to prevent concatenation
/// ambiguity (e.g. `["ab", "c"]` vs `["a", "bc"]` hash differently).
#[inline]
fn hash_len_prefixed(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

/// Feeds a fixed-width `u32` into the hasher (no length prefix needed).
#[inline]
fn hash_u32(hasher: &mut blake3::Hasher, v: u32) {
    hasher.update(&v.to_le_bytes());
}

/// Feeds a fixed-width `u64` into the hasher (no length prefix needed).
#[inline]
fn hash_u64(hasher: &mut blake3::Hasher, v: u64) {
    hasher.update(&v.to_le_bytes());
}

// ---------------------------------------------------------------------------
// Fuzz entry point
// ---------------------------------------------------------------------------

/// Fuzz entry point: attempts to load a cache file from arbitrary bytes.
///
/// Writes `data` as a cache file under `dir` with a fixed key, then calls
/// `try_load`. Returns `true` if a database was successfully deserialized
/// (caller is responsible for nothing — the database is freed internally).
#[cfg(feature = "tiger-harness")]
pub fn fuzz_try_load(dir: &std::path::Path, data: &[u8]) -> bool {
    let key = "fuzz-key";
    let path = dir.join(format!("{key}.hsdb"));
    if std::fs::write(&path, data).is_err() {
        return false;
    }
    let cache = VsDbCache {
        dir: Some(dir.to_path_buf()),
    };
    match cache.try_load(key) {
        Some(db) => {
            // SAFETY: `db` was returned by `hs_deserialize_database` inside
            // `try_load` and is non-null; freed exactly once here.
            unsafe { vs::hs_free_database(db) };
            true
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::mem::MaybeUninit;

    fn test_platform() -> vs::hs_platform_info_t {
        let mut platform = MaybeUninit::<vs::hs_platform_info_t>::zeroed();
        // SAFETY: `platform` is a zeroed, properly aligned `MaybeUninit`;
        // `hs_populate_platform` writes valid data into the pointer.
        // `assume_init` is sound because the struct was zero-initialized
        // and `hs_populate_platform` fills all fields.
        unsafe {
            let _ = vs::hs_populate_platform(platform.as_mut_ptr());
            platform.assume_init()
        }
    }

    fn test_cache_input<'a>(
        kind: &'a [u8],
        patterns: &'a [CString],
        flags: &'a [c_uint],
        ids: &'a [c_uint],
        platform: &'a vs::hs_platform_info_t,
    ) -> CacheKeyInput<'a> {
        CacheKeyInput {
            kind,
            mode: vs::HS_MODE_BLOCK as c_uint,
            platform,
            patterns,
            flags: Some(flags),
            ids,
        }
    }

    #[test]
    fn cache_key_is_deterministic() {
        let platform = test_platform();
        let pats = [CString::new("abc").unwrap()];
        let flags = [vs::HS_FLAG_PREFILTER as c_uint];
        let ids = [0u32];
        let cache = VsDbCache { dir: None };

        let input = test_cache_input(b"test", &pats, &flags, &ids, &platform);
        let k1 = cache.cache_key(&input);
        let k2 = cache.cache_key(&input);
        assert_eq!(k1, k2);
    }

    #[test]
    fn cache_key_changes_on_kind() {
        let platform = test_platform();
        let pats = [CString::new("abc").unwrap()];
        let flags = [vs::HS_FLAG_PREFILTER as c_uint];
        let ids = [0u32];
        let cache = VsDbCache { dir: None };

        let i1 = test_cache_input(b"prefilter", &pats, &flags, &ids, &platform);
        let i2 = test_cache_input(b"stream", &pats, &flags, &ids, &platform);
        assert_ne!(cache.cache_key(&i1), cache.cache_key(&i2));
    }

    #[test]
    fn cache_key_changes_on_pattern() {
        let platform = test_platform();
        let pats1 = [CString::new("abc").unwrap()];
        let pats2 = [CString::new("xyz").unwrap()];
        let flags = [vs::HS_FLAG_PREFILTER as c_uint];
        let ids = [0u32];
        let cache = VsDbCache { dir: None };

        let i1 = test_cache_input(b"test", &pats1, &flags, &ids, &platform);
        let i2 = test_cache_input(b"test", &pats2, &flags, &ids, &platform);
        assert_ne!(cache.cache_key(&i1), cache.cache_key(&i2));
    }

    #[test]
    fn cache_key_changes_on_flags() {
        let platform = test_platform();
        let pats = [CString::new("abc").unwrap()];
        let flags1 = [vs::HS_FLAG_PREFILTER as c_uint];
        let flags2 = [vs::HS_FLAG_SINGLEMATCH as c_uint];
        let ids = [0u32];
        let cache = VsDbCache { dir: None };

        let i1 = test_cache_input(b"test", &pats, &flags1, &ids, &platform);
        let i2 = test_cache_input(b"test", &pats, &flags2, &ids, &platform);
        assert_ne!(cache.cache_key(&i1), cache.cache_key(&i2));
    }

    #[test]
    fn cache_key_none_flags_differs_from_empty() {
        let platform = test_platform();
        let pats = [CString::new("abc").unwrap()];
        let ids = [0u32];
        let cache = VsDbCache { dir: None };

        let i1 = CacheKeyInput {
            kind: b"test",
            mode: vs::HS_MODE_BLOCK as c_uint,
            platform: &platform,
            patterns: &pats,
            flags: None,
            ids: &ids,
        };
        let i2 = CacheKeyInput {
            kind: b"test",
            mode: vs::HS_MODE_BLOCK as c_uint,
            platform: &platform,
            patterns: &pats,
            flags: Some(&[]),
            ids: &ids,
        };
        assert_ne!(cache.cache_key(&i1), cache.cache_key(&i2));
    }

    /// Helper: compile a trivial block-mode DB for round-trip tests.
    fn compile_trivial_db() -> *mut vs::hs_database_t {
        let pat = CString::new("test").unwrap();
        let expr_ptrs = [pat.as_ptr()];
        let flags = [vs::HS_FLAG_PREFILTER as c_uint];
        let ids = [0u32];
        let platform = test_platform();
        let mut db: *mut vs::hs_database_t = ptr::null_mut();
        let mut err: *mut vs::hs_compile_error_t = ptr::null_mut();
        // SAFETY: All pointer arrays (`expr_ptrs`, `flags`, `ids`) have exactly
        // `1` element matching the `elements` count. `platform`, `db`, and `err`
        // are valid, properly aligned out-pointers.
        let rc = unsafe {
            vs::hs_compile_multi(
                expr_ptrs.as_ptr(),
                flags.as_ptr(),
                ids.as_ptr(),
                1,
                vs::HS_MODE_BLOCK as c_uint,
                &platform as *const vs::hs_platform_info_t,
                &mut db as *mut *mut vs::hs_database_t,
                &mut err as *mut *mut vs::hs_compile_error_t,
            )
        };
        assert_eq!(rc, vs::HS_SUCCESS as c_int);
        assert!(!db.is_null());
        db
    }

    #[test]
    fn round_trip_store_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let cache = VsDbCache {
            dir: Some(dir.path().to_path_buf()),
        };
        let db = compile_trivial_db();
        let key = "test-round-trip-key";

        cache.try_store(key, db as *const vs::hs_database_t);
        let loaded = cache.try_load(key);
        assert!(loaded.is_some(), "expected cache hit after store");

        // Clean up both DBs.
        // SAFETY: `db` was allocated by `hs_compile_multi` and `loaded_db` by
        // `hs_deserialize_database`; both are non-null and freed exactly once.
        unsafe {
            vs::hs_free_database(db);
            if let Some(loaded_db) = loaded {
                vs::hs_free_database(loaded_db);
            }
        }
    }

    #[test]
    fn corrupted_mac_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let cache = VsDbCache {
            dir: Some(dir.path().to_path_buf()),
        };
        let db = compile_trivial_db();
        let key = "test-corrupt-mac";

        cache.try_store(key, db as *const vs::hs_database_t);
        // SAFETY: `db` was allocated by `hs_compile_multi` in `compile_trivial_db`
        // and is non-null; freed exactly once here.
        unsafe { vs::hs_free_database(db) };

        // Corrupt the last byte (MAC tag).
        let path = dir.path().join(format!("{key}.hsdb"));
        let mut bytes = std::fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        std::fs::write(&path, &bytes).unwrap();

        assert!(cache.try_load(key).is_none(), "corrupt MAC should miss");
        assert!(!path.exists(), "corrupt file should be deleted");
    }

    #[test]
    fn truncated_file_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let cache = VsDbCache {
            dir: Some(dir.path().to_path_buf()),
        };
        let db = compile_trivial_db();
        let key = "test-truncated";

        cache.try_store(key, db as *const vs::hs_database_t);
        // SAFETY: `db` was allocated by `hs_compile_multi` in `compile_trivial_db`
        // and is non-null; freed exactly once here.
        unsafe { vs::hs_free_database(db) };

        // Truncate the file.
        let path = dir.path().join(format!("{key}.hsdb"));
        let bytes = std::fs::read(&path).unwrap();
        std::fs::write(&path, &bytes[..HEADER_LEN]).unwrap();

        assert!(cache.try_load(key).is_none(), "truncated file should miss");
        assert!(!path.exists(), "truncated file should be deleted");
    }

    #[test]
    fn wrong_key_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let cache = VsDbCache {
            dir: Some(dir.path().to_path_buf()),
        };
        let db = compile_trivial_db();
        let key = "test-right-key";

        cache.try_store(key, db as *const vs::hs_database_t);
        // SAFETY: `db` was allocated by `hs_compile_multi` in `compile_trivial_db`
        // and is non-null; freed exactly once here.
        unsafe { vs::hs_free_database(db) };

        // Rename the file to a different key name.
        let src = dir.path().join(format!("{key}.hsdb"));
        let dst = dir.path().join("wrong-key.hsdb");
        std::fs::rename(&src, &dst).unwrap();

        assert!(
            cache.try_load("wrong-key").is_none(),
            "wrong key should miss"
        );
    }

    #[test]
    fn disabled_cache_always_misses() {
        let cache = VsDbCache { dir: None };
        assert!(cache.try_load("anything").is_none());
    }

    // -----------------------------------------------------------------------
    // Gap-fill tests
    // -----------------------------------------------------------------------

    #[test]
    fn cache_key_changes_on_mode() {
        let platform = test_platform();
        let pats = [CString::new("abc").unwrap()];
        let flags = [vs::HS_FLAG_PREFILTER as c_uint];
        let ids = [0u32];
        let cache = VsDbCache { dir: None };

        let i1 = CacheKeyInput {
            kind: b"test",
            mode: vs::HS_MODE_BLOCK as c_uint,
            platform: &platform,
            patterns: &pats,
            flags: Some(&flags),
            ids: &ids,
        };
        let i2 = CacheKeyInput {
            kind: b"test",
            mode: vs::HS_MODE_STREAM as c_uint,
            platform: &platform,
            patterns: &pats,
            flags: Some(&flags),
            ids: &ids,
        };
        assert_ne!(cache.cache_key(&i1), cache.cache_key(&i2));
    }

    #[test]
    fn cache_key_changes_on_platform() {
        let mut p1 = test_platform();
        let mut p2 = test_platform();
        p1.tune = 0;
        p2.tune = 1;
        let pats = [CString::new("abc").unwrap()];
        let flags = [vs::HS_FLAG_PREFILTER as c_uint];
        let ids = [0u32];
        let cache = VsDbCache { dir: None };

        let i1 = test_cache_input(b"test", &pats, &flags, &ids, &p1);
        let i2 = test_cache_input(b"test", &pats, &flags, &ids, &p2);
        assert_ne!(cache.cache_key(&i1), cache.cache_key(&i2));

        let mut p3 = test_platform();
        let mut p4 = test_platform();
        p3.cpu_features = 0;
        p4.cpu_features = 1;
        let i3 = test_cache_input(b"test", &pats, &flags, &ids, &p3);
        let i4 = test_cache_input(b"test", &pats, &flags, &ids, &p4);
        assert_ne!(cache.cache_key(&i3), cache.cache_key(&i4));
    }

    #[test]
    fn cache_key_changes_on_ids() {
        let platform = test_platform();
        let pats = [CString::new("abc").unwrap()];
        let flags = [vs::HS_FLAG_PREFILTER as c_uint];
        let cache = VsDbCache { dir: None };

        let ids1 = [0u32];
        let ids2 = [1u32];
        let i1 = test_cache_input(b"test", &pats, &flags, &ids1, &platform);
        let i2 = test_cache_input(b"test", &pats, &flags, &ids2, &platform);
        assert_ne!(cache.cache_key(&i1), cache.cache_key(&i2));

        let ids3 = [0u32, 1];
        let i3 = test_cache_input(b"test", &pats, &flags, &ids3, &platform);
        assert_ne!(cache.cache_key(&i1), cache.cache_key(&i3));
    }

    #[test]
    fn cache_key_empty_patterns() {
        let platform = test_platform();
        let pats_empty: [CString; 0] = [];
        let pats_one = [CString::new("x").unwrap()];
        let flags: [c_uint; 0] = [];
        let flags_one = [vs::HS_FLAG_PREFILTER as c_uint];
        let ids: [u32; 0] = [];
        let ids_one = [0u32];
        let cache = VsDbCache { dir: None };

        let i1 = test_cache_input(b"test", &pats_empty, &flags, &ids, &platform);
        let i2 = test_cache_input(b"test", &pats_one, &flags_one, &ids_one, &platform);
        assert_ne!(cache.cache_key(&i1), cache.cache_key(&i2));

        let i3 = test_cache_input(b"test", &pats_empty, &flags, &ids, &platform);
        assert_eq!(cache.cache_key(&i1), cache.cache_key(&i3));
    }

    #[test]
    fn bad_magic_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let cache = VsDbCache {
            dir: Some(dir.path().to_path_buf()),
        };
        let db = compile_trivial_db();
        let key = "test-bad-magic";

        cache.try_store(key, db as *const vs::hs_database_t);
        // SAFETY: `db` was allocated by `hs_compile_multi` in `compile_trivial_db`
        // and is non-null; freed exactly once here.
        unsafe { vs::hs_free_database(db) };

        let path = dir.path().join(format!("{key}.hsdb"));
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[..8].copy_from_slice(b"BADMAGIC");
        std::fs::write(&path, &bytes).unwrap();

        assert!(cache.try_load(key).is_none(), "bad magic should miss");
        assert!(!path.exists(), "file with bad magic should be deleted");
    }

    #[test]
    fn bad_payload_len_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let cache = VsDbCache {
            dir: Some(dir.path().to_path_buf()),
        };
        let db = compile_trivial_db();
        let key = "test-bad-payload-len";

        cache.try_store(key, db as *const vs::hs_database_t);
        // SAFETY: `db` was allocated by `hs_compile_multi` in `compile_trivial_db`
        // and is non-null; freed exactly once here.
        unsafe { vs::hs_free_database(db) };

        let path = dir.path().join(format!("{key}.hsdb"));
        let mut bytes = std::fs::read(&path).unwrap();
        let huge_len: u64 = (bytes.len() * 10) as u64;
        bytes[8..16].copy_from_slice(&huge_len.to_le_bytes());
        std::fs::write(&path, &bytes).unwrap();

        assert!(cache.try_load(key).is_none(), "bad payload_len should miss");
        assert!(
            !path.exists(),
            "file with bad payload_len should be deleted"
        );
    }

    #[test]
    fn store_skips_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let cache = VsDbCache {
            dir: Some(dir.path().to_path_buf()),
        };
        let db = compile_trivial_db();
        let key = "test-skip-existing";

        cache.try_store(key, db as *const vs::hs_database_t);
        let path = dir.path().join(format!("{key}.hsdb"));
        let original = std::fs::read(&path).unwrap();

        cache.try_store(key, db as *const vs::hs_database_t);
        let after = std::fs::read(&path).unwrap();
        assert_eq!(original, after, "second store should not modify the file");

        // SAFETY: `db` was allocated by `hs_compile_multi` in `compile_trivial_db`
        // and is non-null; freed exactly once here.
        unsafe { vs::hs_free_database(db) };
    }

    #[test]
    fn corrupted_key_hash_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let cache = VsDbCache {
            dir: Some(dir.path().to_path_buf()),
        };
        let db = compile_trivial_db();
        let key = "test-corrupt-keyhash";

        cache.try_store(key, db as *const vs::hs_database_t);
        // SAFETY: `db` was allocated by `hs_compile_multi` in `compile_trivial_db`
        // and is non-null; freed exactly once here.
        unsafe { vs::hs_free_database(db) };

        let path = dir.path().join(format!("{key}.hsdb"));
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[16] ^= 0xFF;
        bytes[30] ^= 0x0F;
        std::fs::write(&path, &bytes).unwrap();

        assert!(
            cache.try_load(key).is_none(),
            "corrupted key hash should miss"
        );
        assert!(
            !path.exists(),
            "file with corrupted key hash should be deleted"
        );
    }

    #[test]
    fn zero_length_payload_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let key = "test-zero-payload";
        let path = dir.path().join(format!("{key}.hsdb"));

        // Valid header + MAC with zero-length payload (not a valid Vectorscan DB).
        let key_hash = *blake3::hash(key.as_bytes()).as_bytes();
        let mut buf = Vec::new();
        buf.extend_from_slice(MAGIC);
        buf.extend_from_slice(&0u64.to_le_bytes());
        buf.extend_from_slice(&key_hash);
        let mac = compute_mac(&key_hash, &buf);
        buf.extend_from_slice(&mac);

        std::fs::create_dir_all(dir.path()).unwrap();
        std::fs::write(&path, &buf).unwrap();

        let cache = VsDbCache {
            dir: Some(dir.path().to_path_buf()),
        };
        assert!(
            cache.try_load(key).is_none(),
            "zero-length payload should miss"
        );
        assert!(
            !path.exists(),
            "file with zero-length payload should be deleted"
        );
    }
}

// ---------------------------------------------------------------------------
// Property tests (proptest)
// ---------------------------------------------------------------------------

#[cfg(all(test, feature = "stdx-proptest"))]
mod prop_tests {
    use super::*;
    use proptest::prelude::*;
    use std::ffi::CString;
    use std::mem::MaybeUninit;

    fn test_platform() -> vs::hs_platform_info_t {
        let mut platform = MaybeUninit::<vs::hs_platform_info_t>::zeroed();
        // SAFETY: `platform` is a zeroed, properly aligned `MaybeUninit`;
        // `hs_populate_platform` writes valid data into the pointer.
        // `assume_init` is sound because the struct was zero-initialized
        // and `hs_populate_platform` fills all fields.
        unsafe {
            let _ = vs::hs_populate_platform(platform.as_mut_ptr());
            platform.assume_init()
        }
    }

    /// Generates a non-empty `Vec<CString>` of lowercase ASCII patterns with
    /// matching-length flags and ids vecs.
    fn arb_pats_flags_ids() -> impl Strategy<Value = (Vec<CString>, Vec<u32>, Vec<u32>)> {
        (1..8usize).prop_flat_map(|n| {
            (
                prop::collection::vec("[a-z]{1,8}", n)
                    .prop_map(|v| v.into_iter().map(|s| CString::new(s).unwrap()).collect()),
                prop::collection::vec(any::<u32>(), n),
                prop::collection::vec(any::<u32>(), n),
            )
        })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// Same input always produces the same key.
        #[test]
        fn cache_key_deterministic(
            kind in prop::collection::vec(any::<u8>(), 1..32),
            mode in any::<u32>(),
            (pats, flags, ids) in arb_pats_flags_ids(),
        ) {
            let platform = test_platform();
            let input = CacheKeyInput {
                kind: &kind,
                mode,
                platform: &platform,
                patterns: &pats,
                flags: Some(&flags),
                ids: &ids,
            };
            let cache = VsDbCache { dir: None };
            prop_assert_eq!(cache.cache_key(&input), cache.cache_key(&input));
        }

        /// Changing `kind` always changes the key.
        #[test]
        fn cache_key_sensitive_to_kind(
            kind1 in prop::collection::vec(any::<u8>(), 1..32),
            kind2 in prop::collection::vec(any::<u8>(), 1..32),
            mode in any::<u32>(),
            (pats, flags, ids) in arb_pats_flags_ids(),
        ) {
            prop_assume!(kind1 != kind2);
            let platform = test_platform();
            let cache = VsDbCache { dir: None };
            let i1 = CacheKeyInput { kind: &kind1, mode, platform: &platform, patterns: &pats, flags: Some(&flags), ids: &ids };
            let i2 = CacheKeyInput { kind: &kind2, mode, platform: &platform, patterns: &pats, flags: Some(&flags), ids: &ids };
            prop_assert_ne!(cache.cache_key(&i1), cache.cache_key(&i2));
        }

        /// Changing `mode` always changes the key.
        #[test]
        fn cache_key_sensitive_to_mode(
            mode1 in any::<u32>(),
            mode2 in any::<u32>(),
            (pats, flags, ids) in arb_pats_flags_ids(),
        ) {
            prop_assume!(mode1 != mode2);
            let platform = test_platform();
            let cache = VsDbCache { dir: None };
            let i1 = CacheKeyInput { kind: b"test", mode: mode1, platform: &platform, patterns: &pats, flags: Some(&flags), ids: &ids };
            let i2 = CacheKeyInput { kind: b"test", mode: mode2, platform: &platform, patterns: &pats, flags: Some(&flags), ids: &ids };
            prop_assert_ne!(cache.cache_key(&i1), cache.cache_key(&i2));
        }

        /// Length-prefix disambiguation: `["ab", "c"]` differs from `["a", "bc"]`.
        #[test]
        fn cache_key_length_prefix_disambiguation(
            a in "[a-z]{1,4}",
            b in "[a-z]{1,4}",
        ) {
            prop_assume!(a.len() > 1);
            let split = a.len() / 2;
            let pats1 = vec![
                CString::new(&a[..split]).unwrap(),
                CString::new(format!("{}{b}", &a[split..])).unwrap(),
            ];
            let pats2 = vec![
                CString::new(a.as_str()).unwrap(),
                CString::new(b.as_str()).unwrap(),
            ];
            prop_assume!(pats1 != pats2);

            let platform = test_platform();
            let cache = VsDbCache { dir: None };
            let flags = [0u32; 2];
            let ids = [0u32, 1];
            let i1 = CacheKeyInput { kind: b"test", mode: 0, platform: &platform, patterns: &pats1, flags: Some(&flags), ids: &ids };
            let i2 = CacheKeyInput { kind: b"test", mode: 0, platform: &platform, patterns: &pats2, flags: Some(&flags), ids: &ids };
            prop_assert_ne!(cache.cache_key(&i1), cache.cache_key(&i2));
        }

        /// `flags: None` always differs from `flags: Some(&[])`.
        #[test]
        fn cache_key_none_vs_some_flags(
            (pats, _flags, ids) in arb_pats_flags_ids(),
        ) {
            let platform = test_platform();
            let cache = VsDbCache { dir: None };
            let i1 = CacheKeyInput { kind: b"test", mode: 0, platform: &platform, patterns: &pats, flags: None, ids: &ids };
            let i2 = CacheKeyInput { kind: b"test", mode: 0, platform: &platform, patterns: &pats, flags: Some(&[]), ids: &ids };
            prop_assert_ne!(cache.cache_key(&i1), cache.cache_key(&i2));
        }
    }
}

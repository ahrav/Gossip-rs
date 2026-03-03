//! Fuzz `VsDbCache::try_load` with arbitrary file contents.
//!
//! Writes random bytes to a cache file path, then calls `try_load` through
//! the `fuzz_try_load` entry point. Goal: no panics, no UB, no crashes --
//! `None` is the only acceptable outcome for random bytes (the MAC check
//! should reject almost everything before reaching Vectorscan FFI).
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Each iteration gets a fresh temp directory so files don't accumulate.
    let dir = tempfile::tempdir().unwrap();
    let _ = scanner_engine::fuzz_try_load(dir.path(), data);
});

//! Shared git-backed helpers for integration and simulation test targets.

use scanner_git::OidBytes;

pub(crate) use gossip_stdx::git_test_support::{
    decode_hex, git_available, git_stdout as git_output, init_git_repo, run_git,
};

pub(crate) fn oid_from_hex(hex: &str) -> OidBytes {
    OidBytes::from_slice(&decode_hex(hex.trim()))
}

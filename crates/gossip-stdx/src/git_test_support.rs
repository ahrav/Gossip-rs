//! Shared git CLI helpers for test and benchmark fixtures.
//!
//! Available under the `git-test-support` feature (for downstream crates) and
//! under `#[cfg(test)]` (for internal gossip-stdx tests). Provides command
//! wrappers, deterministic repository initialization, and hex decoding used by
//! git-backed test fixtures across the workspace.

use std::path::Path;
use std::process::{Command, Output};

/// Run `git --version` to determine whether the git CLI is available.
#[must_use]
pub fn git_available() -> bool {
    Command::new("git").arg("--version").output().is_ok()
}

/// Run `git` inside `dir`, assert the command succeeds, and return the raw
/// process output.
fn assert_git_output(dir: &Path, args: &[&str]) -> Output {
    let output = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .unwrap_or_else(|e| {
            panic!(
                "failed to spawn git -C {} {}: {e}",
                dir.display(),
                args.join(" "),
            )
        });
    assert!(
        output.status.success(),
        "git command failed: git -C {} {}\nstdout:{}\nstderr:{}",
        dir.display(),
        args.join(" "),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    output
}

/// Run `git` inside `dir` and assert that the command succeeds.
///
/// # Panics
///
/// Panics if the git process cannot be spawned or exits with a non-zero
/// status.
pub fn run_git(dir: &Path, args: &[&str]) {
    assert_git_output(dir, args);
}

/// Run `git` inside `dir`, assert success, and return trimmed UTF-8 stdout.
///
/// # Panics
///
/// Panics if the git process cannot be spawned, exits with a non-zero status,
/// or produces non-UTF-8 stdout.
#[must_use]
pub fn git_stdout(dir: &Path, args: &[&str]) -> String {
    let output = assert_git_output(dir, args);
    String::from_utf8(output.stdout)
        .unwrap_or_else(|e| {
            panic!(
                "git -C {} {} produced non-UTF-8 stdout: {e}",
                dir.display(),
                args.join(" "),
            )
        })
        .trim()
        .to_owned()
}

/// Run `git` inside `dir`, assert success, and return the raw process output.
///
/// # Panics
///
/// Panics if the git process cannot be spawned or exits with a non-zero
/// status.
#[must_use]
pub fn git_output_raw(dir: &Path, args: &[&str]) -> Output {
    assert_git_output(dir, args)
}

/// Initialize a git repository with a deterministic local author identity.
///
/// The initial branch is always `main`, regardless of the host's
/// `init.defaultBranch` configuration.
///
/// # Panics
///
/// Panics if any git command fails.
pub fn init_git_repo(dir: &Path, email: &str, name: &str) {
    run_git(dir, &["init", "-q", "-b", "main"]);
    run_git(dir, &["config", "user.email", email]);
    run_git(dir, &["config", "user.name", name]);
}

/// Initialize a git repository and create one tracked fixture commit.
///
/// The fixture commit adds `fixture.txt` with the contents `fixture`.
///
/// # Panics
///
/// Panics if writing the fixture file or any git command fails.
pub fn init_committed_repo(dir: &Path, email: &str, name: &str) {
    init_git_repo(dir, email, name);
    std::fs::write(dir.join("fixture.txt"), "fixture")
        .unwrap_or_else(|e| panic!("failed to write fixture.txt in {}: {e}", dir.display()));
    run_git(dir, &["add", "."]);
    run_git(dir, &["commit", "-q", "-m", "fixture"]);
}

/// Decode a hexadecimal string into raw bytes.
///
/// Accepts uppercase or lowercase ASCII hex digits.
///
/// # Panics
///
/// Panics if `hex` has odd length or contains a non-hex digit.
#[must_use]
pub fn decode_hex(hex: &str) -> Vec<u8> {
    assert!(
        hex.len().is_multiple_of(2),
        "decode_hex: odd-length input ({len} bytes): {hex:?}",
        len = hex.len()
    );
    let mut out = Vec::with_capacity(hex.len() / 2);
    for pair in hex.as_bytes().chunks_exact(2) {
        let hi = decode_nibble(pair[0]);
        let lo = decode_nibble(pair[1]);
        out.push((hi << 4) | lo);
    }
    out
}

fn decode_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("decode_hex: invalid hex digit {:?}", byte as char),
    }
}

#[cfg(test)]
mod tests {
    use std::panic;

    use tempfile::tempdir;

    use super::*;

    const TEST_EMAIL: &str = "test@example.com";
    const TEST_NAME: &str = "Test User";

    fn require_git() -> bool {
        if git_available() {
            return true;
        }
        eprintln!("git not available; skipping git_test_support tests");
        false
    }

    #[test]
    fn run_git_succeeds_on_valid_command() {
        if !require_git() {
            return;
        }
        let dir = tempdir().expect("tempdir");
        run_git(dir.path(), &["--version"]);
    }

    #[test]
    fn run_git_panics_on_invalid_command() {
        if !require_git() {
            return;
        }
        let dir = tempdir().expect("tempdir");
        let result = panic::catch_unwind(|| run_git(dir.path(), &["not-a-real-subcommand"]));
        assert!(result.is_err(), "invalid git subcommand must panic");
    }

    #[test]
    fn git_stdout_returns_trimmed_output() {
        if !require_git() {
            return;
        }
        let dir = tempdir().expect("tempdir");
        init_git_repo(dir.path(), TEST_EMAIL, TEST_NAME);
        run_git(
            dir.path(),
            &["commit", "--allow-empty", "-q", "-m", "fixture"],
        );

        let head = git_stdout(dir.path(), &["rev-parse", "HEAD"]);
        assert_eq!(head.len(), 40);
        assert!(head.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(head.trim(), head);
    }

    #[test]
    fn init_git_repo_creates_main_branch() {
        if !require_git() {
            return;
        }
        let dir = tempdir().expect("tempdir");
        init_git_repo(dir.path(), TEST_EMAIL, TEST_NAME);

        let branch = git_stdout(dir.path(), &["branch", "--show-current"]);
        assert_eq!(branch, "main");
    }

    #[test]
    fn init_committed_repo_has_head() {
        if !require_git() {
            return;
        }
        let dir = tempdir().expect("tempdir");
        init_committed_repo(dir.path(), TEST_EMAIL, TEST_NAME);

        let head = git_stdout(dir.path(), &["rev-parse", "--verify", "HEAD"]);
        assert_eq!(head.len(), 40);
    }

    #[test]
    fn decode_hex_roundtrip() {
        let bytes = [0x00, 0x12, 0xab, 0xcd, 0xff];
        assert_eq!(decode_hex(&crate::hex_encode(&bytes)), bytes);
    }

    #[test]
    fn decode_hex_panics_on_odd_length() {
        let result = panic::catch_unwind(|| decode_hex("abc"));
        assert!(result.is_err(), "odd-length hex input must panic");
    }
}

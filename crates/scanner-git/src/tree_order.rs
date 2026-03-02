//! Git tree entry ordering.
//!
//! Git trees store entries in a specific sorted order that differs from
//! plain lexicographic byte comparison. This module provides the correct
//! comparison function for tree entry names.
//!
//! # Git Tree Ordering Rules
//!
//! Git's `base_name_compare()` compares tree entries as follows:
//!
//! 1. Compare name bytes lexicographically up to the shorter length (memcmp)
//! 2. If prefixes match, compare the "next byte" where:
//!    - If the name ended, use the virtual terminator
//!    - Directories use `/` (0x2F) as virtual terminator
//!    - Files use NUL (0x00) as virtual terminator
//!
//! # Why This Matters
//!
//! For prefix relationships, this creates non-obvious ordering:
//!
//! ```text
//! File "a" vs File "a.txt":  0x00 vs '.' (0x2E) -> "a" < "a.txt"
//! Dir  "a" vs File "a.txt":  '/'  vs '.' (0x2E) -> "a/" > "a.txt"
//! Dir  "a" vs Dir  "a.":     '/'  vs '.' (0x2E) -> "a/" > "a./"
//! ```
//!
//! This is why `a.txt` sorts before `a/` when `a` is a directory.
//!
//! # Caller Contract
//!
//! The `is_dir` flag must mean "tree entry mode is 040000" (Git tree object),
//! NOT "filesystem directory" or "path contains a slash". For symlinks and
//! submodules (gitlinks), `is_dir` must be `false`.
//!
//! # References
//!
//! - Git source: `tree.c`, `base_name_compare()`
//! - https://kernel.googlesource.com/pub/scm/git/git.git/+/refs/heads/master/tree.c

use core::cmp::Ordering;

/// Virtual terminator byte for Git tree ordering.
///
/// Directories compare as if they end with `/` (0x2F).
/// Files compare as if they end with NUL (0x00).
#[inline(always)]
const fn terminator(is_dir: bool) -> u8 {
    if is_dir {
        b'/'
    } else {
        0
    }
}

/// Compares two tree entry names using Git's tree ordering rules.
///
/// This implements the semantics of Git's `base_name_compare()` function,
/// which is critical for correct tree diff merge-walks.
///
/// # Arguments
///
/// * `a_name` - First entry name (without trailing NUL)
/// * `a_is_dir` - True if first entry is a tree (mode 040000)
/// * `b_name` - Second entry name (without trailing NUL)
/// * `b_is_dir` - True if second entry is a tree (mode 040000)
///
/// # Performance
///
/// Uses optimized `memcmp` for prefix comparison via `slice::cmp`.
/// The terminator logic handles the suffix comparison.
///
/// # Examples
///
/// ```
/// use scanner_git::tree_order::git_tree_name_cmp;
/// use core::cmp::Ordering;
///
/// // File "a" vs file "a.txt": 0x00 < '.' -> "a" < "a.txt"
/// assert_eq!(
///     git_tree_name_cmp(b"a", false, b"a.txt", false),
///     Ordering::Less
/// );
///
/// // Dir "a" vs file "a.txt": '/' > '.' -> "a/" > "a.txt"
/// assert_eq!(
///     git_tree_name_cmp(b"a", true, b"a.txt", false),
///     Ordering::Greater
/// );
///
/// // Dir "a" vs dir "a.": '/' > '.' -> "a/" > "a./"
/// assert_eq!(
///     git_tree_name_cmp(b"a", true, b"a.", true),
///     Ordering::Greater
/// );
/// ```
#[inline]
pub fn git_tree_name_cmp(a_name: &[u8], a_is_dir: bool, b_name: &[u8], b_is_dir: bool) -> Ordering {
    let len_a = a_name.len();
    let len_b = b_name.len();
    let min_len = len_a.min(len_b);

    // Fast prefix comparison using optimized memcmp via slice::cmp
    let prefix_cmp = a_name[..min_len].cmp(&b_name[..min_len]);
    if prefix_cmp != Ordering::Equal {
        return prefix_cmp;
    }

    // Prefix matches. Compare the "next byte" for each side.
    // If the name ended, use the virtual terminator; otherwise use the actual byte.
    let a_next = if len_a > min_len {
        a_name[min_len]
    } else {
        terminator(a_is_dir)
    };
    let b_next = if len_b > min_len {
        b_name[min_len]
    } else {
        terminator(b_is_dir)
    };

    a_next.cmp(&b_next)
}

/// Compares two file entries by name (both must be non-directories).
///
/// This is a safe optimization when you know both entries are files
/// (blobs, symlinks, or gitlinks - anything with `is_dir = false`).
///
/// For files, the virtual terminator is NUL (0x00), and since all valid
/// filename bytes are > 0, standard lexicographic comparison is equivalent
/// to Git's tree ordering.
///
/// # Safety Contract
///
/// Do not use this for directories. Directory ordering differs from
/// lexicographic when one name is a prefix of another and the longer name's
/// next character is less than `/` (e.g., `-`, `.`, `+`).
///
/// # Examples
///
/// ```
/// use scanner_git::tree_order::{git_tree_name_cmp, git_tree_file_name_cmp};
/// use core::cmp::Ordering;
///
/// // For files, this is equivalent to the full comparison
/// assert_eq!(
///     git_tree_file_name_cmp(b"foo", b"foo.txt"),
///     git_tree_name_cmp(b"foo", false, b"foo.txt", false)
/// );
/// ```
#[inline]
pub fn git_tree_file_name_cmp(a_name: &[u8], b_name: &[u8]) -> Ordering {
    // For files (terminator = 0x00), lexicographic comparison is correct
    // because all valid filename bytes are > 0x00.
    a_name.cmp(b_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Basic ordering tests

    #[test]
    fn same_name_same_type() {
        assert_eq!(
            git_tree_name_cmp(b"foo", false, b"foo", false),
            Ordering::Equal
        );
        assert_eq!(
            git_tree_name_cmp(b"foo", true, b"foo", true),
            Ordering::Equal
        );
    }

    #[test]
    fn same_name_different_type() {
        // File (terminator 0x00) < Directory (terminator 0x2F)
        assert_eq!(
            git_tree_name_cmp(b"foo", false, b"foo", true),
            Ordering::Less
        );
        assert_eq!(
            git_tree_name_cmp(b"foo", true, b"foo", false),
            Ordering::Greater
        );
    }

    #[test]
    fn different_names_no_prefix_relation() {
        assert_eq!(
            git_tree_name_cmp(b"abc", false, b"def", false),
            Ordering::Less
        );
        assert_eq!(
            git_tree_name_cmp(b"xyz", false, b"abc", false),
            Ordering::Greater
        );
    }

    // Prefix cases (the tricky ones)

    #[test]
    fn file_prefix_of_file() {
        // "a\0" vs "a.txt\0"
        assert_eq!(
            git_tree_name_cmp(b"a", false, b"a.txt", false),
            Ordering::Less
        );
        assert_eq!(
            git_tree_name_cmp(b"a.txt", false, b"a", false),
            Ordering::Greater
        );
    }

    #[test]
    fn dir_prefix_of_file() {
        // "a/" vs "a.txt\0"
        assert_eq!(
            git_tree_name_cmp(b"a", true, b"a.txt", false),
            Ordering::Greater
        );
        assert_eq!(
            git_tree_name_cmp(b"a.txt", false, b"a", true),
            Ordering::Less
        );
    }

    #[test]
    fn file_prefix_of_dir_different_names() {
        // "a\0" vs "ab/"
        assert_eq!(git_tree_name_cmp(b"a", false, b"ab", true), Ordering::Less);
    }

    #[test]
    fn dir_prefix_of_dir_different_names() {
        // "a/" vs "ab/"
        assert_eq!(git_tree_name_cmp(b"a", true, b"ab", true), Ordering::Less);
    }

    #[test]
    fn file_vs_dir_same_prefix_next_byte_lt_slash() {
        // File "a-" vs Dir "a"
        // Compare: '-' (0x2D) vs '/' (0x2F) -> '-' < '/'
        assert_eq!(git_tree_name_cmp(b"a-", false, b"a", true), Ordering::Less);
    }

    #[test]
    fn file_vs_dir_same_prefix_next_byte_gt_slash() {
        // File "a~" vs Dir "a"
        // Compare: '~' (0x7E) vs '/' (0x2F) -> '~' > '/'
        assert_eq!(
            git_tree_name_cmp(b"a~", false, b"a", true),
            Ordering::Greater
        );
    }

    #[test]
    fn file_name_cmp_matches_full_for_files() {
        assert_eq!(
            git_tree_file_name_cmp(b"foo", b"foo.txt"),
            git_tree_name_cmp(b"foo", false, b"foo.txt", false)
        );
    }
}

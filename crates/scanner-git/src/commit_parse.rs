//! Parser for Git commit objects.
//!
//! This module provides efficient parsing of commit objects to extract
//! the tree OID, parent OIDs, and committer timestamp needed for
//! commit graph construction.
//!
//! # Commit Object Format
//! ```text
//! tree <hex-oid>\n
//! parent <hex-oid>\n   (zero or more)
//! author <name> <email> <timestamp> <tz>\n
//! committer <name> <email> <timestamp> <tz>\n
//! [gpgsig <signature>]\n  (optional, may span multiple lines)
//! \n
//! <message>
//! ```
//!
//! # Parsing Assumptions
//! - Headers appear in the standard order: `tree`, zero or more `parent`,
//!   `author`, then `committer`.
//! - The `committer` line ends with `"<timestamp> <timezone>"`. The parser
//!   extracts the second-to-last field to tolerate spaces in names/emails.
//! - `gpgsig` and message bodies are ignored; we stop parsing after the
//!   `committer` line and do not validate signature payloads.
//!
//! # Complexity
//! - Parsing is O(header size), not O(commit size).
//! - Memory allocation is bounded by parent count.

use std::fmt;

use super::object_id::{ObjectFormat, OidBytes};
use super::repo_paths;

/// Errors from commit parsing.
#[derive(Debug)]
#[non_exhaustive]
pub enum CommitParseError {
    /// Commit data is corrupt or malformed.
    Corrupt { detail: &'static str },
    /// Commit exceeds size limit.
    TooLarge { size: usize, max: usize },
    /// Too many parent commits.
    TooManyParents { count: usize, max: usize },
    /// Invalid hex character in OID.
    InvalidHex { byte: u8 },
    /// OID has wrong length.
    InvalidOidLength { found: usize, expected: usize },
    /// Invalid timestamp value.
    InvalidTimestamp { detail: &'static str },
}

impl CommitParseError {
    /// Constructs a corruption error with a static detail string.
    #[inline]
    pub const fn corrupt(detail: &'static str) -> Self {
        Self::Corrupt { detail }
    }
}

impl fmt::Display for CommitParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Corrupt { detail } => write!(f, "corrupt commit: {detail}"),
            Self::TooLarge { size, max } => {
                write!(f, "commit too large: {size} bytes (max: {max})")
            }
            Self::TooManyParents { count, max } => {
                write!(f, "too many parents: {count} (max: {max})")
            }
            Self::InvalidHex { byte } => {
                write!(f, "invalid hex byte in OID: 0x{byte:02x}")
            }
            Self::InvalidOidLength { found, expected } => {
                write!(f, "OID length mismatch: found {found}, expected {expected}")
            }
            Self::InvalidTimestamp { detail } => {
                write!(f, "invalid timestamp: {detail}")
            }
        }
    }
}

impl std::error::Error for CommitParseError {}

/// Parsed commit data.
///
/// Contains the essential fields needed for commit graph construction:
/// tree OID for blob extraction, parent OIDs for graph edges, and
/// committer timestamp for generation number validation.
#[derive(Debug, Clone)]
pub struct ParsedCommit {
    /// The tree object this commit points to.
    pub tree_oid: OidBytes,
    /// Parent commit OIDs (empty for root commits).
    pub parents: Vec<OidBytes>,
    /// Unix timestamp from the committer line.
    pub committer_timestamp: u64,
}

/// Limits for commit parsing.
#[derive(Debug, Clone, Copy)]
pub struct CommitParseLimits {
    /// Maximum commit object size in bytes.
    pub max_commit_bytes: usize,
    /// Maximum number of parents (for octopus merges).
    pub max_parents: usize,
}

impl Default for CommitParseLimits {
    fn default() -> Self {
        Self {
            max_commit_bytes: 1024 * 1024, // 1 MiB
            max_parents: 256,              // Well above typical octopus merges
        }
    }
}

/// Parses a commit object.
///
/// Extracts the tree OID, parent OIDs, and committer timestamp from
/// a raw commit object. The commit message is not parsed.
///
/// The parser expects the header ordering shown in the module docs. Non-standard
/// header layouts are treated as corrupt.
///
/// The returned data is sufficient for commit-graph construction; callers that
/// need additional headers must parse the remaining payload separately.
///
/// # Errors
/// Returns `CommitParseError` if the commit is malformed, too large,
/// or has too many parents.
pub fn parse_commit(
    data: &[u8],
    format: ObjectFormat,
    limits: &CommitParseLimits,
) -> Result<ParsedCommit, CommitParseError> {
    if data.len() > limits.max_commit_bytes {
        return Err(CommitParseError::TooLarge {
            size: data.len(),
            max: limits.max_commit_bytes,
        });
    }

    let hex_len = format.hex_len() as usize;
    let mut pos = 0;

    // Parse "tree <hex>\n"
    let tree_oid = parse_tree_line(data, &mut pos, format, hex_len)?;

    // Parse zero or more "parent <hex>\n" lines
    let mut parents = Vec::new();
    while data[pos..].starts_with(b"parent ") {
        if parents.len() >= limits.max_parents {
            return Err(CommitParseError::TooManyParents {
                count: parents.len() + 1,
                max: limits.max_parents,
            });
        }
        let parent = parse_parent_line(data, &mut pos, format, hex_len)?;
        parents.push(parent);
    }

    // Skip "author" line
    skip_header_line(data, &mut pos, b"author ")?;

    // Parse "committer" line for timestamp
    let committer_timestamp = parse_committer_timestamp(data, &mut pos)?;

    // We don't need to parse gpgsig or message

    Ok(ParsedCommit {
        tree_oid,
        parents,
        committer_timestamp,
    })
}

/// Parses the "tree <hex>\n" line.
fn parse_tree_line(
    data: &[u8],
    pos: &mut usize,
    format: ObjectFormat,
    hex_len: usize,
) -> Result<OidBytes, CommitParseError> {
    let prefix = b"tree ";
    if !data[*pos..].starts_with(prefix) {
        return Err(CommitParseError::corrupt("missing tree line"));
    }
    *pos += prefix.len();

    // Need hex_len bytes + newline
    if data.len() < *pos + hex_len + 1 {
        return Err(CommitParseError::corrupt("tree line too short"));
    }

    let hex = &data[*pos..*pos + hex_len];
    let oid = parse_hex_oid(hex, format)?;

    *pos += hex_len;

    // Expect newline
    if data[*pos] != b'\n' {
        return Err(CommitParseError::corrupt("tree line missing newline"));
    }
    *pos += 1;

    Ok(oid)
}

/// Parses a "parent <hex>\n" line.
fn parse_parent_line(
    data: &[u8],
    pos: &mut usize,
    format: ObjectFormat,
    hex_len: usize,
) -> Result<OidBytes, CommitParseError> {
    let prefix = b"parent ";
    debug_assert!(data[*pos..].starts_with(prefix));
    *pos += prefix.len();

    // Need hex_len bytes + newline
    if data.len() < *pos + hex_len + 1 {
        return Err(CommitParseError::corrupt("parent line too short"));
    }

    let hex = &data[*pos..*pos + hex_len];
    let oid = parse_hex_oid(hex, format)?;

    *pos += hex_len;

    // Expect newline
    if data[*pos] != b'\n' {
        return Err(CommitParseError::corrupt("parent line missing newline"));
    }
    *pos += 1;

    Ok(oid)
}

/// Skips a header line starting with the given prefix.
fn skip_header_line(data: &[u8], pos: &mut usize, prefix: &[u8]) -> Result<(), CommitParseError> {
    if !data[*pos..].starts_with(prefix) {
        return Err(CommitParseError::corrupt("missing expected header line"));
    }

    // Find newline
    let remaining = &data[*pos..];
    let newline = remaining
        .iter()
        .position(|&b| b == b'\n')
        .ok_or_else(|| CommitParseError::corrupt("header line missing newline"))?;

    *pos += newline + 1;
    Ok(())
}

/// Parses the committer line and extracts the timestamp.
///
/// Format: `committer <name> <email> <timestamp> <timezone>\n`
///
/// The timestamp is a Unix timestamp (seconds since epoch). We scan backwards
/// for the last two space-separated fields to avoid parsing names/emails that
/// may contain spaces.
fn parse_committer_timestamp(data: &[u8], pos: &mut usize) -> Result<u64, CommitParseError> {
    let prefix = b"committer ";
    if !data[*pos..].starts_with(prefix) {
        return Err(CommitParseError::corrupt("missing committer line"));
    }

    // Find the end of the line
    let remaining = &data[*pos..];
    let newline = remaining
        .iter()
        .position(|&b| b == b'\n')
        .ok_or_else(|| CommitParseError::corrupt("committer line missing newline"))?;

    let line = &remaining[..newline];
    *pos += newline + 1;

    // Find timestamp by searching backwards from the end
    // Line format: "committer Name <email> timestamp timezone"
    // We need to find the second-to-last space-separated field

    // Find the last space (before timezone)
    let last_space = line
        .iter()
        .rposition(|&b| b == b' ')
        .ok_or_else(|| CommitParseError::corrupt("committer line malformed"))?;

    // Find the space before that (before timestamp)
    let timestamp_start = line[..last_space]
        .iter()
        .rposition(|&b| b == b' ')
        .ok_or_else(|| CommitParseError::corrupt("committer line malformed"))?
        + 1;

    let timestamp_bytes = &line[timestamp_start..last_space];

    // Parse as integer
    let timestamp = parse_unix_timestamp(timestamp_bytes)?;

    // Sanity check: timestamp should be reasonable (after 1970, before year 3000)
    // This catches obvious parse errors without being too restrictive
    if timestamp > 32_503_680_000 {
        // Year 3000
        return Err(CommitParseError::InvalidTimestamp {
            detail: "timestamp too large (after year 3000)",
        });
    }

    Ok(timestamp)
}

/// Parses a Unix timestamp from ASCII decimal bytes.
///
/// Overflow is detected with checked arithmetic. Policy bounds (for example,
/// rejecting post-year-3000 commit timestamps) are enforced by the caller.
fn parse_unix_timestamp(bytes: &[u8]) -> Result<u64, CommitParseError> {
    if bytes.is_empty() {
        return Err(CommitParseError::InvalidTimestamp {
            detail: "empty timestamp",
        });
    }

    let mut result: u64 = 0;
    for &b in bytes {
        if !b.is_ascii_digit() {
            return Err(CommitParseError::InvalidTimestamp {
                detail: "non-digit in timestamp",
            });
        }
        let digit = (b - b'0') as u64;
        result = result
            .checked_mul(10)
            .and_then(|v| v.checked_add(digit))
            .ok_or(CommitParseError::InvalidTimestamp {
                detail: "timestamp overflow",
            })?;
    }

    Ok(result)
}

/// Parses a hex-encoded OID into `OidBytes`.
fn parse_hex_oid(hex: &[u8], format: ObjectFormat) -> Result<OidBytes, CommitParseError> {
    repo_paths::parse_hex_oid(hex, format).map_err(|err| match err {
        repo_paths::HexOidParseError::InvalidHex { byte } => CommitParseError::InvalidHex { byte },
        repo_paths::HexOidParseError::InvalidOidLength { found, expected } => {
            CommitParseError::InvalidOidLength { found, expected }
        }
    })
}

/// Converts a hex ASCII byte to its numeric value.
#[inline]
#[cfg(test)]
fn hex_digit(b: u8) -> Result<u8, CommitParseError> {
    repo_paths::decode_hex_digit(b).ok_or(CommitParseError::InvalidHex { byte: b })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_commit(
        tree: &str,
        parents: &[&str],
        author: &str,
        committer: &str,
        msg: &str,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"tree ");
        out.extend_from_slice(tree.as_bytes());
        out.push(b'\n');

        for parent in parents {
            out.extend_from_slice(b"parent ");
            out.extend_from_slice(parent.as_bytes());
            out.push(b'\n');
        }

        out.extend_from_slice(b"author ");
        out.extend_from_slice(author.as_bytes());
        out.push(b'\n');

        out.extend_from_slice(b"committer ");
        out.extend_from_slice(committer.as_bytes());
        out.push(b'\n');

        out.push(b'\n');
        out.extend_from_slice(msg.as_bytes());

        out
    }

    const TREE_HEX: &str = "1234567890abcdef1234567890abcdef12345678";
    const PARENT1_HEX: &str = "abcdef1234567890abcdef1234567890abcdef12";
    const PARENT2_HEX: &str = "fedcba0987654321fedcba0987654321fedcba09";

    #[test]
    fn parse_root_commit() {
        let data = make_commit(
            TREE_HEX,
            &[],
            "Author Name <author@example.com> 1700000000 +0000",
            "Committer Name <committer@example.com> 1700000001 +0000",
            "Initial commit",
        );

        let limits = CommitParseLimits::default();
        let commit = parse_commit(&data, ObjectFormat::Sha1, &limits).unwrap();

        assert!(commit.parents.is_empty());
        assert_eq!(commit.committer_timestamp, 1700000001);

        // Verify tree OID
        let expected_tree = parse_hex_oid(TREE_HEX.as_bytes(), ObjectFormat::Sha1).unwrap();
        assert_eq!(commit.tree_oid, expected_tree);
    }

    #[test]
    fn parse_single_parent_commit() {
        let data = make_commit(
            TREE_HEX,
            &[PARENT1_HEX],
            "Author Name <author@example.com> 1700000000 +0000",
            "Committer Name <committer@example.com> 1700000002 -0500",
            "Second commit",
        );

        let limits = CommitParseLimits::default();
        let commit = parse_commit(&data, ObjectFormat::Sha1, &limits).unwrap();

        assert_eq!(commit.parents.len(), 1);
        let expected_parent = parse_hex_oid(PARENT1_HEX.as_bytes(), ObjectFormat::Sha1).unwrap();
        assert_eq!(commit.parents[0], expected_parent);
        assert_eq!(commit.committer_timestamp, 1700000002);
    }

    #[test]
    fn parse_merge_commit() {
        let data = make_commit(
            TREE_HEX,
            &[PARENT1_HEX, PARENT2_HEX],
            "Author Name <author@example.com> 1700000000 +0000",
            "Committer Name <committer@example.com> 1700000003 +0100",
            "Merge branch 'feature'",
        );

        let limits = CommitParseLimits::default();
        let commit = parse_commit(&data, ObjectFormat::Sha1, &limits).unwrap();

        assert_eq!(commit.parents.len(), 2);
        let expected_p1 = parse_hex_oid(PARENT1_HEX.as_bytes(), ObjectFormat::Sha1).unwrap();
        let expected_p2 = parse_hex_oid(PARENT2_HEX.as_bytes(), ObjectFormat::Sha1).unwrap();
        assert_eq!(commit.parents[0], expected_p1);
        assert_eq!(commit.parents[1], expected_p2);
    }

    #[test]
    fn parse_gpgsig_commit() {
        // GPG-signed commit has extra header between committer and message
        let mut data = Vec::new();
        data.extend_from_slice(b"tree ");
        data.extend_from_slice(TREE_HEX.as_bytes());
        data.push(b'\n');
        data.extend_from_slice(b"parent ");
        data.extend_from_slice(PARENT1_HEX.as_bytes());
        data.push(b'\n');
        data.extend_from_slice(b"author Author <a@b.com> 1700000000 +0000\n");
        data.extend_from_slice(b"committer Committer <c@d.com> 1700000004 +0000\n");
        data.extend_from_slice(b"gpgsig -----BEGIN PGP SIGNATURE-----\n");
        data.extend_from_slice(b" \n");
        data.extend_from_slice(b" iQEzBAABCAAdFiEE...\n");
        data.extend_from_slice(b" -----END PGP SIGNATURE-----\n");
        data.push(b'\n');
        data.extend_from_slice(b"Signed commit message\n");

        let limits = CommitParseLimits::default();
        let commit = parse_commit(&data, ObjectFormat::Sha1, &limits).unwrap();

        assert_eq!(commit.parents.len(), 1);
        assert_eq!(commit.committer_timestamp, 1700000004);
    }

    #[test]
    fn parse_sha256_commit() {
        let tree_hex = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let parent_hex = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";

        let data = make_commit(
            tree_hex,
            &[parent_hex],
            "Author <a@b.com> 1700000000 +0000",
            "Committer <c@d.com> 1700000005 +0000",
            "SHA-256 commit",
        );

        let limits = CommitParseLimits::default();
        let commit = parse_commit(&data, ObjectFormat::Sha256, &limits).unwrap();

        assert_eq!(commit.tree_oid.len(), 32);
        assert_eq!(commit.parents.len(), 1);
        assert_eq!(commit.parents[0].len(), 32);
        assert_eq!(commit.committer_timestamp, 1700000005);
    }

    #[test]
    fn reject_too_large_commit() {
        let data = vec![0u8; 2 * 1024 * 1024]; // 2 MiB

        let limits = CommitParseLimits {
            max_commit_bytes: 1024 * 1024,
            max_parents: 256,
        };

        let result = parse_commit(&data, ObjectFormat::Sha1, &limits);
        assert!(matches!(result, Err(CommitParseError::TooLarge { .. })));
    }

    #[test]
    fn reject_too_many_parents() {
        let mut data = Vec::new();
        data.extend_from_slice(b"tree ");
        data.extend_from_slice(TREE_HEX.as_bytes());
        data.push(b'\n');

        // Add 10 parents
        for _ in 0..10 {
            data.extend_from_slice(b"parent ");
            data.extend_from_slice(PARENT1_HEX.as_bytes());
            data.push(b'\n');
        }

        data.extend_from_slice(b"author A <a@b.com> 1700000000 +0000\n");
        data.extend_from_slice(b"committer C <c@d.com> 1700000000 +0000\n");
        data.push(b'\n');

        let limits = CommitParseLimits {
            max_commit_bytes: 1024 * 1024,
            max_parents: 5,
        };

        let result = parse_commit(&data, ObjectFormat::Sha1, &limits);
        assert!(matches!(
            result,
            Err(CommitParseError::TooManyParents { .. })
        ));
    }

    #[test]
    fn reject_invalid_hex() {
        let mut data = make_commit(
            TREE_HEX,
            &[],
            "Author <a@b.com> 1700000000 +0000",
            "Committer <c@d.com> 1700000000 +0000",
            "msg",
        );

        // Corrupt the tree hex
        data[5] = b'Z';

        let limits = CommitParseLimits::default();
        let result = parse_commit(&data, ObjectFormat::Sha1, &limits);
        assert!(matches!(result, Err(CommitParseError::InvalidHex { .. })));
    }

    #[test]
    fn reject_missing_tree() {
        let data = b"parent abcdef1234567890abcdef1234567890abcdef12\n";

        let limits = CommitParseLimits::default();
        let result = parse_commit(data, ObjectFormat::Sha1, &limits);
        assert!(matches!(result, Err(CommitParseError::Corrupt { .. })));
    }

    #[test]
    fn reject_missing_committer() {
        let mut data = Vec::new();
        data.extend_from_slice(b"tree ");
        data.extend_from_slice(TREE_HEX.as_bytes());
        data.push(b'\n');
        data.extend_from_slice(b"author Author <a@b.com> 1700000000 +0000\n");
        // Missing committer line
        data.push(b'\n');
        data.extend_from_slice(b"Message\n");

        let limits = CommitParseLimits::default();
        let result = parse_commit(&data, ObjectFormat::Sha1, &limits);
        assert!(matches!(result, Err(CommitParseError::Corrupt { .. })));
    }

    #[test]
    fn parse_timestamp_edge_cases() {
        // Very early timestamp (1970)
        let data = make_commit(
            TREE_HEX,
            &[],
            "A <a@b.com> 0 +0000",
            "C <c@d.com> 0 +0000",
            "msg",
        );

        let limits = CommitParseLimits::default();
        let commit = parse_commit(&data, ObjectFormat::Sha1, &limits).unwrap();
        assert_eq!(commit.committer_timestamp, 0);

        // Large but valid timestamp (year 2500)
        let data = make_commit(
            TREE_HEX,
            &[],
            "A <a@b.com> 16725225600 +0000",
            "C <c@d.com> 16725225600 +0000",
            "msg",
        );
        let commit = parse_commit(&data, ObjectFormat::Sha1, &limits).unwrap();
        assert_eq!(commit.committer_timestamp, 16725225600);
    }

    #[test]
    fn parse_negative_timezone() {
        // Negative timezone should not affect timestamp parsing
        let data = make_commit(
            TREE_HEX,
            &[],
            "A <a@b.com> 1700000000 -1200",
            "C <c@d.com> 1700000006 -0800",
            "msg",
        );

        let limits = CommitParseLimits::default();
        let commit = parse_commit(&data, ObjectFormat::Sha1, &limits).unwrap();
        assert_eq!(commit.committer_timestamp, 1700000006);
    }

    #[test]
    fn reject_committer_timestamp_u64_wraparound() {
        // u64::MAX + 1. Older wrapping arithmetic could parse this as 0,
        // allowing it past the caller's year-3000 range check.
        let data = make_commit(
            TREE_HEX,
            &[],
            "A <a@b.com> 1700000000 +0000",
            "C <c@d.com> 18446744073709551616 +0000",
            "msg",
        );

        let limits = CommitParseLimits::default();
        let result = parse_commit(&data, ObjectFormat::Sha1, &limits);
        assert!(
            matches!(result, Err(CommitParseError::InvalidTimestamp { .. })),
            "expected invalid timestamp error for wrapped u64 input, got: {result:?}",
        );
    }

    #[test]
    fn parse_unix_timestamp_rejects_20_digit_overflow() {
        // "18446744073709551616" is u64::MAX + 1.
        let overflow = b"18446744073709551616";
        let result = parse_unix_timestamp(overflow);
        assert!(
            result.is_err(),
            "20-digit input (u64::MAX+1) must be rejected, got: {result:?}",
        );
    }

    #[test]
    fn parse_unix_timestamp_rejects_20_digit_all_nines() {
        // 20 nines also overflow u64.
        let all_nines = b"99999999999999999999";
        let result = parse_unix_timestamp(all_nines);
        assert!(
            result.is_err(),
            "20-digit all-nines must be rejected, got: {result:?}",
        );
    }

    #[test]
    fn parse_unix_timestamp_accepts_u64_max() {
        let max = b"18446744073709551615";
        let result = parse_unix_timestamp(max);
        assert_eq!(result.unwrap(), u64::MAX);
    }

    #[test]
    fn parse_unix_timestamp_accepts_leading_zero_padding() {
        let leading_zeros = b"000000000001";
        let result = parse_unix_timestamp(leading_zeros);
        assert_eq!(result.unwrap(), 1);
    }

    #[test]
    fn parse_unix_timestamp_accepts_11_digit() {
        // 32503680000 is 11 digits, representing year ~3000.
        let year_3000 = b"32503680000";
        let result = parse_unix_timestamp(year_3000);
        assert_eq!(result.unwrap(), 32_503_680_000);
    }

    #[test]
    fn parse_unix_timestamp_accepts_10_digit() {
        // 1700000000 is 10 digits, a typical recent Unix timestamp (~Nov 2023).
        let typical = b"1700000000";
        let result = parse_unix_timestamp(typical);
        assert_eq!(result.unwrap(), 1_700_000_000);
    }

    #[test]
    fn parse_commit_accepts_leading_zero_committer_timestamp() {
        let data = make_commit(
            TREE_HEX,
            &[],
            "A <a@b.com> 1700000000 +0000",
            "C <c@d.com> 000000000001 +0000",
            "msg",
        );

        let limits = CommitParseLimits::default();
        let commit = parse_commit(&data, ObjectFormat::Sha1, &limits).unwrap();
        assert_eq!(commit.committer_timestamp, 1);
    }

    #[test]
    fn parse_commit_rejects_post_year_3000_timestamp_with_leading_zeroes() {
        let data = make_commit(
            TREE_HEX,
            &[],
            "A <a@b.com> 1700000000 +0000",
            "C <c@d.com> 00032503680001 +0000",
            "msg",
        );

        let limits = CommitParseLimits::default();
        let result = parse_commit(&data, ObjectFormat::Sha1, &limits);
        assert!(matches!(
            result,
            Err(CommitParseError::InvalidTimestamp { .. })
        ));
    }

    #[test]
    fn hex_digit_conversion() {
        assert_eq!(hex_digit(b'0').unwrap(), 0);
        assert_eq!(hex_digit(b'9').unwrap(), 9);
        assert_eq!(hex_digit(b'a').unwrap(), 10);
        assert_eq!(hex_digit(b'f').unwrap(), 15);
        assert_eq!(hex_digit(b'A').unwrap(), 10);
        assert_eq!(hex_digit(b'F').unwrap(), 15);
        assert!(hex_digit(b'g').is_err());
        assert!(hex_digit(b'G').is_err());
        assert!(hex_digit(b' ').is_err());
    }
}

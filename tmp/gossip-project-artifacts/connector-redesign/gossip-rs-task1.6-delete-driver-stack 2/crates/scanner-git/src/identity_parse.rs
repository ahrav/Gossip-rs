//! Zero-copy extraction of author/committer identity from raw git commit bytes.
//!
//! Git commit objects store identity in ASCII header lines:
//!
//! ```text
//! author Name <email> timestamp timezone\n
//! committer Name <email> timestamp timezone\n
//! ```
//!
//! [`super::commit_parse::parse_commit`] already extracts structural fields
//! (tree, parents, committer timestamp) but not identity. Rather than threading identity
//! extraction through that well-tested parser, this module makes a second pass
//! over the same header bytes (~200 B). The cost is negligible — a single
//! linear scan with no allocation — and keeps the two concerns decoupled.
//!
//! Parsed [`RawIdentity`] values are then interned via
//! [`super::identity_intern::IdentityInterner`] to produce compact `u32` IDs
//! for downstream storage.
//!
//! # Invariants
//! - **Zero allocation**: all returned slices borrow the input commit bytes.
//! - **Format-agnostic**: works on any git object format (SHA-1 or SHA-256)
//!   since it only inspects header lines, not OID fields.
//! - **Total function**: never panics; returns `None` on malformed input.
//!
//! # Edge cases
//! - Empty name (`<email> timestamp tz`) → `name` is an empty slice.
//! - Empty email (`Name <> timestamp tz`) → `email` is an empty slice.
//! - Non-UTF-8 bytes in name → preserved as raw bytes (handled at
//!   serialization time via `\u00XX` escaping).
//! - Missing angle brackets → returns `None`.
//! - Multiple `<>` pairs → uses first `<` and last `>`, matching
//!   git's own `split_ident_line` behavior.

/// Borrowed name + email extracted from a single identity header line.
///
/// All slices borrow directly from the input commit bytes — no copies,
/// no owned storage. Lifetime `'a` ties this to the commit buffer.
///
/// Both fields may be empty slices (valid per git) and may contain
/// non-UTF-8 bytes (preserved as-is for the interner).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawIdentity<'a> {
    /// Name bytes (everything before the first `<`, trimmed).
    pub name: &'a [u8],
    /// Email bytes (between first `<` and last `>`).
    pub email: &'a [u8],
}

/// Extracts author identity from raw commit object bytes.
///
/// Scans for the `"author "` header line, then parses name and email.
/// Returns `None` if the header is missing or malformed.
pub fn parse_author_identity(data: &[u8]) -> Option<RawIdentity<'_>> {
    let line = find_header_line(data, b"author ")?;
    parse_identity_fields(line)
}

/// Extracts committer identity from raw commit object bytes.
///
/// Scans for the `"committer "` header line, then parses name and email.
/// Returns `None` if the header is missing or malformed.
pub fn parse_committer_identity(data: &[u8]) -> Option<RawIdentity<'_>> {
    let line = find_header_line(data, b"committer ")?;
    parse_identity_fields(line)
}

/// Scan commit bytes for a header line starting with `prefix`.
///
/// Returns the portion of the line *after* the prefix, up to `\n` (exclusive).
/// Stops at the first blank line — the boundary between header and message
/// body in git's commit object format — so body content is never matched.
fn find_header_line<'a>(data: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    let mut pos = 0;
    while pos < data.len() {
        // Find end of current line.
        let line_end = memchr_newline(data, pos);

        let line = &data[pos..line_end];

        // Blank line = end of header section.
        if line.is_empty() {
            return None;
        }

        if line.starts_with(prefix) {
            return Some(&line[prefix.len()..]);
        }

        // Advance past the newline.
        pos = if line_end < data.len() {
            line_end + 1
        } else {
            line_end
        };
    }
    None
}

/// Extract name and email from the value portion of an identity header.
///
/// Input is the bytes *after* the `"author "` or `"committer "` prefix,
/// i.e. `Name <email> timestamp timezone`.
///
/// Uses first `<` and last `>` as delimiters. This matches git's own
/// `split_ident_line` in `ident.c`: when multiple angle-bracket pairs
/// exist (e.g. `Name <first> <second>`), the email spans from the
/// opening `<` to the final `>`, yielding `first> <second`.
fn parse_identity_fields(value: &[u8]) -> Option<RawIdentity<'_>> {
    let lt_pos = memchr_byte(b'<', value)?;
    let gt_pos = memchr_byte_rev(b'>', value)?;

    // Reversed or overlapping brackets → malformed.
    if gt_pos <= lt_pos {
        return None;
    }

    let name = trim_bytes(&value[..lt_pos]);
    let email = &value[lt_pos + 1..gt_pos];

    Some(RawIdentity { name, email })
}

/// Strip leading and trailing ASCII whitespace from a byte slice.
fn trim_bytes(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|b| !b.is_ascii_whitespace())
        .map(|p| p + 1)
        .unwrap_or(start);
    &bytes[start..end]
}

/// Find the first occurrence of `byte` in `data`.
#[inline]
fn memchr_byte(byte: u8, data: &[u8]) -> Option<usize> {
    data.iter().position(|&b| b == byte)
}

/// Find the last occurrence of `byte` in `data`.
#[inline]
fn memchr_byte_rev(byte: u8, data: &[u8]) -> Option<usize> {
    data.iter().rposition(|&b| b == byte)
}

/// Find the next newline in `data` starting at `from`, or return `data.len()`.
#[inline]
fn memchr_newline(data: &[u8], from: usize) -> usize {
    data[from..]
        .iter()
        .position(|&b| b == b'\n')
        .map(|p| from + p)
        .unwrap_or(data.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_commit(author: &[u8], committer: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"tree ");
        buf.extend_from_slice(&[b'a'; 40]);
        buf.push(b'\n');
        buf.extend_from_slice(b"author ");
        buf.extend_from_slice(author);
        buf.push(b'\n');
        buf.extend_from_slice(b"committer ");
        buf.extend_from_slice(committer);
        buf.push(b'\n');
        buf.push(b'\n');
        buf.extend_from_slice(b"commit message\n");
        buf
    }

    #[test]
    fn standard_identity() {
        let data = make_commit(
            b"Linus Torvalds <torvalds@linux-foundation.org> 1700000000 +0000",
            b"Linus Torvalds <torvalds@linux-foundation.org> 1700000000 +0000",
        );

        let author = parse_author_identity(&data).unwrap();
        assert_eq!(author.name, b"Linus Torvalds");
        assert_eq!(author.email, b"torvalds@linux-foundation.org");

        let committer = parse_committer_identity(&data).unwrap();
        assert_eq!(committer.name, b"Linus Torvalds");
        assert_eq!(committer.email, b"torvalds@linux-foundation.org");
    }

    #[test]
    fn different_author_and_committer() {
        let data = make_commit(
            b"Alice <alice@example.com> 1700000000 +0000",
            b"Bob <bob@example.com> 1700000001 +0000",
        );

        let author = parse_author_identity(&data).unwrap();
        assert_eq!(author.name, b"Alice");
        assert_eq!(author.email, b"alice@example.com");

        let committer = parse_committer_identity(&data).unwrap();
        assert_eq!(committer.name, b"Bob");
        assert_eq!(committer.email, b"bob@example.com");
    }

    #[test]
    fn empty_name() {
        let data = make_commit(
            b"<email@test.com> 1700000000 +0000",
            b"<email@test.com> 1700000000 +0000",
        );

        let author = parse_author_identity(&data).unwrap();
        assert_eq!(author.name, b"");
        assert_eq!(author.email, b"email@test.com");
    }

    #[test]
    fn empty_email() {
        let data = make_commit(
            b"Some Name <> 1700000000 +0000",
            b"Some Name <> 1700000000 +0000",
        );

        let author = parse_author_identity(&data).unwrap();
        assert_eq!(author.name, b"Some Name");
        assert_eq!(author.email, b"");
    }

    #[test]
    fn non_utf8_name() {
        let mut line = Vec::new();
        line.extend_from_slice(&[0xff, 0xfe, 0xfd]);
        line.extend_from_slice(b" <email@x.com> 1700000000 +0000");

        let data = make_commit(&line, &line);
        let author = parse_author_identity(&data).unwrap();
        assert_eq!(author.name, &[0xff, 0xfe, 0xfd]);
        assert_eq!(author.email, b"email@x.com");
    }

    #[test]
    fn missing_brackets_returns_none() {
        let data = make_commit(
            b"No Brackets 1700000000 +0000",
            b"No Brackets 1700000000 +0000",
        );

        assert!(parse_author_identity(&data).is_none());
    }

    #[test]
    fn missing_closing_bracket_returns_none() {
        let data = make_commit(
            b"Name <email 1700000000 +0000",
            b"Name <email 1700000000 +0000",
        );

        assert!(parse_author_identity(&data).is_none());
    }

    #[test]
    fn multiple_angle_brackets() {
        // First `<`, last `>` — matches git's behavior.
        let data = make_commit(
            b"Name <first> <second> 1700000000 +0000",
            b"Name <first> <second> 1700000000 +0000",
        );

        let author = parse_author_identity(&data).unwrap();
        assert_eq!(author.name, b"Name");
        // first `<` to last `>`: "first> <second"
        assert_eq!(author.email, b"first> <second");
    }

    #[test]
    fn no_author_header() {
        let data = b"tree aaaa\ncommitter Bob <bob@x.com> 100 +0000\n\nmsg\n";
        assert!(parse_author_identity(data).is_none());
        assert!(parse_committer_identity(data).is_some());
    }

    #[test]
    fn no_committer_header() {
        let data = b"tree aaaa\nauthor Alice <alice@x.com> 100 +0000\n\nmsg\n";
        assert!(parse_author_identity(data).is_some());
        assert!(parse_committer_identity(data).is_none());
    }

    #[test]
    fn header_after_blank_line_ignored() {
        // Author header appears in the message body — should not be found.
        let data = b"tree aaaa\n\nauthor Fake <fake@x.com> 100 +0000\n";
        assert!(parse_author_identity(data).is_none());
    }

    #[test]
    fn trim_bytes_works() {
        assert_eq!(trim_bytes(b"  hello  "), b"hello");
        assert_eq!(trim_bytes(b"hello"), b"hello");
        assert_eq!(trim_bytes(b"  "), b"");
        assert_eq!(trim_bytes(b""), b"");
        assert_eq!(trim_bytes(b"\t\n x \n\t"), b"x");
    }
}

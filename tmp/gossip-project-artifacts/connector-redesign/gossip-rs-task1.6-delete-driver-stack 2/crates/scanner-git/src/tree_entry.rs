//! Git tree entry parsing.
//!
//! Parses raw tree object bytes (decompressed, no object header) into entries.
//! Designed for streaming iteration without per-entry allocation.
//!
//! # Tree Object Format
//!
//! A tree object contains zero or more entries, each with format:
//! ```text
//! <mode> SP <name> NUL <oid>
//! ```
//!
//! Where:
//! - `<mode>`: ASCII octal digits (e.g., "100644", "40000")
//! - `SP`: Single space byte (0x20)
//! - `<name>`: Entry name bytes (non-empty, no slashes, no NUL)
//! - `NUL`: Single NUL byte (0x00)
//! - `<oid>`: Raw OID bytes (20 for SHA-1, 32 for SHA-256)
//!
//! # Entry Modes
//!
//! Git uses a subset of Unix mode bits. The high 4 bits encode object type:
//!
//! | Type Mask | Type | Canonical Mode(s) |
//! |-----------|------|-------------------|
//! | 0o040000 | Tree | 40000 |
//! | 0o100000 | Blob | 100644, 100755 |
//! | 0o120000 | Symlink | 120000 |
//! | 0o160000 | Gitlink | 160000 |
//!
//! Historical Git versions and third-party tools may create non-canonical
//! blob modes (e.g., 100664, 100600). This parser handles them by checking
//! the type mask and executable bit, rather than exact mode matching.
//!
//! # Iterator Behavior
//!
//! The iterator behaves as fused: after returning an error, all subsequent
//! calls to `next()` return `None`. This prevents garbage results from
//! partially parsed state. (Note: `FusedIterator` is not formally
//! implemented; the fusing behavior is enforced by an internal flag.)
//!
//! # Streaming vs. Complete Buffers
//!
//! `TreeEntryIter` expects a complete tree payload; if the last entry is
//! truncated it is treated as corruption. For streaming callers that may
//! refill a buffer mid-entry, use `parse_entry` directly and handle the
//! `ParseOutcome::Incomplete` case.
//!
//! # Strictness
//!
//! The parser rejects malformed entries:
//! - Empty names
//! - Names containing `/`
//! - Non-octal mode digits
//! - Truncated OIDs (treated as "incomplete" until EOF)
//!
//! Entry ordering and duplicate names are not validated here; those are
//! handled at higher layers (tree diffing and traversal).
//!
//! # Performance
//!
//! Delimiter scanning uses the `memchr` crate for SIMD-accelerated byte
//! searching (NEON on aarch64, SSE2/AVX2 on x86-64).

use super::errors::TreeDiffError;
use super::object_id::OidBytes;

/// Classification of a tree entry's type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryKind {
    /// Subdirectory (mode 040000).
    Tree,
    /// Regular file (mode 100644 or similar without execute bit).
    RegularFile,
    /// Executable file (mode 100755 or similar with execute bit).
    ExecutableFile,
    /// Symbolic link (mode 120000).
    Symlink,
    /// Gitlink/submodule (mode 160000).
    Gitlink,
    /// Unknown or invalid mode (type bits don't match any known type).
    Unknown,
}

impl EntryKind {
    /// Returns true if this entry is a tree (directory).
    #[inline]
    #[must_use]
    pub const fn is_tree(self) -> bool {
        matches!(self, Self::Tree)
    }

    /// Returns true if this entry is blob-like (content we should scan).
    ///
    /// Includes regular files, executables, and symlinks.
    /// Excludes trees (directories) and gitlinks (submodules).
    #[inline]
    #[must_use]
    pub const fn is_blob_like(self) -> bool {
        matches!(
            self,
            Self::RegularFile | Self::ExecutableFile | Self::Symlink
        )
    }

    /// Returns true if this entry is a regular or executable file.
    #[inline]
    #[must_use]
    pub const fn is_file(self) -> bool {
        matches!(self, Self::RegularFile | Self::ExecutableFile)
    }
}

/// A parsed tree entry (zero-copy reference into tree bytes).
///
/// All byte slices borrow from the tree buffer supplied to `TreeEntryIter`.
/// They are only valid as long as that buffer lives.
#[derive(Clone, Copy, Debug)]
pub struct TreeEntry<'a> {
    /// Entry name (without any path prefix).
    /// Guaranteed non-empty and slash-free.
    pub name: &'a [u8],
    /// Raw OID bytes (20 or 32 bytes depending on repo format).
    pub oid_bytes: &'a [u8],
    /// Classified entry kind.
    pub kind: EntryKind,
    /// Raw mode value (for preservation if needed).
    pub mode: u32,
    /// OID length from iterator configuration (20 or 32).
    /// Used for accurate error reporting in `oid()`.
    oid_len: u8,
}

impl<'a> TreeEntry<'a> {
    /// Returns the OID as `OidBytes`.
    ///
    /// # Errors
    ///
    /// Returns an error if the OID length is invalid (not 20 or 32).
    /// This should not happen for entries from a valid `TreeEntryIter`,
    /// which guarantees `oid_bytes.len() == oid_len`.
    pub fn oid(&self) -> Result<OidBytes, TreeDiffError> {
        OidBytes::try_from_slice(self.oid_bytes).ok_or(TreeDiffError::InvalidOidLength {
            len: self.oid_bytes.len(),
            expected: self.oid_len as usize,
        })
    }

    /// Returns the configured OID length (20 or 32).
    #[inline]
    #[must_use]
    pub const fn oid_len(&self) -> u8 {
        self.oid_len
    }
}

/// Parsed tree entry offsets relative to the provided input slice.
///
/// `entry_len` is the number of bytes to advance from the start of the slice
/// to reach the next entry.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ParsedTreeEntry {
    pub(crate) name_start: usize,
    pub(crate) name_end: usize,
    pub(crate) oid_start: usize,
    pub(crate) oid_end: usize,
    pub(crate) kind: EntryKind,
    pub(crate) mode: u32,
    pub(crate) entry_len: usize,
}

impl ParsedTreeEntry {
    /// Materializes a borrowed `TreeEntry` from the parsed offsets.
    ///
    /// `data` must be the same buffer that the entry was parsed from, and
    /// must not have been mutated or reallocated since parsing (offsets are
    /// byte-exact).
    pub(crate) fn materialize<'a>(&self, data: &'a [u8], oid_len: u8) -> TreeEntry<'a> {
        TreeEntry {
            name: &data[self.name_start..self.name_end],
            oid_bytes: &data[self.oid_start..self.oid_end],
            kind: self.kind,
            mode: self.mode,
            oid_len,
        }
    }

    /// Shifts offsets forward when a sliding window advances.
    pub(crate) fn offset_by(&mut self, delta: usize) {
        // Used when a sliding window is advanced while parsing a stream.
        self.name_start = self.name_start.saturating_add(delta);
        self.name_end = self.name_end.saturating_add(delta);
        self.oid_start = self.oid_start.saturating_add(delta);
        self.oid_end = self.oid_end.saturating_add(delta);
    }
}

/// Parsing stage that can run out of bytes when streaming.
#[derive(Clone, Copy, Debug)]
pub(crate) enum ParseStage {
    Mode,
    Name,
    Oid,
}

impl ParseStage {
    /// Returns a static error detail string for incomplete parsing.
    pub(crate) const fn error_detail(self) -> &'static str {
        match self {
            Self::Mode => "unexpected end while parsing mode",
            Self::Name => "unexpected end while parsing name",
            Self::Oid => "unexpected end while parsing OID",
        }
    }
}

/// Result of parsing a tree entry from a byte slice.
///
/// `Incomplete` indicates the slice ended mid-entry; callers should supply
/// more bytes (or treat as corruption at EOF).
#[derive(Clone, Copy, Debug)]
pub(crate) enum ParseOutcome {
    Complete(ParsedTreeEntry),
    Incomplete(ParseStage),
}

/// Iterator over tree entries in a raw tree object.
///
/// Yields entries in tree order (already sorted by Git).
/// Does not allocate; references into the source bytes.
///
/// # Fused Behavior
///
/// After returning an error, all subsequent calls return `None`.
/// This prevents garbage results from partial state.
#[derive(Clone, Debug)]
pub struct TreeEntryIter<'a> {
    /// Full tree object bytes (not shrunk; we advance `pos` instead).
    data: &'a [u8],
    /// Current position in data. Set to `data.len()` to fuse after error.
    pos: usize,
    /// OID length (20 for SHA-1, 32 for SHA-256).
    oid_len: u8,
}

impl<'a> TreeEntryIter<'a> {
    /// Creates a new iterator over tree object bytes.
    ///
    /// # Arguments
    ///
    /// * `data` - Raw tree object payload (decompressed, no header)
    /// * `oid_len` - OID length in bytes (20 or 32)
    ///
    /// # Panics
    ///
    /// Panics if `oid_len` is not 20 or 32.
    #[must_use]
    pub fn new(data: &'a [u8], oid_len: usize) -> Self {
        assert!(
            oid_len == 20 || oid_len == 32,
            "OID length must be 20 or 32"
        );
        Self {
            data,
            pos: 0,
            oid_len: oid_len as u8,
        }
    }

    /// Returns the current byte position (for diagnostics).
    #[inline]
    #[must_use]
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Returns the total data length.
    #[inline]
    #[must_use]
    pub fn data_len(&self) -> usize {
        self.data.len()
    }

    /// Returns true if the iterator is exhausted or fused due to error.
    #[inline]
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.pos >= self.data.len()
    }

    /// Fuses the iterator (marks it as finished).
    ///
    /// Called on error to prevent garbage results from partial state.
    #[inline]
    fn fuse(&mut self) {
        self.pos = self.data.len();
    }

    /// Parses the next entry, advancing the position.
    ///
    /// Returns `Ok(None)` at end of data.
    /// Returns `Err` on malformed data (and fuses the iterator).
    ///
    /// After an error, `next_entry()` and `Iterator::next()` will always
    /// return `None` to avoid exposing partially parsed state.
    pub fn next_entry(&mut self) -> Result<Option<TreeEntry<'a>>, TreeDiffError> {
        if self.pos >= self.data.len() {
            return Ok(None);
        }

        let remaining = &self.data[self.pos..];
        let outcome = match parse_entry(remaining, self.oid_len) {
            Ok(outcome) => outcome,
            Err(err) => {
                self.fuse();
                return Err(err);
            }
        };

        match outcome {
            ParseOutcome::Complete(parsed) => {
                let entry = parsed.materialize(remaining, self.oid_len);
                self.pos += parsed.entry_len;
                Ok(Some(entry))
            }
            ParseOutcome::Incomplete(stage) => {
                self.fuse();
                Err(TreeDiffError::CorruptTree {
                    detail: stage.error_detail(),
                })
            }
        }
    }
}

impl<'a> Iterator for TreeEntryIter<'a> {
    type Item = Result<TreeEntry<'a>, TreeDiffError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.next_entry() {
            Ok(Some(entry)) => Some(Ok(entry)),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        }
    }
}

/// Parses a single tree entry from the start of `data`.
///
/// The slice must start at an entry boundary. Incomplete data yields
/// `ParseOutcome::Incomplete` so streaming callers can refill buffers.
/// Callers should only treat `Incomplete` as corruption when they are
/// at EOF.
///
/// # Errors
/// Returns `TreeDiffError::CorruptTree` if the mode digits are invalid or
/// if the entry name is empty or contains a slash.
pub(crate) fn parse_entry(data: &[u8], oid_len: u8) -> Result<ParseOutcome, TreeDiffError> {
    if data.is_empty() {
        return Ok(ParseOutcome::Incomplete(ParseStage::Mode));
    }

    // Parse mode (ASCII octal digits until space)
    let space_offset = match memchr_space(data) {
        Some(idx) => idx,
        None => return Ok(ParseOutcome::Incomplete(ParseStage::Mode)),
    };

    let mode_bytes = &data[..space_offset];
    let mode = parse_octal_mode(mode_bytes).ok_or(TreeDiffError::CorruptTree {
        detail: "invalid mode digits",
    })?;

    // Parse name (bytes until NUL)
    let after_space = &data[space_offset + 1..];
    let nul_offset = match memchr_nul(after_space) {
        Some(idx) => idx,
        None => return Ok(ParseOutcome::Incomplete(ParseStage::Name)),
    };

    let name = &after_space[..nul_offset];
    if name.is_empty() {
        return Err(TreeDiffError::CorruptTree {
            detail: "empty entry name",
        });
    }

    if memchr_slash(name).is_some() {
        return Err(TreeDiffError::CorruptTree {
            detail: "entry name contains slash",
        });
    }

    let oid_len = oid_len as usize;
    let after_nul = &after_space[nul_offset + 1..];
    if after_nul.len() < oid_len {
        return Ok(ParseOutcome::Incomplete(ParseStage::Oid));
    }

    let oid_start = space_offset + 1 + nul_offset + 1;
    let oid_end = oid_start + oid_len;
    let kind = classify_mode(mode);

    Ok(ParseOutcome::Complete(ParsedTreeEntry {
        name_start: space_offset + 1,
        name_end: space_offset + 1 + nul_offset,
        oid_start,
        oid_end,
        kind,
        mode,
        entry_len: oid_end,
    }))
}

// Delimiter scanning helpers — SIMD-accelerated via the `memchr` crate.

#[inline]
fn memchr_space(haystack: &[u8]) -> Option<usize> {
    ::memchr::memchr(b' ', haystack)
}

#[inline]
fn memchr_nul(haystack: &[u8]) -> Option<usize> {
    ::memchr::memchr(b'\0', haystack)
}

#[inline]
fn memchr_slash(haystack: &[u8]) -> Option<usize> {
    ::memchr::memchr(b'/', haystack)
}

// Mode parsing and classification

/// Parses ASCII octal mode bytes into a u32.
///
/// Returns `None` if bytes are empty, too long (>7), or contain non-octal digits.
///
/// # Why 7 bytes max?
///
/// The maximum valid Git mode is 0o160000 (6 digits). With 7 octal digits,
/// the maximum value is 0o7777777 = 2,097,151 which fits in u32. This gives
/// us headroom without overflow risk, so we can use shift-add without checked
/// arithmetic.
#[inline]
fn parse_octal_mode(bytes: &[u8]) -> Option<u32> {
    if bytes.is_empty() || bytes.len() > 7 {
        return None;
    }

    let mut mode: u32 = 0;
    for &b in bytes {
        let digit = b.wrapping_sub(b'0');
        if digit > 7 {
            return None;
        }
        mode = (mode << 3) | u32::from(digit);
    }

    Some(mode)
}

/// Classifies a mode value into an entry kind.
///
/// Uses mask-based classification for robustness with historical non-canonical
/// modes (e.g., 100664, 100600 created by older Git versions).
///
/// The type is determined by the high 4 bits (masked with 0o170000):
/// - 0o040000: Tree
/// - 0o100000: Blob (executable if user-execute bit set)
/// - 0o120000: Symlink
/// - 0o160000: Gitlink
#[inline]
fn classify_mode(mode: u32) -> EntryKind {
    const S_IFMT: u32 = 0o170000;

    match mode & S_IFMT {
        0o040000 => EntryKind::Tree,
        0o120000 => EntryKind::Symlink,
        0o160000 => EntryKind::Gitlink,
        0o100000 => {
            if (mode & 0o100) != 0 {
                EntryKind::ExecutableFile
            } else {
                EntryKind::RegularFile
            }
        }
        _ => EntryKind::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(mode: &str, name: &str, oid: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(mode.as_bytes());
        out.push(b' ');
        out.extend_from_slice(name.as_bytes());
        out.push(0);
        out.extend_from_slice(oid);
        out
    }

    #[test]
    fn parses_single_entry() {
        let oid = [0x11; 20];
        let data = make_entry("100644", "file.txt", &oid);
        let mut iter = TreeEntryIter::new(&data, 20);

        let entry = iter.next_entry().unwrap().unwrap();
        assert_eq!(entry.name, b"file.txt");
        assert_eq!(entry.oid_bytes, &oid);
        assert_eq!(entry.kind, EntryKind::RegularFile);
        assert!(iter.next_entry().unwrap().is_none());
    }

    #[test]
    fn parses_multiple_entries() {
        let mut data = Vec::new();
        data.extend(make_entry("100644", "a.txt", &[0x11; 20]));
        data.extend(make_entry("100644", "b.txt", &[0x22; 20]));

        let mut iter = TreeEntryIter::new(&data, 20);
        let a = iter.next_entry().unwrap().unwrap();
        let b = iter.next_entry().unwrap().unwrap();

        assert_eq!(a.name, b"a.txt");
        assert_eq!(b.name, b"b.txt");
        assert!(iter.next_entry().unwrap().is_none());
    }

    #[test]
    fn rejects_empty_name() {
        let mut data = Vec::new();
        data.extend_from_slice(b"100644 ");
        data.push(0);
        data.extend_from_slice(&[0x11; 20]);

        let mut iter = TreeEntryIter::new(&data, 20);
        let err = iter.next_entry().unwrap_err();
        assert!(matches!(err, TreeDiffError::CorruptTree { .. }));
        assert!(iter.next_entry().unwrap().is_none());
    }

    #[test]
    fn rejects_slash_in_name() {
        let data = make_entry("100644", "dir/file", &[0x11; 20]);
        let mut iter = TreeEntryIter::new(&data, 20);
        let err = iter.next_entry().unwrap_err();
        assert!(matches!(err, TreeDiffError::CorruptTree { .. }));
        assert!(iter.next_entry().unwrap().is_none());
    }

    #[test]
    fn rejects_bad_mode_digits() {
        let mut data = Vec::new();
        data.extend_from_slice(b"10a644 ");
        data.extend_from_slice(b"file");
        data.push(0);
        data.extend_from_slice(&[0x11; 20]);

        let mut iter = TreeEntryIter::new(&data, 20);
        let err = iter.next_entry().unwrap_err();
        assert!(matches!(err, TreeDiffError::CorruptTree { .. }));
    }

    #[test]
    fn rejects_truncated_oid() {
        let mut data = Vec::new();
        data.extend_from_slice(b"100644 file");
        data.push(0);
        data.extend_from_slice(&[0x11; 10]);

        let mut iter = TreeEntryIter::new(&data, 20);
        let err = iter.next_entry().unwrap_err();
        assert!(matches!(err, TreeDiffError::CorruptTree { .. }));
    }

    #[test]
    fn classifies_modes() {
        let mut data = Vec::new();
        data.extend(make_entry("100644", "file", &[0x11; 20]));
        data.extend(make_entry("100755", "exec", &[0x22; 20]));
        data.extend(make_entry("120000", "link", &[0x33; 20]));
        data.extend(make_entry("160000", "gitlink", &[0x44; 20]));
        data.extend(make_entry("40000", "tree", &[0x55; 20]));

        let mut iter = TreeEntryIter::new(&data, 20);
        assert_eq!(iter.next().unwrap().unwrap().kind, EntryKind::RegularFile);
        assert_eq!(
            iter.next().unwrap().unwrap().kind,
            EntryKind::ExecutableFile
        );
        assert_eq!(iter.next().unwrap().unwrap().kind, EntryKind::Symlink);
        assert_eq!(iter.next().unwrap().unwrap().kind, EntryKind::Gitlink);
        assert_eq!(iter.next().unwrap().unwrap().kind, EntryKind::Tree);
    }
}

//! Pack byte reader abstraction for deterministic I/O.
//!
//! The reader exposes a `read_at` interface so simulation can inject
//! short reads, interruptions, and corruption without relying on OS I/O.
//! Implementations should be deterministic for identical inputs.

use std::fmt;

use super::bytes::BytesView;

/// Errors produced by pack readers.
#[derive(Debug)]
pub enum PackReadError {
    /// The requested read exceeded the available range.
    OutOfRange { offset: u64, len: usize },
    /// The reader returned fewer bytes than requested.
    ShortRead { expected: usize, got: usize },
    /// Reader-specific I/O error.
    Io(String),
}

impl fmt::Display for PackReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutOfRange { offset, len } => {
                write!(f, "read out of range at {offset} (len {len})")
            }
            Self::ShortRead { expected, got } => {
                write!(f, "short read: expected {expected}, got {got}")
            }
            Self::Io(msg) => write!(f, "pack read error: {msg}"),
        }
    }
}

impl std::error::Error for PackReadError {}

/// Read-only pack reader interface.
pub trait PackReader {
    /// Total length in bytes.
    fn len(&self) -> u64;

    /// Returns true if the reader is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Read bytes starting at `offset` into `dst`.
    ///
    /// Returns the number of bytes read (may be less than `dst.len()`).
    /// Implementations should return `OutOfRange` when `offset > len()`.
    fn read_at(&mut self, offset: u64, dst: &mut [u8]) -> Result<usize, PackReadError>;

    /// Fill `dst` completely or return a `ShortRead` error.
    ///
    /// This helper performs a single `read_at` call to allow deterministic
    /// fault injection (short reads map to a single failure).
    /// If `dst` is empty, this returns `Ok(())` without calling `read_at`.
    fn read_exact_at(&mut self, offset: u64, dst: &mut [u8]) -> Result<(), PackReadError> {
        if dst.is_empty() {
            return Ok(());
        }
        let got = self.read_at(offset, dst)?;
        if got != dst.len() {
            return Err(PackReadError::ShortRead {
                expected: dst.len(),
                got,
            });
        }
        Ok(())
    }
}

/// Pack reader over an in-memory slice.
#[derive(Debug)]
pub struct SlicePackReader<'a> {
    bytes: &'a [u8],
}

impl<'a> SlicePackReader<'a> {
    /// Wrap a slice for pack reads.
    #[must_use]
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }
}

impl PackReader for SlicePackReader<'_> {
    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }

    fn read_at(&mut self, offset: u64, dst: &mut [u8]) -> Result<usize, PackReadError> {
        let offset = offset as usize;
        if offset > self.bytes.len() {
            return Err(PackReadError::OutOfRange {
                offset: offset as u64,
                len: dst.len(),
            });
        }
        let available = &self.bytes[offset..];
        let n = available.len().min(dst.len());
        dst[..n].copy_from_slice(&available[..n]);
        Ok(n)
    }
}

impl PackReader for BytesView {
    fn len(&self) -> u64 {
        BytesView::len(self) as u64
    }

    fn read_at(&mut self, offset: u64, dst: &mut [u8]) -> Result<usize, PackReadError> {
        let offset = offset as usize;
        let bytes = self.as_slice();
        if offset > bytes.len() {
            return Err(PackReadError::OutOfRange {
                offset: offset as u64,
                len: dst.len(),
            });
        }
        let available = &bytes[offset..];
        let n = available.len().min(dst.len());
        dst[..n].copy_from_slice(&available[..n]);
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slice_reader_reads() {
        let mut reader = SlicePackReader::new(&[1u8, 2, 3, 4]);
        let mut buf = [0u8; 2];
        let n = reader.read_at(1, &mut buf).expect("read");
        assert_eq!(n, 2);
        assert_eq!(buf, [2, 3]);
    }

    #[test]
    fn slice_reader_short_read() {
        let mut reader = SlicePackReader::new(&[1u8, 2]);
        let mut buf = [0u8; 4];
        let got = reader.read_at(0, &mut buf).expect("read");
        assert_eq!(got, 2);
    }
}

//! Spill run reader.
//!
//! Reads `RunRecord`s from a spill run file with strict validation. The
//! reader trusts the header's `record_count` and stops after that many
//! records, returning `Ok(None)` thereafter.

use std::io::Read;

use super::errors::SpillError;
use super::object_id::OidBytes;
use super::run_format::{RunContext, RunHeader, RunRecord};
use super::tree_candidate::ChangeKind;

/// Spill run reader.
///
/// The reader enforces a maximum path length to avoid unbounded allocation.
pub struct RunReader<R: Read> {
    reader: R,
    header: RunHeader,
    remaining: u32,
    max_path_len: u16,
}

impl<R: Read> RunReader<R> {
    /// Creates a new run reader and validates the header.
    ///
    /// # Errors
    /// Returns `InvalidRunHeader` on bad magic/version/oid length and
    /// `Io` on unexpected EOF during header read.
    pub fn new(mut reader: R, max_path_len: u16) -> Result<Self, SpillError> {
        let mut header_bytes = [0u8; 12];
        reader
            .read_exact(&mut header_bytes)
            .map_err(SpillError::from)?;
        let header = RunHeader::decode(&header_bytes)?;
        Ok(Self {
            reader,
            remaining: header.record_count,
            header,
            max_path_len,
        })
    }

    /// Returns the parsed header.
    #[must_use]
    pub const fn header(&self) -> RunHeader {
        self.header
    }

    /// Returns the maximum allowed path length.
    #[must_use]
    pub const fn max_path_len(&self) -> u16 {
        self.max_path_len
    }

    /// Reads the next record into the provided scratch buffer.
    ///
    /// The supplied `record` is overwritten in-place; its path buffer is
    /// resized to the exact encoded length.
    ///
    /// Returns `Ok(false)` when the run is exhausted.
    pub fn read_next_into(&mut self, record: &mut RunRecord) -> Result<bool, SpillError> {
        if self.remaining == 0 {
            return Ok(false);
        }

        let oid = self.read_oid()?;
        let commit_id = self.read_u32()?;
        let parent_idx = self.read_u8()?;
        let change_kind = match self.read_u8()? {
            1 => ChangeKind::Add,
            2 => ChangeKind::Modify,
            _ => {
                return Err(SpillError::CorruptRunFile {
                    detail: "invalid change kind",
                })
            }
        };
        let ctx_flags = self.read_u16()?;
        let cand_flags = self.read_u16()?;
        let path_len = self.read_u16()?;
        if path_len > self.max_path_len {
            return Err(SpillError::RunPathTooLong {
                len: path_len as usize,
                max: self.max_path_len as usize,
            });
        }

        record.oid = oid;
        record.ctx = RunContext {
            commit_id,
            parent_idx,
            change_kind,
            ctx_flags,
            cand_flags,
        };
        record.path.clear();
        record.path.resize(path_len as usize, 0);
        self.read_exact(&mut record.path)?;

        self.remaining -= 1;
        Ok(true)
    }

    /// Reads the next record, or `Ok(None)` at end of run.
    ///
    /// # Errors
    /// Returns `CorruptRunFile` on unexpected EOF or malformed fields, and
    /// `RunPathTooLong` if the path exceeds `max_path_len`.
    pub fn next_record(&mut self) -> Result<Option<RunRecord>, SpillError> {
        let mut record = RunRecord::scratch(self.header.oid_len, self.max_path_len as usize);
        if !self.read_next_into(&mut record)? {
            return Ok(None);
        }
        Ok(Some(record))
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), SpillError> {
        self.reader
            .read_exact(buf)
            .map_err(|_| SpillError::CorruptRunFile {
                detail: "unexpected EOF",
            })
    }

    fn read_u8(&mut self) -> Result<u8, SpillError> {
        let mut buf = [0u8; 1];
        self.read_exact(&mut buf)?;
        Ok(buf[0])
    }

    fn read_u16(&mut self) -> Result<u16, SpillError> {
        let mut buf = [0u8; 2];
        self.read_exact(&mut buf)?;
        Ok(u16::from_be_bytes(buf))
    }

    fn read_u32(&mut self) -> Result<u32, SpillError> {
        let mut buf = [0u8; 4];
        self.read_exact(&mut buf)?;
        Ok(u32::from_be_bytes(buf))
    }

    fn read_oid(&mut self) -> Result<OidBytes, SpillError> {
        let mut buf = [0u8; OidBytes::MAX_LEN as usize];
        let len = self.header.oid_len as usize;
        self.read_exact(&mut buf[..len])?;
        OidBytes::try_from_slice(&buf[..len]).ok_or(SpillError::InvalidRunHeader)
    }
}

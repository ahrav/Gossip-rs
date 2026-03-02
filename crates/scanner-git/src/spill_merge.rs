//! K-way merge of spill runs.
//!
//! Merges sorted spill runs into a single sorted stream with duplicate
//! records removed. The merge preserves the canonical ordering defined
//! by `RunRecord`.
//!
//! # Requirements
//! - Each input run must already be sorted by `RunRecord` ordering.
//! - All runs must use the same OID length.
//!
//! # Dedupe
//! Duplicate records across runs become adjacent in the merged order, so the
//! merger only compares against the last emitted record.

use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::io::Read;

use super::errors::SpillError;
use super::run_format::{RunContext, RunHeader, RunRecord};
use super::run_reader::RunReader;

/// K-way merge reader for spill runs.
///
/// The merger performs dedupe by suppressing adjacent equal records in the
/// merged order.
pub struct RunMerger<R: Read> {
    /// Per-run readers (one cursor per input run).
    cursors: Vec<RunCursor<R>>,
    /// Min-heap of the next record from each cursor.
    heap: BinaryHeap<HeapItem>,
    /// Key of the last emitted record for dedupe.
    last: Option<RunRecordKey>,
    /// Current record returned to the caller (reused across calls).
    current: Option<RunRecord>,
    /// Cursor index that produced `current`; advanced on the next call.
    pending_cursor: Option<usize>,
    /// Shared OID length for all runs.
    oid_len: u8,
}

impl<R: Read> RunMerger<R> {
    /// Creates a new merger from run readers.
    ///
    /// Each reader contributes a single scratch record to minimize per-record
    /// allocations; records are reused as the cursor advances.
    ///
    /// # Errors
    /// Returns `OidLengthMismatch` if run headers disagree on OID length.
    pub fn new(readers: Vec<RunReader<R>>) -> Result<Self, SpillError> {
        let mut cursors = Vec::with_capacity(readers.len());
        let mut heap = BinaryHeap::new();
        let mut oid_len = None;

        for (idx, reader) in readers.into_iter().enumerate() {
            let header = reader.header();
            match oid_len {
                None => oid_len = Some(header.oid_len),
                Some(len) if len != header.oid_len => {
                    return Err(SpillError::OidLengthMismatch {
                        got: header.oid_len,
                        expected: len,
                    })
                }
                _ => {}
            }

            let mut cursor = RunCursor { reader };
            let scratch = RunRecord::scratch(header.oid_len, cursor.reader.max_path_len() as usize);
            if let Some(record) = cursor.advance_with(scratch)? {
                heap.push(HeapItem {
                    record,
                    cursor: idx,
                });
            }
            cursors.push(cursor);
        }

        Ok(Self {
            cursors,
            heap,
            last: None,
            current: None,
            pending_cursor: None,
            oid_len: oid_len.unwrap_or(20),
        })
    }

    /// Returns the OID length for the merged runs.
    #[must_use]
    pub const fn oid_len(&self) -> u8 {
        self.oid_len
    }

    /// Returns the next unique record, or `Ok(None)` when exhausted.
    ///
    /// The returned reference is valid until the next call, when the internal
    /// scratch record may be reused.
    ///
    /// The dedupe logic only compares against the last emitted record, which
    /// is sufficient because inputs are globally ordered.
    pub fn next_unique(&mut self) -> Result<Option<&RunRecord>, SpillError> {
        if let Some(cursor_idx) = self.pending_cursor.take() {
            if let Some(record) = self.current.take() {
                if let Some(next) = self.cursors[cursor_idx].advance_with(record)? {
                    self.heap.push(HeapItem {
                        record: next,
                        cursor: cursor_idx,
                    });
                }
            }
        }

        while let Some(item) = self.heap.pop() {
            let cursor_idx = item.cursor;
            let record = item.record;

            if let Some(last) = &self.last {
                if last.matches(&record) {
                    if let Some(next) = self.cursors[cursor_idx].advance_with(record)? {
                        self.heap.push(HeapItem {
                            record: next,
                            cursor: cursor_idx,
                        });
                    }
                    continue;
                }
            }

            match &mut self.last {
                Some(last) => last.update_from(&record),
                None => self.last = Some(RunRecordKey::from_record(&record)),
            }

            self.current = Some(record);
            self.pending_cursor = Some(cursor_idx);
            return Ok(self.current.as_ref());
        }

        Ok(None)
    }
}

struct RunCursor<R: Read> {
    /// Reader for a single run (expects sorted records).
    reader: RunReader<R>,
}

impl<R: Read> RunCursor<R> {
    /// Reads the next record into the provided buffer and returns it.
    ///
    /// The buffer is reused by the merger to avoid per-record allocations.
    fn advance_with(&mut self, mut record: RunRecord) -> Result<Option<RunRecord>, SpillError> {
        if self.reader.read_next_into(&mut record)? {
            Ok(Some(record))
        } else {
            Ok(None)
        }
    }
}

#[derive(Debug)]
struct RunRecordKey {
    oid: super::object_id::OidBytes,
    ctx: RunContext,
    path: Vec<u8>,
}

impl RunRecordKey {
    /// Creates a key that owns the path bytes for dedupe comparisons.
    fn from_record(record: &RunRecord) -> Self {
        let mut path = Vec::with_capacity(record.path.len());
        path.extend_from_slice(&record.path);
        Self {
            oid: record.oid,
            ctx: record.ctx,
            path,
        }
    }

    /// Returns true if the record matches this key exactly.
    fn matches(&self, record: &RunRecord) -> bool {
        self.oid == record.oid && self.ctx == record.ctx && self.path == record.path
    }

    /// Updates the key to match the provided record.
    fn update_from(&mut self, record: &RunRecord) {
        self.oid = record.oid;
        self.ctx = record.ctx;
        self.path.clear();
        self.path.extend_from_slice(&record.path);
    }
}

#[derive(Debug)]
struct HeapItem {
    record: RunRecord,
    cursor: usize,
}

impl Ord for HeapItem {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse order for min-heap behavior.
        // Tie-break on cursor index for deterministic ordering across runs.
        other
            .record
            .cmp(&self.record)
            .then_with(|| other.cursor.cmp(&self.cursor))
    }
}

impl PartialOrd for HeapItem {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for HeapItem {
    fn eq(&self, other: &Self) -> bool {
        self.record == other.record && self.cursor == other.cursor
    }
}

impl Eq for HeapItem {}

/// Convenience helper to merge runs fully into memory.
///
/// This is suitable for tests or small repositories; large runs should be
/// streamed instead.
pub fn merge_all<R: Read>(readers: Vec<RunReader<R>>) -> Result<Vec<RunRecord>, SpillError> {
    let mut merger = RunMerger::new(readers)?;
    let mut out = Vec::new();
    while let Some(record) = merger.next_unique()? {
        out.push(record.clone());
    }
    Ok(out)
}

/// Validates headers for a set of run readers.
///
/// Returns the shared OID length if all headers are consistent.
/// Empty input defaults to 20.
pub fn validate_headers(headers: &[RunHeader]) -> Result<u8, SpillError> {
    let mut oid_len = None;
    for header in headers {
        match oid_len {
            None => oid_len = Some(header.oid_len),
            Some(len) if len != header.oid_len => {
                return Err(SpillError::OidLengthMismatch {
                    got: header.oid_len,
                    expected: len,
                })
            }
            _ => {}
        }
    }
    Ok(oid_len.unwrap_or(20))
}

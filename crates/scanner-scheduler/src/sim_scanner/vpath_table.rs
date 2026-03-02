//! Virtual path table for simulation runs.
//!
//! This keeps a deterministic, byte-budgeted mapping between raw path bytes
//! and `FileId`s so archive entries can be treated like first-class scan
//! objects without relying on OS paths.
//!
//! Invariants:
//! - Root IDs are assigned from a low, monotonically increasing range.
//! - Virtual IDs are assigned from a high-bit namespace (`0x8000_0000+`).
//! - The table is append-only; duplicate paths reuse the existing ID.
//! - Insertions fail once the byte budget is exhausted or an ID collides.

use std::collections::BTreeMap;

use crate::FileId;

const VIRTUAL_FILE_ID_BASE: u32 = 0x8000_0000;
const VIRTUAL_FILE_ID_MASK: u32 = 0x7FFF_FFFF;

/// Append-only path table with a byte budget.
///
/// Uses `BTreeMap` to keep deterministic ordering for artifact output.
#[derive(Clone, Debug)]
pub struct VirtualPathTable {
    bytes_cap: usize,
    bytes_used: usize,
    by_id: BTreeMap<u32, Vec<u8>>,
    by_path: BTreeMap<Vec<u8>, u32>,
    next_root_id: u32,
    next_virtual_id: u32,
}

impl VirtualPathTable {
    /// Create a new table with a maximum total byte budget.
    pub fn new(bytes_cap: usize) -> Self {
        Self {
            bytes_cap,
            bytes_used: 0,
            by_id: BTreeMap::new(),
            by_path: BTreeMap::new(),
            next_root_id: 0,
            next_virtual_id: VIRTUAL_FILE_ID_BASE,
        }
    }

    #[inline]
    pub fn bytes_cap(&self) -> usize {
        self.bytes_cap
    }

    #[inline]
    pub fn bytes_used(&self) -> usize {
        self.bytes_used
    }

    /// Insert a root file path (low-id namespace).
    ///
    /// Returns `None` if the byte budget is exhausted or an ID collision occurs.
    pub fn try_insert_root(&mut self, path: &[u8]) -> Option<FileId> {
        self.try_insert(path, false)
    }

    /// Insert a virtual path (high-id namespace for archive entries).
    ///
    /// Returns `None` if the byte budget is exhausted or an ID collision occurs.
    pub fn try_insert_virtual(&mut self, path: &[u8]) -> Option<FileId> {
        self.try_insert(path, true)
    }

    /// Look up a file id by path bytes.
    pub fn file_id_for_path(&self, path: &[u8]) -> Option<FileId> {
        self.by_path.get(path).copied().map(FileId)
    }

    /// Retrieve path bytes for a file id.
    pub fn path_bytes(&self, id: FileId) -> Option<&[u8]> {
        self.by_id.get(&id.0).map(|v| v.as_slice())
    }

    fn try_insert(&mut self, path: &[u8], virtual_id: bool) -> Option<FileId> {
        if let Some(id) = self.by_path.get(path) {
            return Some(FileId(*id));
        }

        let needed = path.len();
        if self.bytes_used.saturating_add(needed) > self.bytes_cap {
            return None;
        }

        let id = if virtual_id {
            let id = self.next_virtual_id;
            let next = (id.wrapping_add(1) & VIRTUAL_FILE_ID_MASK) | VIRTUAL_FILE_ID_BASE;
            self.next_virtual_id = next;
            id
        } else {
            let id = self.next_root_id;
            self.next_root_id = self.next_root_id.wrapping_add(1);
            id
        };

        if self.by_id.contains_key(&id) {
            return None;
        }

        self.bytes_used = self.bytes_used.saturating_add(needed);
        self.by_id.insert(id, path.to_vec());
        self.by_path.insert(path.to_vec(), id);
        Some(FileId(id))
    }
}

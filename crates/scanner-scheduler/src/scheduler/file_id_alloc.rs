//! Run-scoped `FileId` allocation shared by scheduler backends.
//!
//! `FileId` is used by engine scratch state to reset overlap/dedupe boundaries
//! between logical files. Reusing ids for distinct files can suppress findings,
//! so IDs must be unique across regular files and archive entries.

use crate::api::FileId;
use std::sync::atomic::{AtomicU32, Ordering};

/// Allocates run-scoped file IDs for scanner work items.
#[derive(Debug)]
pub(crate) struct FileIdAllocator {
    next_file_id: AtomicU32,
}

impl FileIdAllocator {
    #[inline]
    pub(crate) fn new(start: u32) -> Self {
        Self {
            next_file_id: AtomicU32::new(start),
        }
    }

    #[inline]
    pub(crate) fn next_root_file_id(&self) -> Option<FileId> {
        self.next_file_id
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .ok()
            .map(FileId)
    }

    #[inline]
    pub(crate) fn next_archive_entry_file_id(
        &self,
        _container_file_id: FileId,
        entry_index: &mut u32,
    ) -> Option<FileId> {
        *entry_index = entry_index.wrapping_add(1);
        self.next_root_file_id()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn root_file_ids_increase() {
        let ids = FileIdAllocator::new(0);
        assert_eq!(ids.next_root_file_id(), Some(FileId(0)));
        assert_eq!(ids.next_root_file_id(), Some(FileId(1)));
        assert_eq!(ids.next_root_file_id(), Some(FileId(2)));
    }

    #[test]
    fn archive_entry_ids_are_unique_across_neighboring_archives() {
        let ids = FileIdAllocator::new(0);
        let archive_a = ids.next_root_file_id().expect("archive A root id");
        let archive_b = ids.next_root_file_id().expect("archive B root id");

        let mut a_entry_idx = 0;
        let mut b_entry_idx = 0;
        let allocated = [
            ids.next_archive_entry_file_id(archive_a, &mut a_entry_idx)
                .expect("archive A entry 1 id"),
            ids.next_archive_entry_file_id(archive_a, &mut a_entry_idx)
                .expect("archive A entry 2 id"),
            ids.next_archive_entry_file_id(archive_b, &mut b_entry_idx)
                .expect("archive B entry 1 id"),
        ];

        let unique: HashSet<FileId> = allocated.into_iter().collect();
        assert_eq!(
            unique.len(),
            allocated.len(),
            "entry ids must be globally unique across archives"
        );
    }
}

//! Work item structure-of-arrays tables.
//!
//! Stores per-candidate metadata in SoA form so sorting and partitioning
//! can shuffle indices without moving large structs. Sorting uses a
//! preallocated radix-sort scratch buffer to avoid per-call allocation.

use super::byte_arena::ByteRef;
use super::errors::SpillError;
use super::object_id::OidBytes;
use super::tree_candidate::CandidateContext;

/// Work item tables with preallocated radix-sort scratch.
#[derive(Debug)]
pub struct WorkItems {
    oid_table: Vec<OidBytes>,
    ctx_table: Vec<CandidateContext>,
    pub oid_idx: Vec<u32>,
    pub ctx_idx: Vec<u32>,
    pub path_ref: Vec<ByteRef>,
    pub flags: Vec<u16>,
    pub pack_id: Vec<u16>,
    pub offset: Vec<u64>,
    order: Vec<u32>,
    scratch: Vec<u32>,
    oid_len: u8,
}

impl WorkItems {
    /// Creates a new work item table with capacity for `max_items`.
    #[must_use]
    pub fn new(max_items: usize, oid_len: u8) -> Self {
        assert!(oid_len == 20 || oid_len == 32, "oid_len must be 20 or 32");
        Self {
            oid_table: Vec::with_capacity(max_items),
            ctx_table: Vec::with_capacity(max_items),
            oid_idx: Vec::with_capacity(max_items),
            ctx_idx: Vec::with_capacity(max_items),
            path_ref: Vec::with_capacity(max_items),
            flags: Vec::with_capacity(max_items),
            pack_id: Vec::with_capacity(max_items),
            offset: Vec::with_capacity(max_items),
            order: Vec::with_capacity(max_items),
            scratch: Vec::with_capacity(max_items),
            oid_len,
        }
    }

    /// Clears all items, retaining capacity.
    pub fn clear(&mut self) {
        self.oid_table.clear();
        self.ctx_table.clear();
        self.oid_idx.clear();
        self.ctx_idx.clear();
        self.path_ref.clear();
        self.flags.clear();
        self.pack_id.clear();
        self.offset.clear();
        self.order.clear();
        self.scratch.clear();
    }

    /// Returns the number of items in the table.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.oid_idx.len()
    }

    /// Returns true if the table has no items.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.oid_idx.is_empty()
    }

    /// Pushes a new work item.
    pub fn push(
        &mut self,
        oid: OidBytes,
        ctx: CandidateContext,
        path_ref: ByteRef,
        flags: u16,
        pack_id: u16,
        offset: u64,
    ) -> Result<(), SpillError> {
        if oid.len() != self.oid_len {
            return Err(SpillError::OidLengthMismatch {
                got: oid.len(),
                expected: self.oid_len,
            });
        }
        if self.oid_idx.len() >= u32::MAX as usize {
            return Err(SpillError::ArenaOverflow);
        }

        let oid_idx = self.oid_table.len() as u32;
        self.oid_table.push(oid);
        let ctx_idx = self.ctx_table.len() as u32;
        self.ctx_table.push(ctx);

        self.oid_idx.push(oid_idx);
        self.ctx_idx.push(ctx_idx);
        self.path_ref.push(path_ref);
        self.flags.push(flags);
        self.pack_id.push(pack_id);
        self.offset.push(offset);
        Ok(())
    }

    /// Prepares the ordering arrays for sorting.
    pub fn prepare_sort(&mut self) {
        let len = self.len();
        self.order.clear();
        self.scratch.clear();
        self.order.extend((0..len).map(|i| i as u32));
        self.scratch.resize(len, 0);
    }

    /// Returns the current ordering of item indices.
    #[must_use]
    pub fn ordered_indices(&self) -> &[u32] {
        &self.order
    }

    /// Sorts the order indices by OID bytes using radix sort.
    ///
    /// Stable for equal OIDs and only reorders the `order` indices; the
    /// underlying SoA tables remain unchanged.
    pub fn sort_by_oid(&mut self) {
        self.prepare_sort();
        let len = self.order.len();
        if len <= 1 {
            return;
        }

        for byte_pos in (0..self.oid_len as usize).rev() {
            let mut counts = [0usize; 256];
            for &idx in &self.order {
                let oid_idx = self.oid_idx[idx as usize] as usize;
                let byte = self.oid_table[oid_idx].as_slice()[byte_pos];
                counts[byte as usize] += 1;
            }
            let mut sum = 0usize;
            for count in counts.iter_mut() {
                let tmp = *count;
                *count = sum;
                sum += tmp;
            }
            for &idx in &self.order {
                let oid_idx = self.oid_idx[idx as usize] as usize;
                let byte = self.oid_table[oid_idx].as_slice()[byte_pos] as usize;
                let pos = &mut counts[byte];
                self.scratch[*pos] = idx;
                *pos += 1;
            }
            self.order.copy_from_slice(&self.scratch);
        }
    }

    /// Returns the OID for a given item index.
    #[must_use]
    pub fn oid_at(&self, idx: u32) -> OidBytes {
        let oid_idx = self.oid_idx[idx as usize] as usize;
        self.oid_table[oid_idx]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ChangeKind;

    fn ctx(id: u32) -> CandidateContext {
        CandidateContext {
            commit_id: id,
            parent_idx: 0,
            change_kind: ChangeKind::Add,
            ctx_flags: 0,
            cand_flags: 0,
            path_ref: ByteRef::new(0, 0),
        }
    }

    #[test]
    fn sort_by_oid_orders_indices() {
        let mut items = WorkItems::new(4, 20);
        let oid_a = OidBytes::sha1([0x01; 20]);
        let oid_b = OidBytes::sha1([0x02; 20]);
        let oid_c = OidBytes::sha1([0x00; 20]);

        items
            .push(oid_a, ctx(1), ByteRef::new(0, 0), 0, 0, 0)
            .unwrap();
        items
            .push(oid_b, ctx(2), ByteRef::new(0, 0), 0, 0, 0)
            .unwrap();
        items
            .push(oid_c, ctx(3), ByteRef::new(0, 0), 0, 0, 0)
            .unwrap();

        items.sort_by_oid();
        let order = items.ordered_indices();
        assert_eq!(items.oid_at(order[0]), oid_c);
        assert_eq!(items.oid_at(order[1]), oid_a);
        assert_eq!(items.oid_at(order[2]), oid_b);
    }

    #[test]
    fn sort_is_stable_for_equal_oids() {
        let mut items = WorkItems::new(4, 20);
        let oid = OidBytes::sha1([0x01; 20]);

        items
            .push(oid, ctx(1), ByteRef::new(0, 0), 0, 0, 0)
            .unwrap();
        items
            .push(oid, ctx(2), ByteRef::new(0, 0), 0, 0, 0)
            .unwrap();
        items
            .push(oid, ctx(3), ByteRef::new(0, 0), 0, 0, 0)
            .unwrap();

        items.sort_by_oid();
        let order = items.ordered_indices();
        assert_eq!(order, &[0, 1, 2]);
    }

    #[test]
    fn sort_only_reorders_indices() {
        let mut items = WorkItems::new(3, 20);
        let oid_a = OidBytes::sha1([0x01; 20]);
        let oid_b = OidBytes::sha1([0x00; 20]);

        items
            .push(oid_a, ctx(1), ByteRef::new(0, 0), 7, 0, 0)
            .unwrap();
        items
            .push(oid_b, ctx(2), ByteRef::new(0, 0), 9, 0, 0)
            .unwrap();

        let flags_before = items.flags.clone();
        items.sort_by_oid();
        assert_eq!(items.flags, flags_before);
    }
}

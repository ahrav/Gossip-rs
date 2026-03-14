//! Shared MIDX v1 test builder.
//!
//! Encodes minimal MIDX v1 bytes for unit tests. All six test modules that
//! previously defined their own `MidxBuilder` now share this single copy.

const MIDX_MAGIC: [u8; 4] = *b"MIDX";
const VERSION: u8 = 1;
const HEADER_SIZE: usize = 12;
const CHUNK_ENTRY_SIZE: usize = 12;
const CHUNK_PNAM: [u8; 4] = *b"PNAM";
const CHUNK_OIDF: [u8; 4] = *b"OIDF";
const CHUNK_OIDL: [u8; 4] = *b"OIDL";
const CHUNK_OOFF: [u8; 4] = *b"OOFF";

/// Minimal MIDX v1 builder for tests.
///
/// Produces valid MIDX bytes with 4 standard chunks (PNAM, OIDF, OIDL, OOFF).
/// Does **not** write checksums or LOFF — sufficient for round-trip parsing
/// tests but not for checksum-validating tooling.
#[derive(Default)]
pub(crate) struct MidxBuilder {
    pub(crate) pack_names: Vec<Vec<u8>>,
    pub(crate) objects: Vec<([u8; 20], u16, u64)>,
}

impl MidxBuilder {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn add_pack(&mut self, name: &[u8]) {
        self.pack_names.push(name.to_vec());
    }

    pub(crate) fn add_object(&mut self, oid: [u8; 20], pack_id: u16, offset: u64) {
        self.objects.push((oid, pack_id, offset));
    }

    pub(crate) fn build(&self) -> Vec<u8> {
        let mut objects = self.objects.clone();
        objects.sort_by(|a, b| a.0.cmp(&b.0));

        let pack_count = self.pack_names.len() as u32;

        // PNAM: null-terminated pack names.
        let mut pnam = Vec::new();
        for name in &self.pack_names {
            pnam.extend_from_slice(name);
            pnam.push(0);
        }

        // OIDF: 256-entry fanout table.
        let mut oidf = vec![0u8; 256 * 4];
        let mut counts = [0u32; 256];
        for (oid, _, _) in &objects {
            counts[oid[0] as usize] += 1;
        }
        let mut running = 0u32;
        for (i, count) in counts.iter().enumerate() {
            running += count;
            let off = i * 4;
            oidf[off..off + 4].copy_from_slice(&running.to_be_bytes());
        }

        // OIDL: sorted OID list.
        let mut oidl = Vec::with_capacity(objects.len() * 20);
        for (oid, _, _) in &objects {
            oidl.extend_from_slice(oid);
        }

        // OOFF: pack-id (u32) + offset (u32) per object.
        let mut ooff = Vec::with_capacity(objects.len() * 8);
        for (_, pack_id, offset) in &objects {
            ooff.extend_from_slice(&(*pack_id as u32).to_be_bytes());
            ooff.extend_from_slice(&(*offset as u32).to_be_bytes());
        }

        // Chunk table layout.
        let chunk_count = 4u8;
        let chunk_table_size = (chunk_count as usize + 1) * CHUNK_ENTRY_SIZE;
        let pnam_off = (HEADER_SIZE + chunk_table_size) as u64;
        let oidf_off = pnam_off + pnam.len() as u64;
        let oidl_off = oidf_off + oidf.len() as u64;
        let ooff_off = oidl_off + oidl.len() as u64;
        let end_off = ooff_off + ooff.len() as u64;

        // Header.
        let mut out = Vec::new();
        out.extend_from_slice(&MIDX_MAGIC);
        out.push(VERSION);
        out.push(1); // SHA-1
        out.push(chunk_count);
        out.push(0); // base count
        out.extend_from_slice(&pack_count.to_be_bytes());

        // Chunk table entries.
        let mut push_chunk = |id: [u8; 4], off: u64| {
            out.extend_from_slice(&id);
            out.extend_from_slice(&off.to_be_bytes());
        };
        push_chunk(CHUNK_PNAM, pnam_off);
        push_chunk(CHUNK_OIDF, oidf_off);
        push_chunk(CHUNK_OIDL, oidl_off);
        push_chunk(CHUNK_OOFF, ooff_off);
        push_chunk([0, 0, 0, 0], end_off);

        // Chunk data.
        out.extend_from_slice(&pnam);
        out.extend_from_slice(&oidf);
        out.extend_from_slice(&oidl);
        out.extend_from_slice(&ooff);

        out
    }
}

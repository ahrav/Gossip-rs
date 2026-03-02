//! Integration tests for the MIDX mapping bridge.
//!
//! These tests build a minimal in-memory MIDX and validate that the bridge
//! maps known OIDs to pack offsets while leaving unknown OIDs as loose.
//!
//! # Invariants
//! - MIDX objects are sorted by OID to satisfy lookup expectations.
//! - Pack ids reflect PNAM order in the constructed MIDX.

use std::collections::{BTreeMap, BTreeSet};

use scanner_git::{
    ByteArena, ByteRef, CappedPackCandidateSink, ChangeKind, CollectingPackCandidateSink,
    MappingBridge, MappingBridgeConfig, MappingCandidateKind, MidxView, ObjectFormat, OidBytes,
    SpillError, UniqueBlob, UniqueBlobSink,
};

fn perf_stats_enabled() -> bool {
    cfg!(all(feature = "perf-stats", debug_assertions))
}

/// Helper for constructing a minimal SHA-1 MIDX buffer.
///
/// Only the chunks needed by `MidxView` lookups are populated.
#[derive(Default)]
struct MidxBuilder {
    pack_names: Vec<Vec<u8>>,
    objects: Vec<([u8; 20], u16, u64)>,
}

impl MidxBuilder {
    /// Adds a pack name (null-terminated in the final MIDX).
    fn add_pack(&mut self, name: &[u8]) {
        self.pack_names.push(name.to_vec());
    }

    /// Adds an object entry with pack id and offset.
    fn add_object(&mut self, oid: [u8; 20], pack_id: u16, offset: u64) {
        self.objects.push((oid, pack_id, offset));
    }

    /// Builds the MIDX byte buffer.
    fn build(&self) -> Vec<u8> {
        const MIDX_MAGIC: [u8; 4] = *b"MIDX";
        const VERSION: u8 = 1;
        const HEADER_SIZE: usize = 12;
        const CHUNK_ENTRY_SIZE: usize = 12;
        const CHUNK_PNAM: [u8; 4] = *b"PNAM";
        const CHUNK_OIDF: [u8; 4] = *b"OIDF";
        const CHUNK_OIDL: [u8; 4] = *b"OIDL";
        const CHUNK_OOFF: [u8; 4] = *b"OOFF";

        let mut objects = self.objects.clone();
        objects.sort_by(|a, b| a.0.cmp(&b.0));

        let pack_count = self.pack_names.len() as u32;

        let mut pnam = Vec::new();
        for name in &self.pack_names {
            pnam.extend_from_slice(name);
            pnam.push(0);
        }

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

        let mut oidl = Vec::with_capacity(objects.len() * 20);
        for (oid, _, _) in &objects {
            oidl.extend_from_slice(oid);
        }

        let mut ooff = Vec::with_capacity(objects.len() * 8);
        for (_, pack_id, offset) in &objects {
            ooff.extend_from_slice(&(*pack_id as u32).to_be_bytes());
            // OOFF stores 32-bit offsets in this minimal builder (no large offsets).
            ooff.extend_from_slice(&(*offset as u32).to_be_bytes());
        }

        let chunk_count = 4u8;
        let chunk_table_size = (chunk_count as usize + 1) * CHUNK_ENTRY_SIZE;
        let pnam_off = (HEADER_SIZE + chunk_table_size) as u64;
        let oidf_off = pnam_off + pnam.len() as u64;
        let oidl_off = oidf_off + oidf.len() as u64;
        let ooff_off = oidl_off + oidl.len() as u64;
        let end_off = ooff_off + ooff.len() as u64;

        let mut out = Vec::new();
        out.extend_from_slice(&MIDX_MAGIC);
        out.push(VERSION);
        out.push(1); // SHA-1
        out.push(chunk_count);
        out.push(0); // base count
        out.extend_from_slice(&pack_count.to_be_bytes());

        let mut push_chunk = |id: [u8; 4], off: u64| {
            out.extend_from_slice(&id);
            out.extend_from_slice(&off.to_be_bytes());
        };

        push_chunk(CHUNK_PNAM, pnam_off);
        push_chunk(CHUNK_OIDF, oidf_off);
        push_chunk(CHUNK_OIDL, oidl_off);
        push_chunk(CHUNK_OOFF, ooff_off);
        push_chunk([0, 0, 0, 0], end_off);

        out.extend_from_slice(&pnam);
        out.extend_from_slice(&oidf);
        out.extend_from_slice(&oidl);
        out.extend_from_slice(&ooff);

        out
    }
}

/// Creates a unique blob with a fixed change context for tests.
fn make_blob(oid: OidBytes, path_ref: ByteRef) -> UniqueBlob {
    UniqueBlob {
        oid,
        ctx: scanner_git::CandidateContext {
            commit_id: 1,
            parent_idx: 0,
            change_kind: ChangeKind::Add,
            ctx_flags: 0,
            cand_flags: 0,
            path_ref,
        },
    }
}

#[test]
fn mapping_bridge_emits_pack_and_loose() {
    let mut builder = MidxBuilder::default();
    builder.add_pack(b"pack-test");
    builder.add_object([0x11; 20], 0, 100);
    builder.add_object([0x22; 20], 0, 200);
    let midx_bytes = builder.build();

    let midx = MidxView::parse(&midx_bytes, ObjectFormat::Sha1).unwrap();
    let sink = CollectingPackCandidateSink::default();
    let mut bridge = MappingBridge::new(
        &midx,
        sink,
        MappingBridgeConfig {
            path_arena_capacity: 1024,
            max_packed_candidates: 128,
            max_loose_candidates: 128,
        },
    );

    let mut src_paths = ByteArena::with_capacity(1024);
    let path_ref_a = src_paths.intern(b"src/main.rs").unwrap();
    let path_ref_b = src_paths.intern(b"README.md").unwrap();

    let blob_a = make_blob(OidBytes::sha1([0x11; 20]), path_ref_a);
    let blob_b = make_blob(OidBytes::sha1([0x33; 20]), path_ref_b);

    bridge.emit(&blob_a, &src_paths).unwrap();
    bridge.emit(&blob_b, &src_paths).unwrap();
    // The sink is finished via the `UniqueBlobSink` trait before consuming the bridge.
    UniqueBlobSink::finish(&mut bridge).unwrap();

    let (stats, sink, arena) = bridge.finish().unwrap();

    if perf_stats_enabled() {
        assert_eq!(stats.unique_blobs_in, 2);
        assert_eq!(stats.packed_matched, 1);
        assert_eq!(stats.loose_unmatched, 1);
    } else {
        assert_eq!(stats.unique_blobs_in, 0);
        assert_eq!(stats.packed_matched, 0);
        assert_eq!(stats.loose_unmatched, 0);
    }

    assert_eq!(sink.packed.len(), 1);
    assert_eq!(sink.loose.len(), 1);

    assert_eq!(sink.packed[0].oid, OidBytes::sha1([0x11; 20]));
    assert_eq!(sink.packed[0].pack_id, 0);
    assert_eq!(sink.packed[0].offset, 100);
    assert_eq!(arena.get(sink.packed[0].ctx.path_ref), b"src/main.rs");

    assert_eq!(sink.loose[0].oid, OidBytes::sha1([0x33; 20]));
    assert_eq!(arena.get(sink.loose[0].ctx.path_ref), b"README.md");
}

#[test]
fn mapping_bridge_enforces_packed_cap() {
    let mut builder = MidxBuilder::default();
    builder.add_pack(b"pack-test");
    builder.add_object([0x11; 20], 0, 100);
    builder.add_object([0x22; 20], 0, 200);
    let midx_bytes = builder.build();

    let midx = MidxView::parse(&midx_bytes, ObjectFormat::Sha1).unwrap();
    let sink = CappedPackCandidateSink::new(1, 10);
    let mut bridge = MappingBridge::new(
        &midx,
        sink,
        MappingBridgeConfig {
            path_arena_capacity: 1024,
            max_packed_candidates: 1,
            max_loose_candidates: 10,
        },
    );

    let mut src_paths = ByteArena::with_capacity(128);
    let path_ref_a = src_paths.intern(b"src/a.txt").unwrap();
    let path_ref_b = src_paths.intern(b"src/b.txt").unwrap();

    let blob_a = make_blob(OidBytes::sha1([0x11; 20]), path_ref_a);
    let blob_b = make_blob(OidBytes::sha1([0x22; 20]), path_ref_b);

    bridge.emit(&blob_a, &src_paths).unwrap();
    let err = bridge.emit(&blob_b, &src_paths).unwrap_err();

    assert!(matches!(
        err,
        SpillError::MappingCandidateLimitExceeded {
            kind: MappingCandidateKind::Packed,
            max: 1,
            observed: 2
        }
    ));
}

#[test]
fn mapping_bridge_matches_find_oid_oracle() {
    let mut builder = MidxBuilder::default();
    builder.add_pack(b"pack-a");
    builder.add_pack(b"pack-b");
    builder.add_object([0x01; 20], 0, 111);
    builder.add_object([0x10; 20], 1, 222);
    builder.add_object([0x80; 20], 0, 333);
    let midx_bytes = builder.build();

    let midx = MidxView::parse(&midx_bytes, ObjectFormat::Sha1).unwrap();
    let sink = CollectingPackCandidateSink::default();
    let mut bridge = MappingBridge::new(
        &midx,
        sink,
        MappingBridgeConfig {
            path_arena_capacity: 2048,
            max_packed_candidates: 128,
            max_loose_candidates: 128,
        },
    );

    let mut src_paths = ByteArena::with_capacity(512);
    let mut inputs = vec![
        OidBytes::sha1([0x00; 20]),
        OidBytes::sha1([0x01; 20]),
        OidBytes::sha1([0x05; 20]),
        OidBytes::sha1([0x10; 20]),
        OidBytes::sha1([0x20; 20]),
        OidBytes::sha1([0x80; 20]),
        OidBytes::sha1([0xff; 20]),
    ];
    inputs.sort();

    for (idx, oid) in inputs.iter().enumerate() {
        let path = format!("path-{idx}").into_bytes();
        let path_ref = src_paths.intern(&path).unwrap();
        let blob = make_blob(*oid, path_ref);
        bridge.emit(&blob, &src_paths).unwrap();
    }

    UniqueBlobSink::finish(&mut bridge).unwrap();
    let (_stats, sink, _arena) = bridge.finish().unwrap();

    let mut expected_packed = BTreeMap::new();
    let mut expected_loose = BTreeSet::new();
    for oid in inputs {
        match midx.find_oid(&oid).unwrap() {
            Some(idx) => {
                let (pack_id, offset) = midx.offset_at(idx).unwrap();
                expected_packed.insert(oid, (pack_id, offset));
            }
            None => {
                expected_loose.insert(oid);
            }
        }
    }

    assert_eq!(sink.packed.len(), expected_packed.len());
    for candidate in sink.packed {
        let Some((pack_id, offset)) = expected_packed.remove(&candidate.oid) else {
            panic!("unexpected packed oid: {}", candidate.oid);
        };
        assert_eq!(candidate.pack_id, pack_id);
        assert_eq!(candidate.offset, offset);
    }
    assert!(expected_packed.is_empty());

    assert_eq!(sink.loose.len(), expected_loose.len());
    for candidate in sink.loose {
        assert!(expected_loose.remove(&candidate.oid));
    }
    assert!(expected_loose.is_empty());
}

#![no_main]

//! Fuzz target for pack plan construction and execution.
//!
//! Exercises the full pack decode pipeline:
//! - synthetic pack file generation with valid zlib-compressed blobs and
//!   OFS_DELTA chains,
//! - `build_pack_plans` for plan construction from header-only pack views,
//! - `execute_pack_plan` for iterative delta chain resolution, buffer reuse,
//!   and cache eviction paths.
//!
//! The harness uses fuzzer input to control object count, chain depth, and
//! content bytes while constructing structurally valid pack files that the
//! planning and execution code can process end-to-end.

use std::io::Write;

use libfuzzer_sys::fuzz_target;

use scanner_git::{
    build_pack_plans, execute_pack_plan, ByteArena, ByteRef, CandidateContext, ChangeKind,
    ExternalBase, ExternalBaseProvider, OidBytes, PackCache, PackCandidate, PackDecodeLimits,
    PackExecError, PackObjectSink, PackPlanConfig, PackView,
};

/// Maximum fuzz input size to avoid excessive runtime.
const MAX_INPUT: usize = 8 * 1024;
/// Maximum number of objects per synthetic pack.
const MAX_OBJECTS: usize = 8;
/// Maximum inflated content size per object.
const MAX_OBJ_SIZE: usize = 256;

// ---------------------------------------------------------------------------
// Stubs for external base provider and object sink
// ---------------------------------------------------------------------------

/// External base provider that always reports bases as missing.
///
/// This keeps the harness focused on pack-local structure and decode logic.
/// Cross-pack REF base lookup paths still need dedicated tests with `PackIo`
/// or `SimPackIo`.
struct NoExternalBases;

impl ExternalBaseProvider for NoExternalBases {
    fn load_base(&mut self, _oid: &OidBytes) -> Result<Option<ExternalBase>, PackExecError> {
        Ok(None)
    }
}

/// Object sink that discards all emitted blobs.
///
/// The harness validates decode stability, not engine-side scanning or event
/// emission behavior.
struct NullSink;

impl PackObjectSink for NullSink {
    fn emit(
        &mut self,
        _candidate: &PackCandidate,
        _path: &[u8],
        _bytes: &[u8],
    ) -> Result<(), PackExecError> {
        Ok(())
    }
}

/// OID resolver that never resolves (no MIDX available in fuzz context).
///
/// REF_DELTA planning paths that depend on real MIDX ordinal lookup are
/// covered by unit tests that build synthetic MIDX fixtures.
struct NoopResolver;

impl scanner_git::OidResolver for NoopResolver {
    fn resolve(&self, _oid: &OidBytes) -> Result<Option<(u16, u64)>, scanner_git::PackPlanError> {
        Ok(None)
    }
}

// ---------------------------------------------------------------------------
// Pack construction helpers
// ---------------------------------------------------------------------------

/// Build a default candidate context with a zero-length path reference.
fn default_ctx() -> CandidateContext {
    CandidateContext {
        commit_id: 1,
        parent_idx: 0,
        change_kind: ChangeKind::Add,
        ctx_flags: 0,
        cand_flags: 0,
        path_ref: ByteRef::new(0, 0),
    }
}

/// Encode a pack object header (type in bits 6..4, size as MSB-varint).
fn encode_obj_header(obj_type: u8, mut size: u64) -> Vec<u8> {
    let mut out = Vec::new();
    let mut first = ((obj_type & 0x07) << 4) | ((size & 0x0f) as u8);
    size >>= 4;
    if size != 0 {
        first |= 0x80;
    }
    out.push(first);
    while size != 0 {
        let mut byte = (size & 0x7f) as u8;
        size >>= 7;
        if size != 0 {
            byte |= 0x80;
        }
        out.push(byte);
    }
    out
}

/// Encode an OFS_DELTA backward distance as a big-endian variable-length int.
fn encode_ofs_distance(mut dist: u64) -> Vec<u8> {
    if dist == 0 {
        return vec![0];
    }
    let mut bytes = Vec::new();
    bytes.push((dist & 0x7f) as u8);
    dist >>= 7;
    while dist > 0 {
        dist -= 1;
        bytes.push(((dist & 0x7f) as u8) | 0x80);
        dist >>= 7;
    }
    bytes.reverse();
    bytes
}

/// Encode a LEB128 varint for delta size headers.
fn encode_varint(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
    out
}

/// Build an insert-only delta instruction stream.
///
/// The stream encodes `base_len` and `result.len()` as size headers followed
/// by literal insert instructions (opcode < 128) that reconstruct `result`.
fn build_insert_delta(base_len: usize, result: &[u8]) -> Vec<u8> {
    let mut delta = Vec::new();
    delta.extend(encode_varint(base_len as u64));
    delta.extend(encode_varint(result.len() as u64));
    let mut remaining = result;
    while !remaining.is_empty() {
        let chunk_len = remaining.len().min(127);
        delta.push(chunk_len as u8);
        delta.extend_from_slice(&remaining[..chunk_len]);
        remaining = &remaining[chunk_len..];
    }
    delta
}

/// Zlib-compress data using a fast compression level.
fn zlib_compress(data: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

// ---------------------------------------------------------------------------
// Fuzz target
// ---------------------------------------------------------------------------

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 || data.len() > MAX_INPUT {
        return;
    }

    // Use first bytes to control structure.
    let num_objects = ((data[0] as usize) % MAX_OBJECTS).max(1);
    let chain_depth = ((data[1] as usize) % num_objects).min(4);
    let data_start = 2usize; // skip control bytes

    // --- Build synthetic pack bytes ---
    let mut pack_buf = Vec::new();
    // Pack header: "PACK" + version 2 + object count
    pack_buf.extend_from_slice(b"PACK");
    pack_buf.extend_from_slice(&2u32.to_be_bytes()); // version 2
    pack_buf.extend_from_slice(&(num_objects as u32).to_be_bytes());

    let mut offsets = Vec::new();

    // First object: a plain blob.
    let base_content_len =
        ((data.get(data_start).copied().unwrap_or(1) as usize) % MAX_OBJ_SIZE).max(1);
    let base_content: Vec<u8> = data
        .iter()
        .cycle()
        .take(base_content_len)
        .copied()
        .collect();

    let base_offset = pack_buf.len() as u64;
    let base_header = encode_obj_header(3, base_content.len() as u64); // type 3 = blob
    let compressed_base = zlib_compress(&base_content);
    pack_buf.extend_from_slice(&base_header);
    pack_buf.extend_from_slice(&compressed_base);
    offsets.push(base_offset);

    // Remaining objects: OFS_DELTA chains then independent blobs.
    let mut prev_content = base_content.clone();
    for i in 1..num_objects {
        let delta_offset = pack_buf.len() as u64;

        if i <= chain_depth {
            // OFS_DELTA referencing the previous object.
            let result_byte = data.get(data_start + i).copied().unwrap_or(0x41 + i as u8);
            let mut result = prev_content.clone();
            if !result.is_empty() {
                result[0] = result_byte;
            }
            result.push(result_byte);

            let delta_stream = build_insert_delta(prev_content.len(), &result);
            let compressed_delta = zlib_compress(&delta_stream);

            // OFS_DELTA header: type 6 + uncompressed delta size, then backward distance.
            let distance = delta_offset - offsets[i - 1];
            let header = encode_obj_header(6, delta_stream.len() as u64);
            let dist_enc = encode_ofs_distance(distance);

            pack_buf.extend_from_slice(&header);
            pack_buf.extend_from_slice(&dist_enc);
            pack_buf.extend_from_slice(&compressed_delta);
            offsets.push(delta_offset);
            prev_content = result;
        } else {
            // Independent blob.
            let content_len =
                ((data.get(data_start + i).copied().unwrap_or(1) as usize) % MAX_OBJ_SIZE).max(1);
            let content: Vec<u8> = data
                .iter()
                .skip(i)
                .cycle()
                .take(content_len)
                .copied()
                .collect();
            let header = encode_obj_header(3, content.len() as u64);
            let compressed = zlib_compress(&content);
            pack_buf.extend_from_slice(&header);
            pack_buf.extend_from_slice(&compressed);
            offsets.push(delta_offset);
            prev_content = content;
        }
    }

    // Trailing SHA-1 checksum placeholder (20 zero bytes).
    pack_buf.extend_from_slice(&[0u8; 20]);

    // --- Parse the pack and build plans ---
    let Ok(pack_view) = PackView::parse(&pack_buf, 20) else {
        return;
    };

    // Build candidates pointing at every object offset.
    let candidates: Vec<PackCandidate> = offsets
        .iter()
        .enumerate()
        .map(|(i, &off)| {
            let mut oid_bytes = [0u8; 20];
            oid_bytes[0] = i as u8;
            oid_bytes[1] = (i >> 8) as u8;
            PackCandidate {
                oid: OidBytes::sha1(oid_bytes),
                ctx: default_ctx(),
                pack_id: 0,
                offset: off,
            }
        })
        .collect();

    let config = PackPlanConfig {
        max_delta_depth: 8,
        ..Default::default()
    };

    let Ok(plans) = build_pack_plans(candidates, &[Some(pack_view)], &NoopResolver, &config) else {
        return;
    };

    if plans.is_empty() {
        return;
    }
    let plan = &plans[0];

    // --- Execute the plan ---
    let limits = PackDecodeLimits::new(
        64,          // max_header_bytes
        1024 * 1024, // max_object_bytes
        1024 * 1024, // max_delta_bytes
    );
    // Small cache (64 KiB) to exercise eviction paths.
    let mut cache = PackCache::new(64 * 1024);
    let mut base_provider = NoExternalBases;
    let mut sink = NullSink;
    // Minimal byte arena (candidates all use ByteRef(0,0) -> empty path).
    let paths = ByteArena::with_capacity(1);
    let spill_dir_handle = tempfile::tempdir().expect("failed to create spill tempdir");
    let spill_dir = spill_dir_handle.path();

    let _ = execute_pack_plan(
        plan,
        &pack_buf,
        &paths,
        &limits,
        &mut cache,
        &mut base_provider,
        &mut sink,
        &spill_dir,
    );
});

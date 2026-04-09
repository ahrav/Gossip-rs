//! Shared test helpers for multi-pack delta-chain fixtures.

use std::collections::HashSet;
use std::io;
use std::path::PathBuf;

use sha1::{Digest, Sha1};
use tempfile::TempDir;

#[cfg(not(feature = "sim-harness"))]
#[path = "sim_git_scan/pack_io.rs"]
mod sim_pack_io_impl;

use crate::delta_test_helpers::{make_add_delta, SyntheticPackBuilder};
use crate::midx_test_builder::MidxBuilder;
use crate::pack_inflate::ObjectKind;
use crate::pack_io::{PackIo, PackIoError, PackIoLimits};
#[cfg(feature = "sim-harness")]
use crate::sim_git_scan::SimPackIo;
use crate::{BytesView, MidxView, ObjectFormat, OidBytes};
#[cfg(not(feature = "sim-harness"))]
use sim_pack_io_impl::SimPackIo;

/// Handle for a pack slot in a [`MultiPackFixtureBuilder`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct PackHandle(usize);

/// Handle for an object registered with a [`MultiPackFixtureBuilder`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct ObjectHandle(usize);

/// Builder for coherent multi-pack test fixtures.
///
/// The builder records object metadata and resolved bytes up front, then
/// composes `SyntheticPackBuilder` + `MidxBuilder` when `build()` is called.
pub(crate) struct MultiPackFixtureBuilder {
    packs: Vec<PackSpec>,
    objects: Vec<ObjectSpec>,
}

struct PackSpec {
    name: Vec<u8>,
    entries: Vec<EntrySpec>,
}

enum EntrySpec {
    Base {
        kind: ObjectKind,
        bytes: Vec<u8>,
    },
    RefDelta {
        base_oid: OidBytes,
        delta: Vec<u8>,
    },
    OfsDelta {
        base_entry_idx: usize,
        delta: Vec<u8>,
    },
}

struct ObjectSpec {
    pack_idx: usize,
    entry_idx: usize,
    kind: ObjectKind,
    oid: OidBytes,
    resolved_bytes: Option<Vec<u8>>,
    offset: u64,
}

/// Built multi-pack fixture with pack bytes, MIDX bytes, and golden values.
pub(crate) struct MultiPackFixture {
    _tempdir: TempDir,
    midx_bytes: Vec<u8>,
    pack_bytes: Vec<Vec<u8>>,
    pack_paths: Vec<PathBuf>,
    objects: Vec<ObjectSpec>,
}

impl MultiPackFixture {
    /// Starts a new multi-pack fixture builder.
    #[must_use]
    pub(crate) fn builder() -> MultiPackFixtureBuilder {
        MultiPackFixtureBuilder::new()
    }

    /// Returns a file-backed [`PackIo`] over the fixture's packs.
    pub(crate) fn pack_io(&self, limits: PackIoLimits) -> Result<PackIo<'_>, PackIoError> {
        let midx = MidxView::parse(&self.midx_bytes, ObjectFormat::Sha1)?;
        PackIo::from_parts(midx, self.pack_paths.clone(), Vec::new(), limits)
    }

    /// Returns an in-memory [`SimPackIo`] over the fixture's packs.
    pub(crate) fn sim_pack_io(&self, limits: PackIoLimits) -> Result<SimPackIo, PackIoError> {
        SimPackIo::new(
            ObjectFormat::Sha1,
            BytesView::from_vec(self.midx_bytes.clone()),
            self.pack_bytes
                .iter()
                .cloned()
                .map(BytesView::from_vec)
                .collect(),
            limits,
        )
    }

    /// Returns the resolved object ID for a fixture handle.
    #[must_use]
    pub(crate) fn oid(&self, handle: ObjectHandle) -> OidBytes {
        self.object(handle).oid
    }

    /// Returns the pack index for a fixture handle.
    #[must_use]
    pub(crate) fn pack_index(&self, handle: ObjectHandle) -> usize {
        self.object(handle).pack_idx
    }

    /// Returns the pack-relative offset for a fixture handle.
    #[must_use]
    pub(crate) fn offset(&self, handle: ObjectHandle) -> u64 {
        self.object(handle).offset
    }

    /// Returns the expected object kind and bytes for a fixture handle.
    #[must_use]
    pub(crate) fn expected(&self, handle: ObjectHandle) -> Option<(ObjectKind, &[u8])> {
        let object = self.object(handle);
        object
            .resolved_bytes
            .as_deref()
            .map(|bytes| (object.kind, bytes))
    }

    /// Returns the raw pack bytes for a pack index.
    #[must_use]
    pub(crate) fn pack_bytes(&self, pack_idx: usize) -> &[u8] {
        &self.pack_bytes[pack_idx]
    }

    /// Iterates over every object with a known golden value.
    pub(crate) fn golden_values(
        &self,
    ) -> impl Iterator<Item = (ObjectHandle, OidBytes, ObjectKind, &[u8])> + '_ {
        self.objects.iter().enumerate().filter_map(|(idx, object)| {
            object
                .resolved_bytes
                .as_deref()
                .map(|bytes| (ObjectHandle(idx), object.oid, object.kind, bytes))
        })
    }

    fn object(&self, handle: ObjectHandle) -> &ObjectSpec {
        &self.objects[handle.0]
    }
}

impl MultiPackFixtureBuilder {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            packs: Vec::new(),
            objects: Vec::new(),
        }
    }

    /// Adds a named pack to the fixture and returns its handle.
    pub(crate) fn add_pack(&mut self, name: &[u8]) -> PackHandle {
        let handle = PackHandle(self.packs.len());
        self.packs.push(PackSpec {
            name: name.to_vec(),
            entries: Vec::new(),
        });
        handle
    }

    /// Adds a non-delta blob object to a pack.
    pub(crate) fn add_blob(&mut self, pack: PackHandle, bytes: &[u8]) -> ObjectHandle {
        self.add_object(pack, ObjectKind::Blob, bytes)
    }

    /// Adds a non-delta object to a pack.
    pub(crate) fn add_object(
        &mut self,
        pack: PackHandle,
        kind: ObjectKind,
        bytes: &[u8],
    ) -> ObjectHandle {
        let oid = git_oid(kind, bytes);
        self.push_object(
            pack.0,
            EntrySpec::Base {
                kind,
                bytes: bytes.to_vec(),
            },
            kind,
            oid,
            Some(bytes.to_vec()),
        )
    }

    /// Adds a REF_DELTA object whose resolved bytes are `result_bytes`.
    pub(crate) fn add_ref_delta(
        &mut self,
        pack: PackHandle,
        base: ObjectHandle,
        result_bytes: &[u8],
    ) -> ObjectHandle {
        let base_object = self.object(base);
        let base_len = base_object
            .resolved_bytes
            .as_ref()
            .expect("REF_DELTA base must have resolved bytes")
            .len();
        let kind = base_object.kind;
        let oid = git_oid(kind, result_bytes);
        self.push_object(
            pack.0,
            EntrySpec::RefDelta {
                base_oid: base_object.oid,
                delta: make_add_delta(base_len, result_bytes),
            },
            kind,
            oid,
            Some(result_bytes.to_vec()),
        )
    }

    /// Adds an OFS_DELTA object whose resolved bytes are `result_bytes`.
    pub(crate) fn add_ofs_delta(
        &mut self,
        pack: PackHandle,
        base: ObjectHandle,
        result_bytes: &[u8],
    ) -> ObjectHandle {
        let base_object = self.object(base);
        assert_eq!(
            base_object.pack_idx, pack.0,
            "OFS_DELTA base must live in the same pack"
        );
        let base_len = base_object
            .resolved_bytes
            .as_ref()
            .expect("OFS_DELTA base must have resolved bytes")
            .len();
        let kind = base_object.kind;
        let oid = git_oid(kind, result_bytes);
        self.push_object(
            pack.0,
            EntrySpec::OfsDelta {
                base_entry_idx: base_object.entry_idx,
                delta: make_add_delta(base_len, result_bytes),
            },
            kind,
            oid,
            Some(result_bytes.to_vec()),
        )
    }

    /// Adds a REF_DELTA object that references an OID absent from the fixture.
    pub(crate) fn add_missing_ref_delta(
        &mut self,
        pack: PackHandle,
        missing_base_oid: OidBytes,
        missing_base_size: usize,
        result_bytes: &[u8],
    ) -> ObjectHandle {
        let pack_idx = pack.0;
        let entry_idx = self.packs[pack_idx].entries.len();
        let oid = stable_oid(format!("missing-ref-{pack_idx}-{entry_idx}").as_bytes());
        self.push_object(
            pack_idx,
            EntrySpec::RefDelta {
                base_oid: missing_base_oid,
                delta: make_add_delta(missing_base_size, result_bytes),
            },
            ObjectKind::Blob,
            oid,
            None,
        )
    }

    /// Builds the fixture and writes pack files into a tempdir.
    pub(crate) fn build(self) -> io::Result<MultiPackFixture> {
        let mut objects = self.objects;
        let mut seen = HashSet::with_capacity(objects.len());
        for object in &objects {
            assert!(
                seen.insert(object.oid),
                "fixture requires unique OIDs, found duplicate {:?}",
                object.oid
            );
        }

        let tempdir = tempfile::tempdir()?;
        let mut midx = MidxBuilder::new();
        let mut pack_bytes = Vec::with_capacity(self.packs.len());
        let mut pack_paths = Vec::with_capacity(self.packs.len());

        for pack in &self.packs {
            midx.add_pack(&pack.name);
        }

        for (pack_idx, pack) in self.packs.iter().enumerate() {
            let mut builder = SyntheticPackBuilder::new();
            for entry in &pack.entries {
                match entry {
                    EntrySpec::Base { kind, bytes } => {
                        builder.add_non_delta(kind_code(*kind), bytes);
                    }
                    EntrySpec::RefDelta { base_oid, delta } => {
                        builder.add_ref_delta(*base_oid, delta);
                    }
                    EntrySpec::OfsDelta {
                        base_entry_idx,
                        delta,
                    } => {
                        builder.add_ofs_delta(*base_entry_idx, delta);
                    }
                }
            }

            let (bytes, offsets) = builder.build();
            for object in objects
                .iter_mut()
                .filter(|object| object.pack_idx == pack_idx)
            {
                object.offset = offsets[object.entry_idx];
                midx.add_object(oid_to_sha1(object.oid), pack_idx as u16, object.offset);
            }

            let path = tempdir
                .path()
                .join(format!("{pack_idx}-{}.pack", pack_path_name(pack)));
            std::fs::write(&path, &bytes)?;
            pack_paths.push(path);
            pack_bytes.push(bytes);
        }

        Ok(MultiPackFixture {
            _tempdir: tempdir,
            midx_bytes: midx.build(),
            pack_bytes,
            pack_paths,
            objects,
        })
    }

    fn object(&self, handle: ObjectHandle) -> &ObjectSpec {
        &self.objects[handle.0]
    }

    fn push_object(
        &mut self,
        pack_idx: usize,
        entry: EntrySpec,
        kind: ObjectKind,
        oid: OidBytes,
        resolved_bytes: Option<Vec<u8>>,
    ) -> ObjectHandle {
        let pack = &mut self.packs[pack_idx];
        let entry_idx = pack.entries.len();
        pack.entries.push(entry);
        let handle = ObjectHandle(self.objects.len());
        self.objects.push(ObjectSpec {
            pack_idx,
            entry_idx,
            kind,
            oid,
            resolved_bytes,
            offset: 0,
        });
        handle
    }
}

/// Returns a deterministic SHA-1 OID for arbitrary test labels.
#[must_use]
pub(crate) fn stable_oid(label: &[u8]) -> OidBytes {
    let mut hasher = Sha1::new();
    hasher.update(b"multi-pack-fixture:");
    hasher.update(label);
    OidBytes::sha1(hasher.finalize().into())
}

fn git_oid(kind: ObjectKind, bytes: &[u8]) -> OidBytes {
    let mut hasher = Sha1::new();
    hasher.update(kind_name(kind));
    hasher.update(b" ");
    hasher.update(bytes.len().to_string().as_bytes());
    hasher.update([0]);
    hasher.update(bytes);
    OidBytes::sha1(hasher.finalize().into())
}

fn kind_name(kind: ObjectKind) -> &'static [u8] {
    match kind {
        ObjectKind::Commit => b"commit",
        ObjectKind::Tree => b"tree",
        ObjectKind::Blob => b"blob",
        ObjectKind::Tag => b"tag",
    }
}

fn kind_code(kind: ObjectKind) -> u8 {
    match kind {
        ObjectKind::Commit => 1,
        ObjectKind::Tree => 2,
        ObjectKind::Blob => 3,
        ObjectKind::Tag => 4,
    }
}

fn oid_to_sha1(oid: OidBytes) -> [u8; 20] {
    oid.as_slice()
        .try_into()
        .expect("multi-pack fixtures only support SHA-1 OIDs")
}

fn pack_path_name(pack: &PackSpec) -> String {
    let raw = String::from_utf8_lossy(&pack.name);
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            out.push(ch);
        } else {
            out.push('-');
        }
    }
    if out.is_empty() {
        "pack".to_string()
    } else {
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pack_decode::PackDecodeLimits;
    use crate::pack_io::PackIoLimits;

    #[test]
    fn fixture_golden_values_match_sim_pack_io() {
        let mut builder = MultiPackFixture::builder();
        let pack_c = builder.add_pack(b"pack-c");
        let pack_b = builder.add_pack(b"pack-b");
        let pack_a = builder.add_pack(b"pack-a");

        let base = builder.add_blob(pack_c, b"blob-c");
        let mid = builder.add_ref_delta(pack_b, base, b"blob-b");
        let top = builder.add_ref_delta(pack_a, mid, b"blob-a");

        let fixture = builder.build().unwrap();
        let limits = PackIoLimits::new(PackDecodeLimits::new(64, 1024, 1024), 8);
        let mut sim = fixture.sim_pack_io(limits).unwrap();

        for (handle, oid, kind, expected) in fixture.golden_values() {
            let loaded = sim.load_object(&oid).unwrap().unwrap();
            assert_eq!(loaded.0, kind);
            assert_eq!(loaded.1, expected);
            assert_eq!(fixture.oid(handle), oid);
        }

        let top_loaded = sim.load_object(&fixture.oid(top)).unwrap().unwrap();
        assert_eq!(top_loaded.1, b"blob-a");
    }
}

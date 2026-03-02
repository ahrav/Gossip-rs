//! Simulated pack I/O for external base resolution.
//!
//! Uses in-memory pack bytes and MIDX bytes to resolve external bases
//! deterministically without filesystem access.

use crate::pack_decode::{entry_header_at, inflate_entry_payload};
use crate::pack_delta::apply_delta;
use crate::pack_inflate::{EntryKind, ObjectKind, PackFile};
use crate::{BytesView, MidxView, ObjectFormat, OidBytes, PackDecodeLimits};
use crate::{ExternalBase, ExternalBaseProvider, PackExecError};
use crate::{PackIoError, PackIoLimits};

/// Simulated pack I/O backed by in-memory bytes.
#[derive(Debug, Clone)]
pub struct SimPackIo {
    object_format: ObjectFormat,
    midx_bytes: BytesView,
    pack_bytes: Vec<BytesView>,
    limits: PackIoLimits,
}

impl SimPackIo {
    /// Build a simulated pack I/O from MIDX and pack bytes.
    pub fn new(
        object_format: ObjectFormat,
        midx_bytes: BytesView,
        pack_bytes: Vec<BytesView>,
        limits: PackIoLimits,
    ) -> Result<Self, PackIoError> {
        let midx = MidxView::parse(midx_bytes.as_slice(), object_format)?;
        let expected = midx.pack_count() as usize;
        if pack_bytes.len() != expected {
            return Err(PackIoError::PackCountMismatch {
                expected,
                actual: pack_bytes.len(),
            });
        }
        Ok(Self {
            object_format,
            midx_bytes,
            pack_bytes,
            limits,
        })
    }

    /// Loads an object by OID, returning `None` if the OID is missing.
    pub fn load_object(
        &mut self,
        oid: &OidBytes,
    ) -> Result<Option<(ObjectKind, Vec<u8>)>, PackIoError> {
        self.load_object_with_depth(oid, self.limits.max_delta_depth)
    }

    fn midx(&self) -> Result<MidxView<'_>, PackIoError> {
        Ok(MidxView::parse(
            self.midx_bytes.as_slice(),
            self.object_format,
        )?)
    }

    fn load_object_with_depth(
        &mut self,
        oid: &OidBytes,
        depth: u8,
    ) -> Result<Option<(ObjectKind, Vec<u8>)>, PackIoError> {
        if oid.len() != self.object_format.oid_len() {
            return Err(PackIoError::OidLengthMismatch {
                got: oid.len(),
                expected: self.object_format.oid_len(),
            });
        }

        let midx = self.midx()?;
        let idx = match midx.find_oid(oid)? {
            Some(idx) => idx,
            None => return Ok(None),
        };
        let (pack_id, offset) = midx.offset_at(idx)?;
        self.load_object_by_offset(pack_id, offset, depth)
    }

    fn load_object_by_offset(
        &mut self,
        pack_id: u16,
        offset: u64,
        depth: u8,
    ) -> Result<Option<(ObjectKind, Vec<u8>)>, PackIoError> {
        let pack = self.pack_data(pack_id)?;
        let pack_file = PackFile::parse(pack.as_slice(), self.object_format.oid_len() as usize)?;
        self.read_pack_object(&pack_file, offset, depth)
    }

    fn pack_data(&self, pack_id: u16) -> Result<BytesView, PackIoError> {
        let idx = pack_id as usize;
        let pack_count = self.pack_bytes.len();
        self.pack_bytes
            .get(idx)
            .cloned()
            .ok_or(PackIoError::PackIdOutOfRange {
                pack_id,
                pack_count,
            })
    }

    fn read_pack_object(
        &mut self,
        pack: &PackFile<'_>,
        offset: u64,
        depth: u8,
    ) -> Result<Option<(ObjectKind, Vec<u8>)>, PackIoError> {
        let header = entry_header_at(pack, offset, &self.limits.decode)?;

        match header.kind {
            EntryKind::NonDelta { kind } => {
                let mut out = Vec::with_capacity(header.size as usize);
                inflate_entry_payload(pack, &header, &mut out, &self.limits.decode)?;
                Ok(Some((kind, out)))
            }
            EntryKind::OfsDelta { base_offset } => {
                if depth == 0 {
                    return Err(PackIoError::DeltaDepthExceeded {
                        max_depth: self.limits.max_delta_depth,
                    });
                }
                let Some((base_kind, base_bytes)) =
                    self.read_pack_object(pack, base_offset, depth - 1)?
                else {
                    return Ok(None);
                };
                let out = apply_delta_entry(pack, &header, &base_bytes, &self.limits.decode)?;
                Ok(Some((base_kind, out)))
            }
            EntryKind::RefDelta { base_oid } => {
                if depth == 0 {
                    return Err(PackIoError::DeltaDepthExceeded {
                        max_depth: self.limits.max_delta_depth,
                    });
                }
                let Some((base_kind, base_bytes)) =
                    self.load_object_with_depth(&base_oid, depth - 1)?
                else {
                    return Ok(None);
                };
                let out = apply_delta_entry(pack, &header, &base_bytes, &self.limits.decode)?;
                Ok(Some((base_kind, out)))
            }
        }
    }
}

impl ExternalBaseProvider for SimPackIo {
    fn load_base(&mut self, oid: &OidBytes) -> Result<Option<ExternalBase>, PackExecError> {
        match self.load_object(oid) {
            Ok(Some((kind, bytes))) => Ok(Some(ExternalBase { kind, bytes })),
            Ok(None) => Ok(None),
            Err(err) => Err(PackExecError::ExternalBase(err.to_string())),
        }
    }
}

fn apply_delta_entry(
    pack: &PackFile<'_>,
    header: &crate::pack_inflate::EntryHeader,
    base_bytes: &[u8],
    limits: &PackDecodeLimits,
) -> Result<Vec<u8>, PackIoError> {
    let mut delta = Vec::with_capacity(limits.max_delta_bytes);
    inflate_entry_payload(pack, header, &mut delta, limits)?;

    let mut out = Vec::with_capacity(header.size as usize);
    apply_delta(base_bytes, &delta, &mut out, limits.max_object_bytes)?;

    Ok(out)
}

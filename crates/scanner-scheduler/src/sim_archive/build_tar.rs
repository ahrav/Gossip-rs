//! Deterministic tar builder for simulation archives.
//!
//! The builder emits minimal ustar headers with stable metadata and uses
//! GNU `L` longname records when entry names exceed 100 bytes. Non-regular
//! entries are emitted with zero-length payloads.

use crate::archive::formats::tar::TAR_BLOCK_LEN;
use crate::sim_scanner::scenario::{ArchiveEntrySpec, EntryKindSpec};

use super::{tar_entry_name, tar_pad, EntryLocator};

/// Build deterministic tar bytes and entry locators.
///
/// The returned locator indices correspond to the header block index for each
/// entry in the emitted tar stream.
pub fn build_tar_bytes(
    entries: &[ArchiveEntrySpec],
) -> Result<(Vec<u8>, Vec<EntryLocator>), String> {
    let mut out = Vec::new();
    let mut locators = Vec::with_capacity(entries.len());
    let mut hdr = [0u8; TAR_BLOCK_LEN];

    for entry in entries {
        let name_bytes = tar_entry_name(entry);
        let is_regular = entry.kind == EntryKindSpec::RegularFile;

        if name_bytes.len() > 100 {
            let mut long_bytes = name_bytes.clone();
            long_bytes.push(0);
            tar_write_header(&mut hdr, b"longname", long_bytes.len() as u64, b'L', None);
            out.extend_from_slice(&hdr);
            out.extend_from_slice(&long_bytes);
            out.extend_from_slice(&vec![0u8; tar_pad(long_bytes.len())]);
        }

        let header_block_index = (out.len() / TAR_BLOCK_LEN) as u64;
        let typeflag = match entry.kind {
            EntryKindSpec::RegularFile => b'0',
            EntryKindSpec::Directory => b'5',
            EntryKindSpec::Symlink => b'2',
            EntryKindSpec::Other => b'1',
        };

        let payload = if is_regular {
            entry.payload.as_slice()
        } else {
            &[]
        };
        let size = payload.len() as u64;
        let name_field = if name_bytes.len() > 100 {
            b"ignored.txt".as_slice()
        } else {
            name_bytes.as_slice()
        };

        tar_write_header(&mut hdr, name_field, size, typeflag, None);
        out.extend_from_slice(&hdr);
        out.extend_from_slice(payload);
        out.extend_from_slice(&vec![0u8; tar_pad(payload.len())]);

        locators.push(EntryLocator::Tar { header_block_index });
    }

    out.extend_from_slice(&[0u8; TAR_BLOCK_LEN]);
    out.extend_from_slice(&[0u8; TAR_BLOCK_LEN]);

    Ok((out, locators))
}

fn tar_write_header(
    buf: &mut [u8; TAR_BLOCK_LEN],
    name: &[u8],
    size: u64,
    typeflag: u8,
    linkname: Option<&[u8]>,
) {
    buf.fill(0);
    let name_len = name.len().min(100);
    buf[0..name_len].copy_from_slice(&name[..name_len]);
    buf[100..108].copy_from_slice(b"0000777\0");
    buf[108..116].copy_from_slice(b"0000000\0");
    buf[116..124].copy_from_slice(b"0000000\0");

    let mut size_field = [b'0'; 11];
    let mut v = size;
    for i in (0..11).rev() {
        size_field[i] = b'0' + ((v & 7) as u8);
        v >>= 3;
    }
    buf[124..135].copy_from_slice(&size_field);
    buf[135] = 0;
    buf[136..148].copy_from_slice(b"00000000000\0");
    for b in &mut buf[148..156] {
        *b = b' ';
    }
    buf[156] = typeflag;
    if let Some(link) = linkname {
        let link_len = link.len().min(100);
        buf[157..157 + link_len].copy_from_slice(&link[..link_len]);
    }
    buf[257..263].copy_from_slice(b"ustar\0");
    buf[263..265].copy_from_slice(b"00");

    let sum: u32 = buf.iter().map(|&b| b as u32).sum();
    let chk = format!("{:06o}\0 ", sum);
    buf[148..156].copy_from_slice(chk.as_bytes());
}

//! Single-shot libdeflate backend for exact-size non-delta pack entries.
//!
//! Pack entry headers report the full uncompressed size of non-delta objects
//! before any inflate work begins, so a fixed-size output buffer is available.
//! This module uses libdeflate's zlib API for that exact-size case while
//! preserving the existing "compressed bytes consumed" contract exposed by
//! `pack_decode`.
//!
//! # Safety boundary
//!
//! The only unsafe surface here is the private `LibdeflateDecompressor`
//! wrapper, which owns a single libdeflate decompressor pointer and never
//! exposes it outside this module. Callers interact only through safe
//! functions that pass borrowed input and output slices into libdeflate and
//! convert libdeflate's result codes into crate-local decode errors.

use std::cell::RefCell;
use std::ffi::c_void;
use std::ptr::NonNull;

use libdeflate_sys::{
    libdeflate_alloc_decompressor, libdeflate_decompressor, libdeflate_free_decompressor,
    libdeflate_result, libdeflate_result_LIBDEFLATE_BAD_DATA,
    libdeflate_result_LIBDEFLATE_INSUFFICIENT_SPACE, libdeflate_result_LIBDEFLATE_SHORT_OUTPUT,
    libdeflate_result_LIBDEFLATE_SUCCESS, libdeflate_zlib_decompress_ex,
};

use super::pack_decode::PackDecodeError;
use super::pack_inflate::{EntryHeader, EntryKind, InflateError};

/// Size threshold for routing exact-size non-delta inflates through libdeflate.
pub(crate) const LIBDEFLATE_THRESHOLD_BYTES: usize = 256 * 1024;

thread_local! {
    static LIBDEFLATE_SCRATCH: RefCell<LibdeflateDecompressor> =
        RefCell::new(LibdeflateDecompressor::new());
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LibdeflateError {
    BadData,
    InsufficientSpace,
    ShortOutput,
}

struct LibdeflateDecompressor {
    raw: NonNull<libdeflate_decompressor>,
}

impl LibdeflateDecompressor {
    fn new() -> Self {
        // SAFETY: `libdeflate_alloc_decompressor` returns either a valid
        // decompressor pointer or null on allocation failure. The null case is
        // handled explicitly below, and the resulting non-null pointer is freed
        // exactly once in `Drop`.
        let raw = unsafe { libdeflate_alloc_decompressor() };
        let raw = NonNull::new(raw)
            .unwrap_or_else(|| panic!("libdeflate_alloc_decompressor returned null"));
        Self { raw }
    }

    fn zlib_decompress_exact(
        &mut self,
        input: &[u8],
        out: &mut [u8],
    ) -> Result<(usize, usize), LibdeflateError> {
        let mut actual_in = 0usize;
        let mut actual_out = 0usize;

        // SAFETY: `self.raw` points to a live decompressor allocated by
        // libdeflate and exclusively borrowed through `&mut self`.
        // `input` and `out` are valid for reads/writes of their reported
        // lengths, and libdeflate writes at most `out.len()` bytes.
        // Both `actual_in` and `actual_out` are valid out-pointers for the
        // duration of the call, which preserves the existing decode contract by
        // reporting the exact number of compressed bytes consumed.
        let result: libdeflate_result = unsafe {
            libdeflate_zlib_decompress_ex(
                self.raw.as_ptr(),
                input.as_ptr().cast::<c_void>(),
                input.len(),
                out.as_mut_ptr().cast::<c_void>(),
                out.len(),
                &mut actual_in,
                &mut actual_out,
            )
        };

        if result == libdeflate_result_LIBDEFLATE_SUCCESS {
            Ok((actual_in, actual_out))
        } else if result == libdeflate_result_LIBDEFLATE_BAD_DATA {
            Err(LibdeflateError::BadData)
        } else if result == libdeflate_result_LIBDEFLATE_INSUFFICIENT_SPACE {
            Err(LibdeflateError::InsufficientSpace)
        } else if result == libdeflate_result_LIBDEFLATE_SHORT_OUTPUT {
            Err(LibdeflateError::ShortOutput)
        } else {
            panic!("libdeflate_zlib_decompress_ex returned an unknown error type");
        }
    }
}

impl Drop for LibdeflateDecompressor {
    fn drop(&mut self) {
        // SAFETY: `self.raw` was allocated by `libdeflate_alloc_decompressor`
        // in `new` and remains uniquely owned by this wrapper until drop.
        unsafe { libdeflate_free_decompressor(self.raw.as_ptr()) };
    }
}

fn with_decompressor<F, R>(f: F) -> R
where
    F: FnOnce(&mut LibdeflateDecompressor) -> R,
{
    LIBDEFLATE_SCRATCH.with(|scratch| {
        let mut scratch = scratch.borrow_mut();
        f(&mut scratch)
    })
}

#[cfg(test)]
pub(crate) fn hold_tls_borrow_for_test<R>(f: impl FnOnce() -> R) -> R {
    with_decompressor(|_| f())
}

#[must_use]
pub(crate) fn use_libdeflate_for_header(header: &EntryHeader) -> bool {
    matches!(header.kind, EntryKind::NonDelta { .. })
        && header.size <= LIBDEFLATE_THRESHOLD_BYTES as u64
}

/// Inflate an exact-size non-delta zlib payload with libdeflate.
///
/// Returns the number of compressed bytes consumed through the end of the
/// first zlib stream.
///
/// # Panics
/// Panics on same-thread reentrancy because the per-thread decompressor is
/// stored in `thread_local!` scratch guarded by `RefCell`.
pub(crate) fn inflate_nondelta_exact(
    pack_slice: &[u8],
    expected: usize,
    out: &mut Vec<u8>,
) -> Result<usize, PackDecodeError> {
    out.clear();
    out.resize(expected, 0);

    match with_decompressor(|de| de.zlib_decompress_exact(pack_slice, out.as_mut_slice())) {
        Ok((actual_in, actual_out)) => {
            if actual_out == expected {
                Ok(actual_in)
            } else {
                out.truncate(actual_out);
                Err(PackDecodeError::Inflate(InflateError::TruncatedInput))
            }
        }
        Err(LibdeflateError::BadData) => {
            out.clear();
            Err(PackDecodeError::Inflate(InflateError::Backend))
        }
        Err(LibdeflateError::InsufficientSpace) => {
            out.clear();
            Err(PackDecodeError::Inflate(InflateError::LimitExceeded))
        }
        Err(LibdeflateError::ShortOutput) => {
            out.clear();
            Err(PackDecodeError::Inflate(InflateError::TruncatedInput))
        }
    }
}

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
//! The unsafe surface is the `LibdeflateDecompressor` wrapper, which owns a
//! single libdeflate decompressor pointer. The wrapper is `pub(crate)` so
//! callers in `pack_exec` can store it alongside `flate2::Decompress` in
//! `DecodeBufs`, bypassing TLS on the hot path. All public methods remain
//! safe — they pass borrowed input and output slices into libdeflate and
//! convert libdeflate's result codes into crate-local decode errors.

use std::cell::RefCell;
use std::ffi::c_void;
use std::ptr::NonNull;

use libdeflate_sys::{
    libdeflate_alloc_decompressor, libdeflate_decompressor, libdeflate_free_decompressor,
    libdeflate_result, libdeflate_result_LIBDEFLATE_BAD_DATA,
    libdeflate_result_LIBDEFLATE_INSUFFICIENT_SPACE, libdeflate_result_LIBDEFLATE_SUCCESS,
    libdeflate_zlib_decompress_ex,
};

use super::pack_decode::PackDecodeError;
use super::pack_inflate::{EntryHeader, EntryKind, InflateError};

/// Size threshold for routing exact-size non-delta inflates through libdeflate.
pub const LIBDEFLATE_THRESHOLD_BYTES: usize = 256 * 1024;

thread_local! {
    static LIBDEFLATE_SCRATCH: RefCell<Option<LibdeflateDecompressor>> =
        RefCell::new(LibdeflateDecompressor::new());
}

/// Failure modes from libdeflate's zlib decompression.
///
/// `SHORT_OUTPUT` is absent because `zlib_decompress_ex` does not return
/// it when `actual_out_nbytes_ret` is non-null.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
enum LibdeflateError {
    #[error("libdeflate: bad data")]
    BadData,
    #[error("libdeflate: insufficient output space")]
    InsufficientSpace,
}

pub struct LibdeflateDecompressor {
    raw: NonNull<libdeflate_decompressor>,
}

impl std::fmt::Debug for LibdeflateDecompressor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LibdeflateDecompressor")
            .finish_non_exhaustive()
    }
}

impl LibdeflateDecompressor {
    /// Allocates a new libdeflate decompressor.
    pub fn new() -> Option<Self> {
        // SAFETY: `libdeflate_alloc_decompressor` returns either a valid
        // decompressor pointer or null on allocation failure. The null case is
        // represented as `None`, and any resulting non-null pointer is freed
        // exactly once in `Drop`.
        let raw = unsafe { libdeflate_alloc_decompressor() };
        NonNull::new(raw).map(|raw| Self { raw })
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
        //
        // The `_ex` variant never returns `SHORT_OUTPUT` when
        // `actual_out_nbytes_ret` is non-NULL (which we always pass). The
        // short-output case is instead reported as SUCCESS with
        // `actual_out < out.len()`, handled by the caller.
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
        } else {
            debug_assert!(
                false,
                "libdeflate returned unexpected result code: {result}"
            );
            Err(LibdeflateError::BadData)
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

// SAFETY: The libdeflate decompressor is a self-contained heap allocation
// with no thread-local or global mutable state. Moving it between threads
// is safe. Concurrent use from multiple threads is NOT safe, which is
// enforced by the `&mut self` borrow on `zlib_decompress_exact`.
unsafe impl Send for LibdeflateDecompressor {}

/// Borrows the thread-local `LibdeflateDecompressor` for the duration of `f`.
///
/// Returns `Option<R>`: `None` when TLS is unavailable (init failure or
/// reentrant borrow). The caller is responsible for choosing a fallback
/// strategy — typically delegating to the flate2 path via
/// [`super::pack_inflate::inflate_exact`]. This differs from
/// [`super::pack_inflate::with_tls_decompress`] which owns its fallback
/// internally and returns `Result`.
#[inline]
pub(crate) fn with_tls_decompressor<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&mut LibdeflateDecompressor) -> R,
{
    LIBDEFLATE_SCRATCH.with(|scratch| match scratch.try_borrow_mut() {
        Ok(mut scratch) => scratch.as_mut().map(f),
        Err(_) => None,
    })
}

#[cfg(test)]
pub(crate) fn hold_tls_borrow_for_test<R>(f: impl FnOnce() -> R) -> R {
    LIBDEFLATE_SCRATCH.with(|scratch| {
        let mut scratch = scratch.borrow_mut();
        let _libde = scratch
            .as_mut()
            .expect("libdeflate TLS should initialize for test coverage");
        f()
    })
}

#[must_use]
pub(crate) fn use_libdeflate_for_header(header: &EntryHeader) -> bool {
    matches!(header.kind, EntryKind::NonDelta { .. })
        && header.size <= LIBDEFLATE_THRESHOLD_BYTES as u64
}

/// Inflate an exact-size non-delta zlib payload using a caller-provided
/// `LibdeflateDecompressor`, bypassing TLS.
///
/// Returns the number of compressed bytes consumed through the end of the
/// first zlib stream. Callers in the hot execution loop store a
/// decompressor in `DecodeBufs` and pass it here to avoid thread-local
/// overhead on every inflate call.
pub(crate) fn inflate_nondelta_exact_with(
    libde: &mut LibdeflateDecompressor,
    pack_slice: &[u8],
    expected: usize,
    out: &mut Vec<u8>,
) -> Result<usize, PackDecodeError> {
    inflate_nondelta_exact_core(libde, pack_slice, expected, out)
}

/// Inflate an exact-size non-delta zlib payload using the thread-local
/// `LibdeflateDecompressor`.
///
/// Convenience wrapper around [`inflate_nondelta_exact_with`] for callers
/// that don't maintain their own decompressor. When the thread-local
/// libdeflate state is unavailable, this falls back to the flate2 exact-size
/// path.
pub(crate) fn inflate_nondelta_exact(
    pack_slice: &[u8],
    expected: usize,
    out: &mut Vec<u8>,
) -> Result<usize, PackDecodeError> {
    with_tls_decompressor(|libde| inflate_nondelta_exact_core(libde, pack_slice, expected, out))
        .unwrap_or_else(
            || match crate::pack_inflate::inflate_exact(pack_slice, out, expected) {
                Ok(consumed) => Ok(consumed),
                Err(err) => {
                    out.clear();
                    Err(PackDecodeError::from(err))
                }
            },
        )
}

fn inflate_nondelta_exact_core(
    libde: &mut LibdeflateDecompressor,
    pack_slice: &[u8],
    expected: usize,
    out: &mut Vec<u8>,
) -> Result<usize, PackDecodeError> {
    out.clear();
    out.reserve(expected);
    crate::pack_inflate::poison_spare_capacity(out);

    // SAFETY: `clear()` set len to 0, `reserve(expected)` guarantees
    // `capacity() >= expected`. libdeflate writes at most `expected` bytes
    // into this buffer on success, and we verify `actual_out == expected`
    // before returning. On error we reset len to 0. The bytes between len
    // and capacity are written by libdeflate before being read.
    //
    // When `expected == 0`, `Vec::as_mut_ptr()` is guaranteed non-null and
    // valid for zero-length writes per Rust's Vec contract, so passing it
    // to libdeflate with `out_nbytes_avail == 0` is safe.
    unsafe { out.set_len(expected) };

    match libde.zlib_decompress_exact(pack_slice, out) {
        Ok((actual_in, actual_out)) => {
            if actual_out == expected {
                Ok(actual_in)
            } else {
                out.clear();
                Err(PackDecodeError::Inflate(InflateError::TruncatedInput))
            }
        }
        Err(LibdeflateError::BadData) => {
            out.clear();
            Err(PackDecodeError::Inflate(InflateError::Backend))
        }
        Err(LibdeflateError::InsufficientSpace) => {
            // The output buffer is sized exactly to the header-declared size.
            // InsufficientSpace means the decompressed stream exceeds the
            // declared size, which is a size-limit violation (not a backend
            // driver error).
            out.clear();
            Err(PackDecodeError::Inflate(InflateError::LimitExceeded))
        }
    }
}

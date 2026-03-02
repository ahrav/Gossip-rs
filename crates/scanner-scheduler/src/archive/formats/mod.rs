//! Format-specific helpers used by detection and scanners.
//!
//! # Design Notes
//! - This module re-exports small, bounded parsers tailored for scanning.

use std::io::Read;

pub mod bzip2;
pub mod gzip;
pub mod tar;
pub mod zip;

pub use bzip2::{is_bzip2_magic, Bzip2Stream};
pub use gzip::{is_gzip_magic, GzipStream};
pub use tar::{is_ustar_header, TarCursor, TarInput, TarNext, TarRead};
pub use zip::{is_zip_magic, ZipCursor, ZipEntryMeta, ZipEntryReader, ZipNext, ZipOpen, ZipSource};

/// Trait abstracting a compressed stream with byte-accounting.
///
/// Both [`GzipStream`] and [`Bzip2Stream`] implement this trait, enabling
/// generic scanning functions that work identically across compression formats.
/// The two methods mirror the existing per-type APIs exactly.
pub trait CompressedStream: Read {
    /// Returns compressed bytes consumed since the previous call.
    fn take_compressed_delta(&mut self) -> u64;
    /// Total compressed bytes consumed since stream creation.
    fn total_compressed(&self) -> u64;
}

impl<R: Read> CompressedStream for GzipStream<R> {
    #[inline]
    fn take_compressed_delta(&mut self) -> u64 {
        GzipStream::take_compressed_delta(self)
    }
    #[inline]
    fn total_compressed(&self) -> u64 {
        GzipStream::total_compressed(self)
    }
}

impl<R: Read> CompressedStream for Bzip2Stream<R> {
    #[inline]
    fn take_compressed_delta(&mut self) -> u64 {
        Bzip2Stream::take_compressed_delta(self)
    }
    #[inline]
    fn total_compressed(&self) -> u64 {
        Bzip2Stream::total_compressed(self)
    }
}

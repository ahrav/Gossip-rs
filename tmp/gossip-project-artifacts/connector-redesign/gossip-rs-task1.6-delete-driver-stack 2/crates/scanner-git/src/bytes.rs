//! Byte container for Git artifact data.
//!
//! This type provides a minimal, read-only view over artifact bytes that
//! can be backed by either an mmap (production) or owned in-memory bytes
//! (simulation). It avoids tying callers to OS-backed file handles while
//! preserving zero-copy access on the fast path.
//!
//! Clones are cheap: the underlying bytes are reference-counted and treated
//! as immutable for the lifetime of any `BytesView`.

use std::sync::Arc;

use memmap2::Mmap;

/// Read-only byte view for Git artifacts.
#[derive(Clone, Debug)]
pub struct BytesView {
    inner: BytesInner,
}

#[derive(Clone, Debug)]
enum BytesInner {
    Mmap(Arc<Mmap>),
    Owned(Arc<[u8]>),
}

impl BytesView {
    /// Wrap a memory-mapped file.
    ///
    /// The mapping is reference-counted to keep it alive across clones.
    #[must_use]
    pub fn from_mmap(mmap: Mmap) -> Self {
        Self {
            inner: BytesInner::Mmap(Arc::new(mmap)),
        }
    }

    /// Wrap shared, in-memory bytes.
    #[must_use]
    pub fn from_arc(bytes: Arc<[u8]>) -> Self {
        Self {
            inner: BytesInner::Owned(bytes),
        }
    }

    /// Wrap owned bytes.
    #[must_use]
    pub fn from_vec(bytes: Vec<u8>) -> Self {
        Self::from_arc(Arc::from(bytes))
    }

    /// Returns the underlying bytes as a slice.
    #[inline(always)]
    pub fn as_slice(&self) -> &[u8] {
        match &self.inner {
            BytesInner::Mmap(mmap) => mmap.as_ref(),
            BytesInner::Owned(bytes) => bytes.as_ref(),
        }
    }

    /// Returns the length of the byte view.
    #[inline(always)]
    pub fn len(&self) -> usize {
        self.as_slice().len()
    }

    /// Returns true if the view is empty.
    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.as_slice().is_empty()
    }
}

impl AsRef<[u8]> for BytesView {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owned_bytes_round_trip() {
        let view = BytesView::from_vec(vec![1u8, 2, 3]);
        assert_eq!(view.len(), 3);
        assert_eq!(view.as_slice(), &[1, 2, 3]);
    }
}

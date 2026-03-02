//! Common source-kind marker shared across scheduler event types.

use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceKind {
    /// Local filesystem source.
    Fs,
    /// Git-backed source.
    Git,
}

impl SourceKind {
    #[inline]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fs => "fs",
            Self::Git => "git",
        }
    }
}

impl fmt::Display for SourceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

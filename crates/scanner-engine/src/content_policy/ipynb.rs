//! Jupyter Notebook (`.ipynb`) text extractor.
//!
//! Parses the JSON structure of a notebook and extracts source lines from
//! **all** cell types — code, markdown, and raw. Markdown cells are included
//! because they frequently contain embedded secrets in code fences, inline
//! snippets, or configuration examples.
//!
//! # Format
//!
//! A `.ipynb` file is JSON with the shape:
//! ```json
//! {
//!   "cells": [
//!     {
//!       "cell_type": "code",
//!       "source": ["line1\n", "line2\n"]
//!     }
//!   ]
//! }
//! ```
//!
//! # Extraction strategy
//!
//! - Each cell's `source` array is concatenated verbatim (lines already
//!   contain their own `\n` terminators).
//! - A trailing `\n` is appended after each non-empty cell to ensure
//!   cell boundaries are visible to line-oriented scan rules.
//! - Output blobs (`outputs` key) are deliberately ignored — they are
//!   large, noisy, and rarely contain secrets.
//! - Cells without a `source` key default to an empty array.
//!
//! # Output encoding
//!
//! Source lines are serialised as UTF-8 by serde, so the output buffer is
//! valid UTF-8 in practice. The extractor trait makes no UTF-8 guarantee,
//! however, so consumers must treat the bytes as opaque.
//!
//! # Why `.ipynb` is extractable even when it looks like text
//!
//! Notebook JSON is technically text (no NUL bytes), but
//! [`classify_content`](super::classify_content) still routes it through
//! extraction so the scan engine sees **only cell source lines**, not the
//! surrounding JSON structural noise or bulky `outputs` blobs.

use serde::Deserialize;

use super::extract::{ExtractResult, Extractor};

/// Extracts source text from all cell types in a Jupyter Notebook.
pub struct IpynbExtractor;

/// Minimal typed representation of a notebook — only the fields we need.
/// All other fields (metadata, outputs, execution_count, etc.) are silently
/// ignored by serde, avoiding BTreeMap/key allocations from `Value`.
#[derive(Deserialize)]
struct Notebook {
    #[serde(default)]
    cells: Vec<Cell>,
}

#[derive(Deserialize)]
struct Cell {
    #[serde(default)]
    source: Vec<String>,
}

impl Extractor for IpynbExtractor {
    fn extract(&self, data: &[u8], out: &mut Vec<u8>, _scratch: &mut Vec<u8>) -> ExtractResult {
        let notebook: Notebook = match serde_json::from_slice(data) {
            Ok(v) => v,
            Err(_) => return ExtractResult::ParseError,
        };

        if notebook.cells.is_empty() {
            return ExtractResult::Empty;
        }

        let start_len = out.len();

        for cell in &notebook.cells {
            for line in &cell.source {
                out.extend_from_slice(line.as_bytes());
            }
            // Separate cells with a newline.
            if !cell.source.is_empty() {
                out.push(b'\n');
            }
        }

        if out.len() == start_len {
            ExtractResult::Empty
        } else {
            ExtractResult::Ok
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_code_cell_source() {
        let notebook = r##"{
            "cells": [
                {
                    "cell_type": "code",
                    "source": ["import os\n", "SECRET_KEY = 'abc123'\n"]
                }
            ]
        }"##;
        let mut out = Vec::new();
        let result = IpynbExtractor.extract(notebook.as_bytes(), &mut out, &mut Vec::new());
        assert_eq!(result, ExtractResult::Ok);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("SECRET_KEY"));
        assert!(text.contains("import os"));
    }

    #[test]
    fn extracts_multiple_cells() {
        let notebook = r##"{
            "cells": [
                {
                    "cell_type": "code",
                    "source": ["x = 1\n"]
                },
                {
                    "cell_type": "markdown",
                    "source": ["# Title\n"]
                },
                {
                    "cell_type": "code",
                    "source": ["password = 'hunter2'\n"]
                }
            ]
        }"##;
        let mut out = Vec::new();
        let result = IpynbExtractor.extract(notebook.as_bytes(), &mut out, &mut Vec::new());
        assert_eq!(result, ExtractResult::Ok);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("x = 1"));
        assert!(text.contains("# Title"));
        assert!(text.contains("password"));
    }

    #[test]
    fn empty_cells_returns_empty() {
        let notebook = r#"{"cells": []}"#;
        let mut out = Vec::new();
        assert_eq!(
            IpynbExtractor.extract(notebook.as_bytes(), &mut out, &mut Vec::new()),
            ExtractResult::Empty
        );
    }

    #[test]
    fn no_cells_key_returns_empty() {
        let data = r#"{"metadata": {}}"#;
        let mut out = Vec::new();
        assert_eq!(
            IpynbExtractor.extract(data.as_bytes(), &mut out, &mut Vec::new()),
            ExtractResult::Empty
        );
    }

    #[test]
    fn invalid_json_returns_parse_error() {
        let mut out = Vec::new();
        assert_eq!(
            IpynbExtractor.extract(b"not json", &mut out, &mut Vec::new()),
            ExtractResult::ParseError
        );
    }

    #[test]
    fn cells_without_source_skipped() {
        let notebook = r##"{
            "cells": [
                {"cell_type": "raw"},
                {"cell_type": "code", "source": ["found\n"]}
            ]
        }"##;
        let mut out = Vec::new();
        let result = IpynbExtractor.extract(notebook.as_bytes(), &mut out, &mut Vec::new());
        assert_eq!(result, ExtractResult::Ok);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("found"));
    }
}

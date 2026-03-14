# Scanner Corpus Index

This directory contains deterministic scanner simulation scenarios. Each `*.case.json` file is a complete ReproArtifact used by the sim harness.

## Scenarios

| File | Description |
|---|---|
| `b64_internal_newline.case.json` | Base64 secret with embedded LF; verifies whitespace-tolerant span finding and decoding. |
| `b64_invalid_padding.case.json` | Base64 transform with invalid padding; ensures decoder rejects/handles bad padding safely. |
| `b64_no_padding.case.json` | Base64 transform without `=` padding; verifies decode and match still succeed. |
| `b64_pad_eq.case.json` | Base64 transform with single `=` padding; verifies decode and match. |
| `b64_pad_eqeq.case.json` | Base64 transform with double `==` padding; verifies decode and match. |
| `b64_padding_seed17.case.json` | Deep random regression: base64 padding drift across partial reads must not fail differential oracle. |
| `b64_padding_split_boundary.case.json` | Base64 padding `=` split across chunk boundary; ensures padding logic is boundary-safe. |
| `b64_spans_eq_cap_16.case.json` | Base64 span detection exactly at span cap (16) for a buffer. |
| `b64_spans_gt_cap_17.case.json` | Base64 span detection above cap (17); verifies cap enforcement. |
| `b64_split_across_chunk_boundary.case.json` | Base64 span crosses chunk boundary; verifies overlap mapping for transformed spans. |
| `b64_truncated_quantum.case.json` | Base64 truncated quantum at end of input; ensures safe handling. |
| `b64_whitespace_crlf.case.json` | Base64 with CRLF line breaks; verifies whitespace handling across Windows-style line endings. |
| `b64url_no_padding.case.json` | Base64url (`-`/`_`) without padding, common in JWT segments. |
| `badutf8.case.json` | File path contains invalid UTF-8; ensures path handling stays robust. |
| `binary_garbage_with_transform_like_sequences.case.json` | Random bytes with `%` and base64-like fragments; avoids false positives and panics. |
| `case_insensitive_regex_jwt.case.json` | Case-insensitive JWT bearer regex (lowercase bearer) in raw data. |
| `corrupt_transform_bytes.case.json` | Corrupted encoded bytes; decoder should fail safely without false positives. |
| `crlf_boundary.case.json` | Chunk boundary splits `\r\n` just before a raw secret; verifies boundary math. |
| `deterministic_replay_stability_runs.case.json` | Same scenario replayed with multiple schedules; results must be stable. |
| `duplicate_finding_seed1.case.json` | Deep random seed regression with faults; prevents duplicate non-root findings in overlap scans. |
| `empty_file.case.json` | Zero-byte file; scan exits cleanly with no findings. |
| `empty_path.case.json` | Empty path bytes; ensures path edge case is handled safely. |
| `extra_expected_root_seed728.case.json` | Deep random regression where chunked scan finds an expected raw secret missed by the single-chunk reference. |
| `huge_noise_sparse_secrets.case.json` | Large file with long noise gaps; stresses chunk scheduling and buffer reuse. |
| `longpath.case.json` | Very long path; validates path handling and hashing stability. |
| `max_transform_depth0_no_decode.case.json` | Depth limit set to 0; encoded content must not be decoded. |
| `mf_parallel.case.json` | Multi-file corpus; verifies parallel discovery/scan ordering invariants. |
| `near_miss_only.case.json` | Adversarial near-miss anchors; ensures no false positives. |
| `nested_depth_exceeds_max.case.json` | Nested encoding depth greater than `max_transform_depth`; decode should stop deterministically. |
| `overlap_eq_required.case.json` | Overlap equals required overlap; verifies dedupe/window correctness. |
| `overlap_gt_required.case.json` | Overlap greater than required; verifies dedupe/window correctness. |
| `path_nul_slashslash.case.json` | Path with NUL and `//` sequences; validates path normalization robustness. |
| `path_weird_bytes_with_secret.case.json` | Path contains NUL/0xFF while content has a valid secret; ensures path bytes do not break scanning. |
| `path_windows_drive.case.json` | Windows-style path `C:\\dir\\file.txt` with backslashes; verifies path handling. |
| `raw_back_to_back.case.json` | Two raw secrets adjacent in one file; both must be found. |
| `raw_boundary.case.json` | Raw secrets at chunk boundary across multiple files. |
| `raw_cross_chunk_end_boundary.case.json` | Raw secret ends exactly at a chunk boundary; exercises drop-prefix boundary math. |
| `raw_duplicate_across_files.case.json` | Same secret appears in multiple files; findings must be distinct per file. |
| `raw_high_entropy_0_255.case.json` | Byte sweep 0..255; ensures raw scanning tolerates arbitrary bytes without matches. |
| `raw_many_anchor_hits_no_match.case.json` | Many anchor hits with regex misses; stresses anchor cap handling without findings. |
| `raw_nonascii_padding.case.json` | Raw secret surrounded by 0x00/0xFF bytes; ensures non-UTF8 bytes are handled safely. |
| `raw_overlapping_secrets.case.json` | Overlapping rules where one token is a strict prefix of another; both must be found. |
| `raw_repetitive_a_200.case.json` | 200 'A' bytes; exercises worst-case prefilter/scan path without matches. |
| `raw_secret_at_eof.case.json` | Raw secret ends at EOF; must still be detected. |
| `raw_split_across_chunks.case.json` | Raw secret split across chunk boundary; must still be detected. |
| `raw_start_boundary.case.json` | Raw secret begins at chunk boundary; must still be detected. |
| `seed_4_nested_base64_urlpct.case.json` | Deep seed regression: nested base64 inside URL-percent span is alignment-sensitive. |
| `seed_17_base64_padding_diff.case.json` | Random deep seed regression: base64 padding tolerance in differential oracle. |
| `tiny_chunk_extreme_overlap.case.json` | Chunk size 1-4 bytes with large overlap; stresses overlap arithmetic. |
| `transforms.case.json` | Mixed Base64 and URL-percent transforms in one file. |
| `urlpct_end_on_boundary.case.json` | URL-percent span ends on chunk boundary; tests transform drop-prefix handling. |
| `urlpct_invalid_tail.case.json` | URL-percent content with invalid trailing escape; decoder pass-through should still match. |
| `urlpct_lower.case.json` | URL-percent encoding with lowercase hex; must decode correctly. |
| `urlpct_mixed_case.case.json` | URL-percent encoding with mixed-case hex; must decode correctly. |
| `urlpct_min_len_edges.case.json` | URL-percent spans at min length boundaries. |
| `urlpct_spans_eq_cap_16.case.json` | URL-percent span detection exactly at span cap (16). |
| `urlpct_spans_gt_cap_17.case.json` | URL-percent span detection above cap (17); verifies cap enforcement. |
| `urlpct_split_triplet_across_boundary.case.json` | Percent escape split across chunk boundary; verifies cross-boundary decode. |
| `urlpct_upper.case.json` | URL-percent encoding with uppercase hex; must decode correctly. |
| `utf16.case.json` | UTF-16LE/BE secrets in separate files. |
| `utf16_mix_two_secrets.case.json` | UTF-16LE and UTF-16BE secrets in one file; verifies mixed-variant detection. |
| `utf16_mixed_endianness.case.json` | UTF-16LE file with two rule variants; verifies multi-rule detection in UTF-16. |
| `utf16_raw_mix_same_file.case.json` | Raw and UTF-16LE secrets in one file; verifies mixed-variant detection. |
| `utf16be_aligned.case.json` | UTF-16BE secret aligned on even boundary. |
| `utf16be_mixed_parity.case.json` | UTF-16BE secret across parity; verifies handling. |
| `utf16be_mixed_parity_tiny_chunks.case.json` | UTF-16BE parity case under tiny chunk sizes. |
| `utf16le_aligned.case.json` | UTF-16LE secret aligned on even boundary. |
| `utf16le_misaligned.case.json` | UTF-16LE secret starting at odd offset; verifies parity tolerance. |
| `utf16le_truncated_odd_len_tail.case.json` | UTF-16LE with truncated odd-length tail; must not mis-detect. |
| `utf16le_with_bom.case.json` | UTF-16LE content with BOM; must decode correctly. |
| `utf8_bom.case.json` | UTF-8 BOM before raw secret; ensures offsets and matching are correct. |

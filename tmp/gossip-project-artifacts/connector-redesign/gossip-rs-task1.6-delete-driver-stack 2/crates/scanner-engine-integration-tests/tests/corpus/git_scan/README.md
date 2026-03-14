# Git Scan Corpus Index

This directory contains deterministic Git simulation scenarios. Each
`*.case.json` file is a complete `GitReproArtifact` used by the sim harness.

## Scenarios

| File | Description |
|---|---|
| `minimal_sha1.case.json` | Single-ref, single-commit SHA-1 repo with a blob candidate; validates trace hash replay and pipeline ordering. |
| `force_push_watermark.case.json` | Watermark points at a non-ancestor commit (force-push style); should scan full history without advancing watermarks. |
| `new_ref_skip.case.json` | New ref without watermark whose tip is an ancestor of another ref's watermark; exercises skip logic for redundant history. |
| `merge_two_parents.case.json` | Merge commit with two parents plus a nested subtree to stress DAG traversal and tree recursion. |
| `gitlink_skipped.case.json` | Tree includes a gitlink (submodule) entry; scanner should ignore the gitlink and scan blobs only. |
| `sha256_single_ref.case.json` | SHA-256 object format with a minimal commit/tree/blob set. |
| `weird_path_bytes.case.json` | Tree entry with non-UTF8 path bytes to validate raw name handling. |
| `watermark_equals_tip.case.json` | Incremental scan where watermark equals tip; should produce no new commit work. |
| `missing_watermark.case.json` | Watermark OID missing from commit graph; treated as full-history scan. |
| `modify_same_path.case.json` | Same path modified across commits; exercises Modify candidates. |
| `delete_only_commit.case.json` | Second commit deletes the only file; ensures deletions do not create scan candidates. |

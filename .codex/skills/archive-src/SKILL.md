---
name: archive-src
description: Use when the user wants a minimal source-only archive for upload or checkpoint. Creates a tar.gz with just source and test files from all workspace crates.
---

# Archive Source + Tests

Package only source code and tests from all workspace crates into a compact `.tar.gz` archive.

## What's Included

- `crates/*/src/**` - All crate source code
- `crates/*/tests/**` - All crate integration/test files
- `Cargo.toml` - Root workspace manifest
- `crates/*/Cargo.toml` - Per-crate manifests (including fuzz)

## What's Excluded

Everything else: benches, fuzz targets, docs, config files, lock file, CI, `.claude/`, `.github/`, binaries.

## Workflow

Run from the project root:

```bash
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
ARCHIVE="gossip-rs-src-${TIMESTAMP}.tar.gz"
git ls-files -z -- \
  ':(glob)crates/*/src/**' \
  ':(glob)crates/*/tests/**' \
  'Cargo.toml' \
  ':(glob)crates/*/Cargo.toml' \
  ':(glob)crates/*/fuzz/Cargo.toml' \
  | grep -zZv -e '\.pack$' -e '\.bin$' \
  | tar czf "${ARCHIVE}" --null -T -
echo "Created ${ARCHIVE} ($(du -h "${ARCHIVE}" | cut -f1))"
```

Report the archive name and size to the user when done.

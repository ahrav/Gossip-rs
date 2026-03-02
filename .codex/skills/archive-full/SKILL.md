---
name: archive-full
description: Use when the user wants to package all source code into a tar.gz archive for upload or checkpoint. Creates a comprehensive archive of all workspace crates, docs, and config excluding binaries.
---

# Archive Full Source

Package all git-tracked files from the workspace into a single `.tar.gz` archive, excluding binaries.

## What's Included

All git-tracked files across the workspace, including:
- `crates/*/src/**` and `crates/*/tests/**` - All crate source and tests
- `Cargo.toml`, `Cargo.lock` - Workspace manifest and lockfile
- `docs/`, `diagrams/`, `specs/` - Documentation and specifications
- Config files (`.github/`, `.claude/`, etc.)

## What's Excluded

- Binary files (`*.pack`, `*.bin`, `*.so`, `*.dylib`, `*.a`)
- Performance data (`perf.data`)
- Build artifacts are not git-tracked and excluded automatically

## Workflow

Run from the project root:

```bash
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
ARCHIVE="gossip-rs-full-${TIMESTAMP}.tar.gz"
git ls-files -z \
  | grep -zZv -e '\.pack$' -e '\.bin$' -e '\.so$' -e '\.dylib$' -e '\.a$' -e 'perf\.data' \
  | tar czf "${ARCHIVE}" --null -T -
echo "Created ${ARCHIVE} ($(du -h "${ARCHIVE}" | cut -f1))"
```

Report the archive name and size to the user when done.

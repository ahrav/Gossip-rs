#!/usr/bin/env python3
"""Fail if removed source-architecture identifiers reappear in code/config files.

This is a lightweight repo guard for the connector-family migration. It scans the
workspace source tree and root Cargo.toml for the removed driver-stack symbols.
Documentation and the guard files themselves are intentionally not scanned.
"""

from __future__ import annotations

from pathlib import Path
import sys


def _join(parts: tuple[str, ...]) -> str:
    return "".join(parts)


NEEDLES: tuple[str, ...] = (
    _join(("Scan", "Driver")),
    _join(("Connector", "Kind")),
    _join(("Assignment", "Source")),
    _join(("gossip", "-", "scan", "-", "driver")),
    _join(("gossip", "_", "scan", "_", "driver")),
)

ROOT = Path(__file__).resolve().parents[1]
SCAN_FILES = [ROOT / "Cargo.toml"]
CRATES = ROOT / "crates"
if CRATES.exists():
    for path in CRATES.rglob("*"):
        if path.is_file() and path.suffix in {".rs", ".toml"}:
            SCAN_FILES.append(path)

violations: list[tuple[Path, str]] = []
for path in SCAN_FILES:
    text = path.read_text(encoding="utf-8", errors="ignore")
    for needle in NEEDLES:
        if needle in text:
            violations.append((path.relative_to(ROOT), needle))

if violations:
    print("Legacy source-design identifiers must not reappear:", file=sys.stderr)
    for path, needle in violations:
        print(f"  - {path}: {needle}", file=sys.stderr)
    sys.exit(1)

print("OK: no legacy source-design identifiers found.")
